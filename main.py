"""
Integration Service - Internal service for JIRA issues and GitHub PRs
"""
import json
import logging
import os
import shutil
import tempfile
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

import aiohttp
import git
import jwt
import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Header, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, HttpUrl

from app.config import settings
from app.exceptions import ServiceException
from app.logging_config import setup_logging
from app.models import (
    CreateIssuesAndPRsRequest,
    CreateIssuesAndPRsResponse,
    GitHubPRRequest,
    JiraCommentRequest,
    JiraIssueRequest,
    VulnerabilityResult,
)

# Setup logging
logger = setup_logging()

# Global variables
redis_client: Optional[aioredis.Redis] = None
jwt_secret_key: str = os.getenv("JWT_SECRET_KEY", "")
jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup and shutdown"""
    global redis_client
    
    # Startup
    logger.info("Starting Integration Service...")
    
    # Sync NTP clock
    try:
        import ntplib
        ntp_client = ntplib.NTPClient()
        response = ntp_client.request('pool.ntp.org', version=3)
        system_time = time.time()
        ntp_time = response.tx_time
        drift = abs(ntp_time - system_time)
        
        if drift > 1.0:
            logger.warning(f"Clock drift detected: {drift:.2f} seconds")
        else:
            logger.info(f"Clock synchronized. Drift: {drift:.3f} seconds")
    except Exception as e:
        logger.error(f"Failed to sync NTP clock: {e}")
    
    # Initialize Redis (optional, for caching)
    try:
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        redis_client = await aioredis.from_url(redis_url, decode_responses=True)
        await redis_client.ping()
        logger.info("Redis connection established")
    except Exception as e:
        logger.warning(f"Failed to connect to Redis: {e}")
        redis_client = None
    
    yield
    
    # Shutdown
    logger.info("Shutting down Integration Service...")
    if redis_client:
        await redis_client.close()


app = FastAPI(
    title="Dependency Scanner Integration Service",
    description="""
    Internal service for creating JIRA issues and GitHub PRs from vulnerability findings.
    
    ## Features
    
    * **JIRA Integration**: Create issues with custom fields and priorities
    * **GitHub Integration**: Create pull requests with dependency updates
    * **Multi-File Support**: Updates package.json, requirements.txt, go.mod, pom.xml, build.gradle, Gemfile
    * **Automatic Branching**: Creates branches named `defect/{JIRA-TICKET}`
    * **Comment Automation**: Automatically adds PR links to JIRA tickets
    
    ## Authentication
    
    All endpoints require JWT authentication from Auth Service.
    """,
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    tags_metadata=[
        {
            "name": "Internal",
            "description": "Internal endpoints (require JWT authentication)",
        },
        {
            "name": "Health",
            "description": "Health check endpoint",
        },
    ],
)


@app.exception_handler(ServiceException)
async def service_exception_handler(request, exc: ServiceException):
    """Handle custom service exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.message, "detail": exc.detail},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc: Exception):
    """Handle general exceptions"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "Internal server error", "detail": str(exc)},
    )


def validate_jwt_token(token: str) -> Dict:
    """
    Validate JWT token and extract claims
    
    Args:
        token: JWT token string
    
    Returns:
        Decoded token claims
    
    Raises:
        ServiceException: If token is invalid or expired
    """
    try:
        payload = jwt.decode(
            token,
            jwt_secret_key,
            algorithms=[jwt_algorithm],
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise ServiceException(
            message="JWT token expired",
            detail="Token has expired",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    except jwt.InvalidTokenError as e:
        raise ServiceException(
            message="Invalid JWT token",
            detail=str(e),
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


async def create_jira_issue(
    jira_request: JiraIssueRequest,
    dry_run: bool = False,
) -> Optional[str]:
    """
    Create JIRA issue using provided fields payload (generic)
    
    Args:
        jira_request: JIRA issue request with complete fields dict
        dry_run: If True, don't create actual issue
    
    Returns:
        JIRA ticket key (e.g., "PROJ-123") or None
    """
    jira_server_url = str(jira_request.server_url)
    if dry_run:
        project_key = jira_request.fields.get("project", {}).get("key", "PROJ")
        logger.info(f"[DRY RUN] Would create JIRA issue with fields: {list(jira_request.fields.keys())}")
        return f"{project_key}-DRY-RUN"
    
    try:
        # Prepare issue data with provided fields
        issue_data = {"fields": jira_request.fields}
        
        # Create issue via JIRA REST API
        api_version = jira_request.api_version or "2"
        url = f"{jira_server_url.rstrip('/')}/rest/api/{api_version}/issue"
        headers = {
            "Authorization": f"Bearer {jira_request.pat}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        
        import pytz
        ist = pytz.timezone("Asia/Kolkata")
        timestamp = datetime.now(ist).isoformat()
        summary = jira_request.fields.get("summary", "Unknown")
        logger.info(f"[{timestamp}] Creating JIRA issue: {summary}")
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=issue_data, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as response:
                response_text = await response.text()
                
                if response.status == 201:
                    result = await response.json()
                    ticket_key = result.get("key", "")
                    logger.info(f"[{timestamp}] JIRA issue created: {ticket_key} (Status: {response.status})")
                    return ticket_key
                else:
                    logger.error(f"[{timestamp}] JIRA API error: {response.status} - {response_text}")
                    raise ServiceException(
                        message="Failed to create JIRA issue",
                        detail=f"JIRA API returned status {response.status}: {response_text}",
                        status_code=status.HTTP_502_BAD_GATEWAY,
                    )
    except aiohttp.ClientError as e:
        logger.error(f"JIRA API request failed: {e}")
        raise ServiceException(
            message="Failed to create JIRA issue",
            detail=str(e),
            status_code=status.HTTP_502_BAD_GATEWAY,
        )
    except Exception as e:
        logger.error(f"Unexpected error creating JIRA issue: {e}", exc_info=True)
        raise ServiceException(
            message="Failed to create JIRA issue",
            detail=str(e),
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


async def add_jira_comment(
    comment_request: JiraCommentRequest,
    dry_run: bool = False,
) -> bool:
    """
    Add comment to JIRA issue (generic)
    
    Args:
        comment_request: JIRA comment request
        dry_run: If True, don't create actual comment
    
    Returns:
        True if comment was created successfully, False otherwise
    """
    jira_server_url = str(comment_request.server_url)
    if dry_run:
        logger.info(f"[DRY RUN] Would add comment to JIRA issue {comment_request.issue_key}")
        return True
    
    try:
        # Prepare comment data
        comment_data = {"body": comment_request.body}
        
        # Add comment via JIRA REST API v2
        url = f"{jira_server_url.rstrip('/')}/rest/api/2/issue/{comment_request.issue_key}/comment"
        headers = {
            "Authorization": f"Bearer {comment_request.pat}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        
        import pytz
        ist = pytz.timezone("Asia/Kolkata")
        timestamp = datetime.now(ist).isoformat()
        logger.info(f"[{timestamp}] Adding comment to JIRA issue {comment_request.issue_key}")
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=comment_data, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as response:
                response_text = await response.text()
                
                if response.status == 201:
                    logger.info(f"[{timestamp}] JIRA comment added to {comment_request.issue_key} (Status: {response.status})")
                    return True
                else:
                    logger.error(f"[{timestamp}] JIRA API error: {response.status} - {response_text}")
                    raise ServiceException(
                        message="Failed to add JIRA comment",
                        detail=f"JIRA API returned status {response.status}: {response_text}",
                        status_code=status.HTTP_502_BAD_GATEWAY,
                    )
    except aiohttp.ClientError as e:
        logger.error(f"JIRA API request failed: {e}")
        raise ServiceException(
            message="Failed to add JIRA comment",
            detail=str(e),
            status_code=status.HTTP_502_BAD_GATEWAY,
        )
    except Exception as e:
        logger.error(f"Unexpected error adding JIRA comment: {e}", exc_info=True)
        raise ServiceException(
            message="Failed to add JIRA comment",
            detail=str(e),
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


def update_dependency_file(file_path: Path, package_name: str, current_version: str, safe_version: str) -> bool:
    """
    Update dependency version in file (package.json, requirements.txt, etc.)
    
    Args:
        file_path: Path to dependency file
        package_name: Package name
        current_version: Current version
        safe_version: Safe version to update to
    
    Returns:
        True if file was updated, False otherwise
    """
    try:
        # Skip if versions are the same
        if safe_version == current_version:
            logger.warning(f"Skipping update for {package_name}: safe_version ({safe_version}) == current_version ({current_version})")
            return False
        
        content = file_path.read_text()
        updated = False
        
        # Handle package.json
        if file_path.name == "package.json":
            data = json.loads(content)
            # Check dependencies
            if "dependencies" in data and package_name in data["dependencies"]:
                old_value = data["dependencies"][package_name]
                # Extract version number (remove ^, ~, >=, etc.)
                clean_old = old_value.lstrip("^~>=<")
                # Only update if the actual version number is different
                if clean_old != safe_version:
                    # Preserve prefix if present, otherwise use exact version
                    if old_value.startswith("^") or old_value.startswith("~"):
                        data["dependencies"][package_name] = f"^{safe_version}"
                    elif old_value.startswith(">="):
                        data["dependencies"][package_name] = f">={safe_version}"
                    else:
                        data["dependencies"][package_name] = safe_version
                    updated = True
            # Check devDependencies
            if "devDependencies" in data and package_name in data["devDependencies"]:
                old_value = data["devDependencies"][package_name]
                clean_old = old_value.lstrip("^~>=<")
                if clean_old != safe_version:
                    if old_value.startswith("^") or old_value.startswith("~"):
                        data["devDependencies"][package_name] = f"^{safe_version}"
                    elif old_value.startswith(">="):
                        data["devDependencies"][package_name] = f">={safe_version}"
                    else:
                        data["devDependencies"][package_name] = safe_version
                    updated = True
            if updated:
                file_path.write_text(json.dumps(data, indent=2) + "\n")
        
        # Handle requirements.txt
        elif file_path.name in ["requirements.txt", "requirements-dev.txt"]:
            lines = content.split("\n")
            new_lines = []
            for line in lines:
                stripped = line.strip()
                # Match package==version or package>=version, etc.
                if stripped.startswith(package_name):
                    # Extract current version from line
                    if "==" in line:
                        parts = line.split("==")
                        if len(parts) == 2:
                            existing_version = parts[1].strip()
                            if existing_version != safe_version:
                                new_lines.append(f"{package_name}=={safe_version}")
                                updated = True
                            else:
                                new_lines.append(line)
                        else:
                            new_lines.append(line)
                    elif ">=" in line:
                        parts = line.split(">=")
                        if len(parts) == 2:
                            existing_version = parts[1].strip()
                            if existing_version != safe_version:
                                new_lines.append(f"{package_name}>={safe_version}")
                                updated = True
                            else:
                                new_lines.append(line)
                        else:
                            new_lines.append(line)
                    else:
                        new_lines.append(line)
                else:
                    new_lines.append(line)
            if updated:
                file_path.write_text("\n".join(new_lines))
        
        # Handle go.mod
        elif file_path.name == "go.mod":
            lines = content.split("\n")
            new_lines = []
            in_require_block = False
            
            for line in lines:
                stripped = line.strip()
                
                # Check if entering require block
                if stripped.startswith("require") and stripped.endswith("("):
                    in_require_block = True
                    new_lines.append(line)
                    continue
                
                # Check if exiting require block
                if in_require_block and stripped == ")":
                    in_require_block = False
                    new_lines.append(line)
                    continue
                
                # Inside require block - check if this line matches our package
                if in_require_block and stripped and not stripped.startswith("//"):
                    # Parse: module version or module => version
                    parts = stripped.split()
                    if len(parts) >= 2:
                        # Handle replace directive: module => version
                        if "=>" in parts:
                            arrow_idx = parts.index("=>")
                            if arrow_idx > 0 and parts[0] == package_name:
                                # This is our package with a replace directive
                                # Update the version after =>
                                if len(parts) > arrow_idx + 1:
                                    existing_version = parts[arrow_idx + 1]
                                    if existing_version != safe_version:
                                        # Reconstruct line with new version
                                        new_line = f"\t{package_name} => {safe_version}"
                                        if len(parts) > arrow_idx + 2:
                                            # Preserve any trailing comments or directives
                                            new_line += " " + " ".join(parts[arrow_idx + 2:])
                                        new_lines.append(new_line)
                                        updated = True
                                    else:
                                        new_lines.append(line)
                                else:
                                    new_lines.append(line)
                            else:
                                new_lines.append(line)
                        else:
                            # Standard: module version
                            if parts[0] == package_name:
                                existing_version = parts[1]
                                # Check if version matches (handle pseudo-versions like v0.0.0-20210314154223-e6e6c4f2bb5b)
                                if existing_version != safe_version:
                                    # Reconstruct line with new version
                                    new_line = f"\t{package_name} {safe_version}"
                                    if len(parts) > 2:
                                        # Preserve any trailing comments
                                        new_line += " " + " ".join(parts[2:])
                                    new_lines.append(new_line)
                                    updated = True
                                else:
                                    new_lines.append(line)
                            else:
                                new_lines.append(line)
                    else:
                        new_lines.append(line)
                else:
                    # Single-line require: require module version
                    if stripped.startswith("require") and package_name in stripped:
                        parts = stripped.split()
                        if len(parts) >= 3 and parts[1] == package_name:
                            existing_version = parts[2]
                            if existing_version != safe_version:
                                new_lines.append(f"require {package_name} {safe_version}")
                                updated = True
                            else:
                                new_lines.append(line)
                        else:
                            new_lines.append(line)
                    else:
                        new_lines.append(line)
            
            if updated:
                file_path.write_text("\n".join(new_lines))
        
        # Handle pom.xml (Maven)
        elif file_path.name == "pom.xml":
            try:
                import xml.etree.ElementTree as ET
                tree = ET.parse(file_path)
                root = tree.getroot()
                
                # Maven package name format: groupId:artifactId
                if ":" in package_name:
                    group_id, artifact_id = package_name.split(":", 1)
                else:
                    # Try to find by artifactId only
                    group_id = None
                    artifact_id = package_name
                
                # Find and update dependency
                for dep in root.findall(".//{http://maven.apache.org/POM/4.0.0}dependency"):
                    dep_group_id = dep.find("{http://maven.apache.org/POM/4.0.0}groupId")
                    dep_artifact_id = dep.find("{http://maven.apache.org/POM/4.0.0}artifactId")
                    dep_version = dep.find("{http://maven.apache.org/POM/4.0.0}version")
                    
                    if dep_group_id is not None and dep_artifact_id is not None and dep_version is not None:
                        # Match by groupId:artifactId or just artifactId
                        if (group_id and dep_group_id.text == group_id and dep_artifact_id.text == artifact_id) or \
                           (not group_id and dep_artifact_id.text == artifact_id):
                            if dep_version.text != safe_version:
                                dep_version.text = safe_version
                                updated = True
                                break
                
                if updated:
                    # Write back with proper XML formatting
                    ET.indent(tree, space="  ")
                    tree.write(file_path, encoding="utf-8", xml_declaration=True)
            except Exception as e:
                logger.error(f"Failed to update pom.xml: {e}")
                return False
        
        # Handle build.gradle and build.gradle.kts
        elif file_path.name in ["build.gradle", "build.gradle.kts"]:
            lines = content.split("\n")
            new_lines = []
            in_dependencies_block = False
            
            # Maven package name format: groupId:artifact:version
            # We need to match groupId:artifact part
            if ":" in package_name:
                parts = package_name.split(":")
                if len(parts) >= 2:
                    group_id = parts[0]
                    artifact_id = parts[1]
                    package_pattern = f"{group_id}:{artifact_id}"
                else:
                    package_pattern = package_name
            else:
                package_pattern = package_name
            
            for line in lines:
                stripped = line.strip()
                
                # Check if entering dependencies block
                if stripped.startswith("dependencies") and "{" in stripped:
                    in_dependencies_block = True
                    new_lines.append(line)
                    continue
                
                # Check if exiting dependencies block
                if in_dependencies_block and stripped == "}":
                    in_dependencies_block = False
                    new_lines.append(line)
                    continue
                
                # Inside dependencies block - check if this line matches our package
                if in_dependencies_block and package_pattern in stripped:
                    # Match: implementation 'group:artifact:version' or implementation("group:artifact:version")
                    import re
                    # Pattern: implementation/api/compile/testImplementation followed by quotes/parens and group:artifact:version
                    match = re.search(r"(implementation|api|compile|testImplementation)\s*[\(']([^'\)]+)", line)
                    if match:
                        dep_type = match.group(1)
                        dep_spec = match.group(2)
                        # Check if this is our package
                        if package_pattern in dep_spec:
                            # Extract version from dep_spec (format: group:artifact:version)
                            dep_parts = dep_spec.split(":")
                            if len(dep_parts) >= 3:
                                # Replace version (last part)
                                new_dep_spec = ":".join(dep_parts[:-1]) + ":" + safe_version
                                # Reconstruct line
                                quote_char = '"' if '"' in line else "'"
                                paren_char = "(" if "(" in line else ""
                                close_paren = ")" if ")" in line else ""
                                new_line = f"\t{dep_type}{paren_char}{quote_char}{new_dep_spec}{quote_char}{close_paren}"
                                new_lines.append(new_line)
                                updated = True
                            else:
                                new_lines.append(line)
                        else:
                            new_lines.append(line)
                    else:
                        new_lines.append(line)
                else:
                    new_lines.append(line)
            
            if updated:
                file_path.write_text("\n".join(new_lines))
        
        # Handle Gemfile
        elif file_path.name == "Gemfile":
            lines = content.split("\n")
            new_lines = []
            
            for line in lines:
                stripped = line.strip()
                # Match: gem "package_name", "version" or gem 'package_name', 'version'
                if stripped.startswith("gem ") and package_name in stripped:
                    import re
                    # Pattern: gem "name", "version" or gem 'name', 'version'
                    match = re.search(r'gem\s+["\']([^"\']+)["\']\s*,\s*["\']([^"\']+)["\']', line)
                    if match:
                        gem_name = match.group(1)
                        gem_version = match.group(2)
                        if gem_name == package_name and gem_version != safe_version:
                            # Reconstruct line with new version
                            quote_char = '"' if '"' in line else "'"
                            new_line = f"gem {quote_char}{package_name}{quote_char}, {quote_char}{safe_version}{quote_char}"
                            new_lines.append(new_line)
                            updated = True
                        else:
                            new_lines.append(line)
                    else:
                        # Try pattern without comma: gem "name" "version"
                        match = re.search(r'gem\s+["\']([^"\']+)["\']\s+["\']([^"\']+)["\']', line)
                        if match:
                            gem_name = match.group(1)
                            gem_version = match.group(2)
                            if gem_name == package_name and gem_version != safe_version:
                                quote_char = '"' if '"' in line else "'"
                                new_line = f"gem {quote_char}{package_name}{quote_char} {quote_char}{safe_version}{quote_char}"
                                new_lines.append(new_line)
                                updated = True
                            else:
                                new_lines.append(line)
                        else:
                            new_lines.append(line)
                else:
                    new_lines.append(line)
            
            if updated:
                file_path.write_text("\n".join(new_lines))
        
        return updated
    except Exception as e:
        logger.error(f"Failed to update dependency file {file_path}: {e}")
        return False


async def create_github_pr(
    pr_request: GitHubPRRequest,
    dry_run: bool = False,
) -> Optional[str]:
    """
    Create GitHub pull request for dependency update (generic - uses provided PR request)
    
    Args:
        pr_request: GitHub PR request with complete payload
        dry_run: If True, don't create actual PR
    
    Returns:
        Pull request URL or None
    """
    repo_url = str(pr_request.repo_url)
    if dry_run:
        logger.info(f"[DRY RUN] Would create GitHub PR for {pr_request.package_name} {pr_request.current_version} -> {pr_request.safe_version}")
        return "https://github.com/owner/repo/pull/DRY-RUN"
    
    repo_path = None
    try:
        # Extract owner and repo from URL
        parsed = urlparse(repo_url)
        path_parts = parsed.path.strip("/").split("/")
        if len(path_parts) < 2:
            raise ServiceException(
                message="Invalid repository URL",
                detail="Could not parse owner/repo from URL",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        
        owner = path_parts[0]
        repo_name = path_parts[1]
        
        # Use branch name from request
        branch_name = pr_request.branch_name
        
        # Clone repository
        temp_dir = tempfile.mkdtemp()
        repo_path = Path(temp_dir)
        
        # Construct git URL with token
        if "github.tools.sap" in repo_url or "github.com" in repo_url:
            # Inject PAT into URL for authentication
            if parsed.scheme == "https":
                git_url = f"{parsed.scheme}://oauth2:{pr_request.github_pat}@{parsed.netloc}{parsed.path}"
            else:
                git_url = repo_url
        else:
            git_url = repo_url
        
        logger.info(f"Cloning repository {repo_url} to {temp_dir}")
        git_repo = git.Repo.clone_from(git_url, temp_dir, depth=1)
        
        # Get default branch (use from request or detect)
        default_branch = pr_request.base_branch or (git_repo.active_branch.name if git_repo.active_branch else "main")
        
        # Create and checkout new branch
        git_repo.git.checkout("-b", branch_name)
        
        # Update dependency files (use provided list or find automatically)
        dependency_files = []
        if pr_request.dependency_files:
            # Use provided dependency files
            for file_path_str in pr_request.dependency_files:
                file_path = repo_path / file_path_str
                if file_path.exists():
                    if update_dependency_file(file_path, pr_request.package_name, pr_request.current_version, pr_request.safe_version):
                        dependency_files.append(file_path_str)
        else:
            # Auto-detect dependency files
            for pattern in ["package.json", "requirements.txt", "requirements-dev.txt", "Pipfile", "poetry.lock", "go.mod", "pom.xml", "build.gradle", "build.gradle.kts", "Gemfile"]:
                for file_path in repo_path.rglob(pattern):
                    if update_dependency_file(file_path, pr_request.package_name, pr_request.current_version, pr_request.safe_version):
                        dependency_files.append(str(file_path.relative_to(repo_path)))
        
        if not dependency_files:
            logger.warning(f"No dependency files found or updated for {pr_request.package_name}")
            if pr_request.current_version == pr_request.safe_version:
                logger.warning(f"Skipping PR creation for {pr_request.package_name}: safe_version equals current_version")
                raise ServiceException(
                    message="Cannot create PR: safe version equals current version",
                    detail=f"Package {pr_request.package_name} has safe_version ({pr_request.safe_version}) equal to current_version ({pr_request.current_version}). No update needed.",
                    status_code=status.HTTP_400_BAD_REQUEST,
                )
            # Still create PR but note that no files were updated
        
        # Stage changes
        if dependency_files:
            git_repo.git.add(dependency_files)
        else:
            # No files to commit - skip PR creation
            logger.warning(f"No files to commit for {pr_request.package_name}, skipping PR creation")
            raise ServiceException(
                message="Cannot create PR: no files updated",
                detail=f"No dependency files were updated for {pr_request.package_name}",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        
        # Commit changes
        commit_message = f"fix: Update {pr_request.package_name} from {pr_request.current_version} to {pr_request.safe_version}\n\n"
        commit_message += "\nAutomated fix created by dependency-scanner."
        
        git_repo.index.commit(commit_message)
        
        # Push branch
        origin = git_repo.remote(name="origin")
        origin.push(branch_name, force=False)
        
        # Create PR via GitHub API (use provided title and body)
        api_url = f"https://api.github.com/repos/{owner}/{repo_name}/pulls"
        if "github.tools.sap" in repo_url:
            api_url = f"https://github.tools.sap/api/v3/repos/{owner}/{repo_name}/pulls"
        
        headers = {
            "Authorization": f"Bearer {pr_request.github_pat}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
        }
        
        pr_data = {
            "title": pr_request.title,
            "body": pr_request.body,
            "head": branch_name,
            "base": default_branch,
        }
        
        import pytz
        ist = pytz.timezone("Asia/Kolkata")
        timestamp = datetime.now(ist).isoformat()
        logger.info(f"[{timestamp}] Creating GitHub PR: {pr_request.title}")
        
        async with aiohttp.ClientSession() as session:
            async with session.post(api_url, json=pr_data, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as response:
                response_text = await response.text()
                
                if response.status == 201:
                    result = await response.json()
                    pr_url = result.get("html_url", "")
                    logger.info(f"[{timestamp}] GitHub PR created: {pr_url} (Status: {response.status})")
                    return pr_url
                else:
                    logger.error(f"[{timestamp}] GitHub API error: {response.status} - {response_text}")
                    raise ServiceException(
                        message="Failed to create GitHub PR",
                        detail=f"GitHub API returned status {response.status}: {response_text}",
                        status_code=status.HTTP_502_BAD_GATEWAY,
                    )
    except git.exc.GitCommandError as e:
        logger.error(f"Git operation failed: {e}")
        raise ServiceException(
            message="Failed to create GitHub PR",
            detail=f"Git operation failed: {str(e)}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
    except aiohttp.ClientError as e:
        logger.error(f"GitHub API request failed: {e}")
        raise ServiceException(
            message="Failed to create GitHub PR",
            detail=str(e),
            status_code=status.HTTP_502_BAD_GATEWAY,
        )
    except Exception as e:
        logger.error(f"Unexpected error creating GitHub PR: {e}", exc_info=True)
        raise ServiceException(
            message="Failed to create GitHub PR",
            detail=str(e),
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
    finally:
        # Cleanup
        if repo_path and repo_path.exists():
            try:
                shutil.rmtree(repo_path, ignore_errors=True)
            except Exception as e:
                logger.warning(f"Failed to cleanup temp directory {repo_path}: {e}")


@app.post(
    "/internal/create-issues-and-prs",
    response_model=CreateIssuesAndPRsResponse,
    status_code=status.HTTP_200_OK,
    tags=["Internal"],
    summary="Create JIRA issues and GitHub PRs",
    description="""
    Internal endpoint to create JIRA issues and GitHub PRs from vulnerability findings.
    
    **Authentication**: Requires JWT token from Auth Service in `Authorization: Bearer <token>` header.
    
    This endpoint:
    * Creates JIRA issues for each vulnerable package (one per package, grouping CVEs)
    * Creates GitHub branches named `defect/{JIRA-TICKET}`
    * Updates dependency files (package.json, requirements.txt, go.mod, pom.xml, build.gradle, Gemfile)
    * Commits and pushes changes
    * Creates GitHub pull requests
    * Adds comments to JIRA tickets with PR links
    
    **Supported File Types for Updates**:
    * npm: package.json
    * Python: requirements.txt, requirements-dev.txt
    * Go: go.mod
    * Java: pom.xml, build.gradle, build.gradle.kts
    * Ruby: Gemfile
    """,
    response_description="Results with created JIRA tickets and PR URLs",
)
async def create_issues_and_prs(
    request: CreateIssuesAndPRsRequest,
    authorization: Optional[str] = Header(None, description="JWT token from Auth Service"),
):
    """
    Internal endpoint - create JIRA issues and GitHub PRs from vulnerabilities (generic)
    """
    # Validate JWT token
    if not authorization or not authorization.startswith("Bearer "):
        raise ServiceException(
            message="Missing or invalid authorization header",
            detail="Bearer token required",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    
    token = authorization.replace("Bearer ", "")
    try:
        claims = validate_jwt_token(token)
    except ServiceException:
        raise
    
    # Extract credentials from request
    github_pat = request.github_pat
    repo_url = str(request.repo_url)
    dry_run = request.dry_run or False
    
    # Validate that we have matching counts
    if len(request.jira_issue_requests) != len(request.vulnerabilities):
        raise ServiceException(
            message="Mismatch between vulnerabilities and JIRA issue requests",
            detail=f"Expected {len(request.vulnerabilities)} JIRA issue requests, got {len(request.jira_issue_requests)}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    
    if len(request.github_pr_requests) != len(request.vulnerabilities):
        raise ServiceException(
            message="Mismatch between vulnerabilities and GitHub PR requests",
            detail=f"Expected {len(request.vulnerabilities)} GitHub PR requests, got {len(request.github_pr_requests)}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    
    logger.info(f"Create issues and PRs request received for {len(request.vulnerabilities)} packages")
    
    results = []
    total_issues_created = 0
    total_prs_created = 0
    total_comments_created = 0
    
    # Map comment requests by issue key for quick lookup
    comment_map = {}
    if request.jira_comment_requests:
        for comment_req in request.jira_comment_requests:
            comment_map[comment_req.issue_key] = comment_req
    
    for idx, vuln in enumerate(request.vulnerabilities):
        jira_ticket = None
        pr_url = None
        fix_branch = None
        
        try:
            # Create JIRA issue using provided fields payload
            jira_request = request.jira_issue_requests[idx]
            jira_ticket = await create_jira_issue(
                jira_request=jira_request,
                dry_run=dry_run,
            )
            
            if jira_ticket:
                total_issues_created += 1
            
            # Create GitHub PR using provided PR request
            pr_request = request.github_pr_requests[idx]
            # Update branch name if JIRA ticket was created
            if jira_ticket and not pr_request.branch_name.startswith("defect/"):
                pr_request.branch_name = f"defect/{jira_ticket}"
            
            pr_url = await create_github_pr(
                pr_request=pr_request,
                dry_run=dry_run,
            )
            
            if pr_url:
                total_prs_created += 1
            
            # Use branch name from PR request
            fix_branch = pr_request.branch_name
            
            # Add comment to JIRA issue after PR creation (if PR was created and comment request exists)
            if jira_ticket and pr_url and not dry_run:
                # Check if there's a comment request for this issue
                if jira_ticket in comment_map:
                    comment_req = comment_map[jira_ticket]
                    try:
                        # Update comment body with PR URL if not already included
                        comment_body = comment_req.body
                        if pr_url not in comment_body:
                            comment_body = f"{comment_req.body}\n\nCreated pull request: {pr_url}\n\nAutomated fix created by dependency-scanner."
                        
                        comment_success = await add_jira_comment(
                            comment_request=JiraCommentRequest(
                                server_url=comment_req.server_url,
                                pat=comment_req.pat,
                                issue_key=jira_ticket,
                                body=comment_body,
                            ),
                            dry_run=dry_run,
                        )
                        if comment_success:
                            total_comments_created += 1
                    except Exception as e:
                        logger.warning(f"Failed to add comment to JIRA issue {jira_ticket}: {e}")
                else:
                    # Auto-create comment if PR was created but no explicit comment request
                    try:
                        # Get server URL and PAT from the JIRA issue request
                        comment_success = await add_jira_comment(
                            comment_request=JiraCommentRequest(
                                server_url=jira_request.server_url,
                                pat=jira_request.pat,
                                issue_key=jira_ticket,
                                body=f"Created pull request: {pr_url}\n\nAutomated fix created by dependency-scanner.",
                            ),
                            dry_run=dry_run,
                        )
                        if comment_success:
                            total_comments_created += 1
                    except Exception as e:
                        logger.warning(f"Failed to auto-add comment to JIRA issue {jira_ticket}: {e}")
            
            results.append(
                VulnerabilityResult(
                    package_name=vuln.package_name,
                    jira_ticket=jira_ticket,
                    pull_request_url=pr_url,
                    fix_branch=fix_branch,
                    severity=vuln.severity,
                    status="created" if (jira_ticket or pr_url) else "failed",
                )
            )
        except Exception as e:
            logger.error(f"Failed to process vulnerability {vuln.package_name}: {e}", exc_info=True)
            results.append(
                VulnerabilityResult(
                    package_name=vuln.package_name,
                    jira_ticket=jira_ticket,
                    pull_request_url=pr_url,
                    fix_branch=fix_branch,
                    severity=vuln.severity,
                    status="failed",
                )
            )
    
    return CreateIssuesAndPRsResponse(
        status="completed",
        total_issues_created=total_issues_created,
        total_prs_created=total_prs_created,
        total_comments_created=total_comments_created,
        results=results,
    )


@app.get(
    "/health",
    tags=["Health"],
    summary="Health check",
    description="Check if the Integration Service is healthy and running",
    response_description="Service health status",
)
async def health_check():
    """
    Health check endpoint
    """
    import pytz
    ist = pytz.timezone("Asia/Kolkata")
    ist_time = datetime.now(ist)
    
    return {
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": ist_time.isoformat(),
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8081,
        log_config=None,
    )

