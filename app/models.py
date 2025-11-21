"""Pydantic models for request/response validation"""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl


class VulnerabilityInput(BaseModel):
    """Vulnerability input model"""
    package_name: str
    current_version: str
    safe_version: str
    severity: str
    cve: str
    description: Optional[str] = None
    advisory_link: Optional[str] = None


class JiraIssueRequest(BaseModel):
    """JIRA issue creation request with complete fields payload"""
    server_url: HttpUrl
    pat: str = Field(..., min_length=1)
    api_version: str = Field("2", description="JIRA API version: '2' or '3'")
    fields: Dict[str, Any] = Field(..., description="Complete JIRA fields dict")


class JiraCommentRequest(BaseModel):
    """JIRA comment creation request"""
    server_url: HttpUrl
    pat: str = Field(..., min_length=1)
    issue_key: str = Field(..., min_length=1)
    body: str = Field(..., min_length=1)


class GitHubPRRequest(BaseModel):
    """GitHub PR creation request with complete payload"""
    repo_url: HttpUrl
    github_pat: str = Field(..., min_length=1)
    branch_name: str = Field(..., min_length=1, description="Branch name to create and push")
    base_branch: str = Field("main", description="Base branch for PR")
    title: str = Field(..., min_length=1)
    body: str = Field(..., min_length=1)
    package_name: str = Field(..., min_length=1)
    current_version: str
    safe_version: str
    dependency_files: List[str] = Field(default_factory=list, description="List of dependency file paths to update")


class VulnerabilityResult(BaseModel):
    """Vulnerability result with fix information"""
    package_name: str
    jira_ticket: Optional[str] = None
    pull_request_url: Optional[str] = None
    fix_branch: Optional[str] = None
    severity: str
    status: str


class CreateIssuesAndPRsRequest(BaseModel):
    """Request model for create-issues-and-prs endpoint"""
    vulnerabilities: List[VulnerabilityInput] = Field(..., example=[])
    repo_url: HttpUrl = Field(..., example="https://github.com/owner/repository")
    github_pat: str = Field(..., min_length=1, example="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    jira_issue_requests: List[JiraIssueRequest] = Field(..., description="JIRA issue creation requests (one per package)", example=[])
    github_pr_requests: List[GitHubPRRequest] = Field(..., description="GitHub PR creation requests (one per package)", example=[])
    jira_comment_requests: Optional[List[JiraCommentRequest]] = Field(None, description="JIRA comment requests (after PR creation)")
    dry_run: bool = Field(False, example=False)
    
    class Config:
        schema_extra = {
            "example": {
                "vulnerabilities": [
                    {
                        "package_name": "lodash",
                        "current_version": "4.17.19",
                        "safe_version": "4.17.21",
                        "severity": "high",
                        "cve": "CVE-2021-23337",
                        "description": "Prototype pollution vulnerability"
                    }
                ],
                "repo_url": "https://github.com/owner/repository",
                "github_pat": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                "jira_issue_requests": [
                    {
                        "server_url": "https://jira-testconfig.com",
                        "pat": "ATATTxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                        "api_version": "2",
                        "fields": {
                            "project": {"key": "RCM"},
                            "summary": "OSS Security of lodash: 4.17.19",
                            "description": "Vulnerability: high\n\nCVE-2021-23337: Prototype pollution vulnerability",
                            "issuetype": {"name": "Bug"},
                            "priority": {"name": "High"}
                        }
                    }
                ],
                "github_pr_requests": [
                    {
                        "repo_url": "https://github.com/owner/repository",
                        "github_pat": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                        "branch_name": "defect/RCM-123456",
                        "base_branch": "main",
                        "title": "[Scanner] Fix: Update lodash from 4.17.19 to 4.17.21",
                        "body": "Dependency Security Update\n\nPackage: lodash\nCurrent Version: 4.17.19\nSafe Version: 4.17.21",
                        "package_name": "lodash",
                        "current_version": "4.17.19",
                        "safe_version": "4.17.21",
                        "dependency_files": ["package.json"]
                    }
                ],
                "dry_run": False
            }
        }


class CreateIssuesAndPRsResponse(BaseModel):
    """Response model for create-issues-and-prs endpoint"""
    status: str
    total_issues_created: int
    total_prs_created: int
    total_comments_created: int
    results: List[VulnerabilityResult]

