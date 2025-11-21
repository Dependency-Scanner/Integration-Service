# Integration Service

A internal HTTP service that integrates with external systems to automate updates and issue tracking.

This service is generic — it accepts fully-formed JIRA issue payloads and GitHub PR payloads and performs the actions requested (create issues, update dependency files, push branches, open PRs, and add comments). The implementation focuses on automation helpers.

**Key responsibilities**
- Create JIRA issues using a provided fields payload
- Clone Git repositories, update files (npm, Python, Go, Maven/Gradle, Ruby), commit and push branches
- Create GitHub pull requests with provided titles and bodies
- Optionally add comments to JIRA issues with PR links
- Dry-run mode to validate operations without mutating remote systems

**Security & Auth**
- Endpoints expect a JWT Bearer token in `Authorization: Bearer <token>` and validate it using `JWT_SECRET_KEY` / `JWT_ALGORITHM` (HS256 by default).
- API requests include personal access tokens (PATs) for JIRA and GitHub in the request payloads; the service does not store these permanently.

## Endpoints

- `POST /internal/create-issues-and-prs` — Create JIRA issues and GitHub PRs. Request and response models are defined under `app.models`. This endpoint:
   - Accepts a list of items and matching JIRA/GitHub request objects.
   - Expects `jira_issue_requests` and `github_pr_requests` counts to match the list length.
   - Uses the provided payloads to perform JIRA and GitHub operations; it does not synthesize issue fields or PR content for you.

- `GET /health` — Returns basic health information and current IST timestamp.

Open API docs are available at `/docs` when the server is running.

## Request / Response Schemas

The Pydantic models are in `app/models.py`. Important models:
- `CreateIssuesAndPRsRequest` — request body for the main endpoint.
— a generic list of items to act on, `repo_url`, `github_pat`, `jira_issue_requests`, `github_pr_requests`, and `dry_run` flag).
- `GitHubPRRequest` — full PR creation payload (repo URL, PAT, branch name, base branch, title, body, package name, versions, list of dependency files to update).
- `JiraIssueRequest` and `JiraCommentRequest` — JIRA server URL, PAT and full fields/body payloads.

Refer to `app/models.py` for examples and schema details.

## Supported Dependency File Types

- npm: `package.json`
- Python: `requirements.txt`, `requirements-dev.txt`
- Go: `go.mod`
- Java: `pom.xml`, `build.gradle`, `build.gradle.kts`
- Ruby: `Gemfile`

The service contains heuristic updaters that will attempt to update versions in these files; review `main.py:update_dependency_file` for exact behavior.

## Environment Variables

- `JWT_SECRET_KEY` — secret used to validate incoming JWT tokens
- `JWT_ALGORITHM` — default `HS256`
- `REDIS_URL` — optional Redis URL for caching (default `redis://localhost:6379`)

Other runtime configuration comes from `app/config.py`.

## Running Locally

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Start the server:

```bash
uvicorn main:app --reload
```

3. Visit `http://127.0.0.1:8081/docs` to view and try the API.

## Running with Docker

Build and run the container:

```bash
docker build -t integration-service .
docker run -p 8081:8081 --env-file .env integration-service
```

## Example Workflow (high level)

1. A caller prepares a `CreateIssuesAndPRsRequest` with matching lists of items, JIRA requests, and GitHub PR requests.
2. The service validates the JWT and request shapes.
3. For each item it: creates a JIRA issue (or dry-run), clones the target repo, updates files, commits/pushes a branch, opens a PR, and optionally comments on the JIRA ticket with the PR link.

## Logging & Timezone

- Logs are configured via `app/logging_config.py` and use IST (`Asia/Kolkata`) timestamps in key messages.
- The service attempts an NTP check on startup and reports clock drift in logs.

## Notes & Safety

- The service performs git clone/push and remote API calls using supplied credentials. Use dry-run mode for testing.
- Ensure PATs used have the minimum required scopes (repo access for GitHub; issue/comment scopes for JIRA).
- This service expects callers to provide well-formed JIRA fields and PR payloads; it will not attempt to infer missing JIRA fields.

## Development

- API code is in `main.py`.
- Pydantic models are in `app/models.py`.
- Config and logging helpers are in `app/config.py` and `app/logging_config.py`.

If you want, I can also:
- Add a minimal `.env.example` and usage notes for required secrets.
- Add a small integration test that runs the `/health` endpoint.


