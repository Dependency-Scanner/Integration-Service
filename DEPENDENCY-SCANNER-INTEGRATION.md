# Integration Service

Internal service for creating JIRA issues and GitHub pull requests from vulnerability findings.

## Overview

The Integration Service is an internal microservice that:
- Accepts requests from Auth Service (with JWT authentication)
- Creates JIRA issues for each vulnerability finding
- Creates GitHub pull requests for dependency updates
- Maps vulnerability severity to JIRA priority levels
- Logs all API interactions with timestamps

## Features

- **JWT Authentication**: Validates JWT tokens from Auth Service
- **JIRA Integration**: Creates issues with proper priority mapping
- **GitHub Integration**: Creates pull requests for dependency fixes
- **Dry-Run Mode**: Test without creating actual issues/PRs
- **Retry Logic**: Exponential backoff for API failures
- **Comprehensive Logging**: All API calls logged with IST timestamps

## Endpoints

### Internal Endpoints

- `POST /internal/create-issues-and-prs` - Create JIRA issues and GitHub PRs (requires JWT)
- `GET /health` - Health check

## JIRA Priority Mapping

- `critical` → Blocker
- `high` → High
- `medium` → Medium
- `low` → Low

## Environment Variables

See `.env.example` for all required environment variables.

## Running the Service

### Local Development

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

### Docker

```bash
docker build -t integration-service .
docker run -p 8000:8000 --env-file .env integration-service
```

## Architecture

The Integration Service:
1. Validates JWT token from Auth Service
2. For each vulnerability:
   - Creates JIRA issue with severity mapping
   - Creates GitHub PR for dependency update
3. Returns aggregated results with ticket IDs and PR URLs

## Logging

- All logs use IST (Asia/Kolkata) timezone
- Structured JSON format for application logs
- All JIRA and GitHub API calls logged with timestamps
- NTP clock synchronization on startup

## Notes

- GitHub PR creation requires actual branch setup and git operations (simplified in this implementation)
- JIRA issue creation uses REST API v3
- All credentials passed via JWT token claims

