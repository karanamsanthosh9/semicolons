# CVE Analyzer - Architecture

- **Backend:** FastAPI application exposing an `/analyze` endpoint that accepts SBOM uploads.
- **LLM Integration:** Proxy to configured LLM via `LLM_API_URL` and `LLM_API_KEY` environment variables.
- **Container:** Dockerfile exposes port 8000 and runs `uvicorn`.

Design goals: minimal scaffold to demonstrate SBOM ingestion, LLM-driven analysis, and actionable remediation suggestions.
