# CVE Analyzer — AI-Powered SBOM Vulnerability Intelligence

This repository contains a minimal prototype of an AI-powered chatbot service that ingests SBOMs, queries an LLM to identify affected containers (including transitive dependencies), and returns remediation recommendations.

**What's included**
- **Source:** FastAPI app at [app/main.py](app/main.py#L1)
- **Manifest:** [requirements.txt](requirements.txt#L1)
- **Container:** [Dockerfile](Dockerfile#L1) (exposes port 8000)
- **Docs:** [docs/usage.md](docs/usage.md#L1) and [docs/architecture.md](docs/architecture.md#L1)
- **Demo & Presentation placeholders:** [demo/video-placeholder.txt](demo/video-placeholder.txt#L1), [presentation/presentation-placeholder.md](presentation/presentation-placeholder.md#L1)

## Quickstart (local)

1. Copy configuration:

```bash
cp .env.example .env
# edit .env and set LLM_API_KEY
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the app:

```bash
uvicorn app.main:app --reload --port 8000
```

4. Analyze an SBOM:

```bash
curl -X POST "http://localhost:8000/analyze" -F "sbom=@/path/to/sbom.json"
```

## Docker

Build and run the container (image will expose port 8000):

```bash
docker build -t cve-analyzer:latest .
docker run --env-file .env -p 8000:8000 cve-analyzer:latest
```

## Notes
- Do not commit secrets. Use `.env` for local testing and CI secrets for pipelines.
- This prototype proxies the SBOM to a configured LLM; refine prompts and parsing for production use.

### Mock LLM mode
- For demos or offline testing you can enable a built-in mock LLM response by setting `MOCK_LLM=true` in your `.env` (or pass `-e MOCK_LLM=true` to `docker run`).
- When enabled, the service returns a canned analysis without calling any external APIs.

