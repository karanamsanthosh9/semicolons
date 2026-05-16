# Usage

1. Copy `.env.example` to `.env` and set `LLM_API_KEY`.
2. Install dependencies: `pip install -r requirements.txt`.
3. Run locally: `uvicorn app.main:app --reload --port 8000`.
4. Use the `/analyze` endpoint to POST an SBOM file (multipart/form-data).

Example curl:

```bash
curl -X POST "http://localhost:8000/analyze" -F "sbom=@/path/to/sbom.json"
```
