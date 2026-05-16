from fastapi import FastAPI, File, UploadFile, HTTPException, Body
from fastapi.responses import HTMLResponse, Response, JSONResponse
from pydantic import BaseModel
import os
import ssl
import httpx
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="CVE Analyzer")


@app.get("/", response_class=HTMLResponse)
async def root():
        html = """
        <html>
            <head><title>CVE Analyzer</title></head>
            <body>
                <h1>CVE Analyzer</h1>
                <p>Service is running. Use <a href="/health">/health</a>.</p>
                <h2>Quick UI</h2>
                <textarea id="sbom" rows="12" cols="80" placeholder="Paste SBOM JSON or text here"></textarea>
                <br/>
                <button id="analyse">Analyse</button>
                <button id="askai">Ask AI (raw)</button>
                <h3>Result</h3>
                <pre id="result"></pre>
                <script>
                    async function postJson(path, body){
                        const resp = await fetch(path, {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify(body)
                        });
                        return resp;
                    }
                    document.getElementById('analyse').addEventListener('click', async ()=>{
                        const sbom = document.getElementById('sbom').value;
                        const resp = await postJson('/analyse_text', {sbom_text: sbom});
                        const txt = await resp.text();
                        document.getElementById('result').textContent = txt;
                    });
                    document.getElementById('askai').addEventListener('click', async ()=>{
                        const sbom = document.getElementById('sbom').value;
                        const resp = await postJson('/ask_ai', {sbom_text: sbom});
                        const txt = await resp.text();
                        document.getElementById('result').textContent = txt;
                    });
                </script>
            </body>
        </html>
        """
        return HTMLResponse(content=html, status_code=200)


@app.get('/favicon.ico')
async def favicon():
        return Response(status_code=204)


class AnalyzeResult(BaseModel):
    summary: str
    recommendations: list[str]


class SBOMText(BaseModel):
    sbom_text: str


def make_ssl_context():
    ca_bundle = os.getenv("SSL_CERT_FILE", os.getenv("REQUESTS_CA_BUNDLE"))
    if not ca_bundle:
        return None
    ctx = ssl.create_default_context(cafile=ca_bundle)
    try:
        # relax strict verification flags (some enterprise proxies)
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    except Exception:
        pass
    return ctx


async def call_llm_with_retry(prompt: str):
    # Support multiple env names for compatibility with various gateways
    api_url = os.getenv("GATEWAY_BASE_URL") or os.getenv("LLM_API_URL")
    api_key = os.getenv("GATEWAY_API_KEY") or os.getenv("LLM_API_KEY")
    model = os.getenv("MODEL") or "gpt-4.1"

    if not api_url or not api_key:
        raise HTTPException(status_code=500, detail="LLM API config missing")

    ssl_ctx = make_ssl_context()
    async with httpx.AsyncClient(verify=ssl_ctx, timeout=30.0) as client:
        headers = {"Content-Type": "application/json"}
        # include both header styles to match proxy expectations
        headers["Authorization"] = f"Bearer {api_key}"
        headers["x-api-key"] = api_key

        body = {"model": model, "input": prompt}
        try:
            resp = await client.post(api_url, headers=headers, json=body)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"LLM request failed: {e}")

        if resp.status_code >= 400:
            # expose response body for easier debugging
            detail = f"LLM proxy error {resp.status_code}: {resp.text}"
            raise HTTPException(status_code=502, detail=detail)

        return resp.json()


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResult)
async def analyze(sbom: UploadFile = File(...)):
    content = await sbom.read()
    if not content:
        raise HTTPException(status_code=400, detail="Empty SBOM")

    api_url = os.getenv("LLM_API_URL")
    api_key = os.getenv("LLM_API_KEY")
    if not api_url or not api_key:
        raise HTTPException(status_code=500, detail="LLM API config missing")

    prompt = (
        "You are a vulnerability analysis assistant. Given the following SBOM, "
        "identify affected containers (including transitive dependencies) and provide actionable remediation steps. "
        "Return a short summary and a bullet list of recommendations.\n\nSBOM:\n" + content.decode(errors="ignore")
    )

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.post(
                api_url,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": "gpt-4.1",
                    "input": prompt,
                },
            )
            resp.raise_for_status()
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"LLM request failed: {e}")

    data = resp.json()
    text = data.get("output") or data.get("choices", [{}])[0].get("text", "")
    summary = text.split("\n\n")[0][:1000]
    recommendations = [line.strip("- ") for line in text.splitlines() if line.strip().startswith("-")]

    return AnalyzeResult(summary=summary, recommendations=recommendations)


@app.post("/analyse", response_model=AnalyzeResult)
async def analyse(sbom: UploadFile = File(...)):
    """Alias for `/analyze` supporting alternate spelling."""
    return await analyze(sbom)


@app.post('/analyse_text')
async def analyse_text(body: SBOMText = Body(...)):
    """Accept SBOM text in JSON and return the structured analysis."""
    if not body.sbom_text:
        raise HTTPException(status_code=400, detail="Empty SBOM text")
    api_url = os.getenv("LLM_API_URL")
    api_key = os.getenv("LLM_API_KEY")
    if not api_url or not api_key:
        raise HTTPException(status_code=500, detail="LLM API config missing")

    prompt = (
        "You are a vulnerability analysis assistant. Given the following SBOM, "
        "identify affected containers (including transitive dependencies) and provide actionable remediation steps. "
        "Return a short summary and a bullet list of recommendations.\n\nSBOM:\n" + body.sbom_text
    )

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.post(
                api_url,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={"model": "gpt-4.1", "input": prompt},
            )
            resp.raise_for_status()
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"LLM request failed: {e}")

    data = resp.json()
    text = data.get("output") or data.get("choices", [{}])[0].get("text", "")
    # Return structured-ish response
    summary = text.split("\n\n")[0][:1000]
    recommendations = [line.strip("- ") for line in text.splitlines() if line.strip().startswith("-")]
    return JSONResponse(content={"summary": summary, "recommendations": recommendations, "raw": text})


@app.post('/ask_ai')
async def ask_ai(body: SBOMText = Body(...)):
    """Return raw LLM output for the provided SBOM text."""
    if not body.sbom_text:
        raise HTTPException(status_code=400, detail="Empty SBOM text")
    api_url = os.getenv("LLM_API_URL")
    api_key = os.getenv("LLM_API_KEY")
    if not api_url or not api_key:
        raise HTTPException(status_code=500, detail="LLM API config missing")

    prompt = (
        "You are a vulnerability analysis assistant. Given the following SBOM, "
        "identify affected containers (including transitive dependencies) and provide actionable remediation steps. "
        "Return a short summary and a bullet list of recommendations.\n\nSBOM:\n" + body.sbom_text
    )

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.post(
                api_url,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={"model": "gpt-4.1", "input": prompt},
            )
            resp.raise_for_status()
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"LLM request failed: {e}")

    data = resp.json()
    text = data.get("output") or data.get("choices", [{}])[0].get("text", "")
    return Response(content=text, media_type='text/plain')
