from __future__ import annotations

import asyncio
import hmac
import json
import logging

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from fastapi.concurrency import run_in_threadpool
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from pdfanalyzer.analyzer import analyze_pdf_bytes
from pdfanalyzer.config import API_TOKEN, MAX_UPLOAD_BYTES, REPORTS_DIR

# The VM has limited RAM/CPU; serialize PDF analysis requests rather than
# allowing multiple uploads to launch parsers and scanners concurrently.
ANALYSIS_SEMAPHORE = asyncio.Semaphore(1)

logger = logging.getLogger("pdf_analyzer.api")

app = FastAPI(
    title="PDF Static Advanced Analyzer",
    version="0.1.0",
    description=(
        "Static-only PDF inspection API. Does not execute PDF JavaScript or payloads. "
        "Reports include tool results, indicators, and an explainable preliminary verdict."
    ),
)


security = HTTPBearer(auto_error=False)


def authorize(credentials: HTTPAuthorizationCredentials | None = Depends(security)) -> None:
    token = API_TOKEN
    if not token:
        raise HTTPException(status_code=503, detail="PDF_API_TOKEN is not configured on the service")
    if credentials is None or not hmac.compare_digest(credentials.credentials, token):
        raise HTTPException(status_code=401, detail="Missing or invalid bearer token")


@app.get("/health")
def health():
    return {"service": "pdf-static-analyzer", "status": "running", "execution_mode": "static_only"}


@app.post("/analyze", dependencies=[Depends(authorize)])
async def analyze(file: UploadFile = File(...)):
    async with ANALYSIS_SEMAPHORE:
        chunks: list[bytes] = []
        size = 0
        prefix = bytearray()
        try:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds configured upload limit ({MAX_UPLOAD_BYTES} bytes)",
                    )
                if len(prefix) < 1024:
                    prefix.extend(chunk[: 1024 - len(prefix)])
                chunks.append(chunk)

            if b"%PDF-" not in prefix:
                raise HTTPException(status_code=415, detail="No recognizable PDF header in the first 1024 bytes")

            content = b"".join(chunks)
            try:
                report = await run_in_threadpool(analyze_pdf_bytes, content, file.filename or "upload.pdf")
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            except Exception as exc:
                logger.exception("Static PDF analysis failed")
                raise HTTPException(status_code=500, detail="Analysis failed; inspect the Ubuntu service log") from exc
            return JSONResponse(content=report)
        finally:
            await file.close()


@app.get("/reports/{job_id}", dependencies=[Depends(authorize)])
def get_report(job_id: str):
    # Only UUID job IDs are accepted; paths cannot escape REPORTS_DIR.
    import uuid
    try:
        normalized = str(uuid.UUID(job_id))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid job_id") from exc
    path = REPORTS_DIR / f"{normalized}.json"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Report not found")
    return JSONResponse(content=json.loads(path.read_text(encoding="utf-8")))
