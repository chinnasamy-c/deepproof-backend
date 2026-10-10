from __future__ import annotations

import csv
import io
import json
import os
import time
import zipfile
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, File, Header, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

APP_NAME = "DeepProof"
MAX_FILE_MB = int(os.getenv("MAX_FILE_MB", "15"))
MAX_FILE_BYTES = MAX_FILE_MB * 1024 * 1024
MAX_BATCH_FILES = int(os.getenv("MAX_BATCH_FILES", "25"))
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
TRUST_ROOTS_DIR = os.getenv("TRUST_ROOTS_DIR", "")

app = FastAPI(
    title=APP_NAME,
    description="PDF digital-signature validation starter project",
    version="0.1.0",
)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# In-memory counters are intentionally temporary. They reset on restart and
# are not suitable for billing, audit logs, or multi-instance production use.
metrics: dict[str, Any] = {
    "started_at": datetime.now(timezone.utc).isoformat(),
    "files_received": 0,
    "files_with_signatures": 0,
    "valid_results": 0,
    "not_valid_or_untrusted_results": 0,
    "errors": 0,
    "batches": 0,
}


def make_validation_context() -> ValidationContext:
    """Build a validation context. Configure trusted roots explicitly for production."""
    kwargs: dict[str, Any] = {"allow_fetching": True}
    if TRUST_ROOTS_DIR:
        from pathlib import Path
        from pyhanko.keys import load_cert_from_pemder

        roots = []
        root_dir = Path(TRUST_ROOTS_DIR)
        for path in root_dir.iterdir():
            if path.is_file() and path.suffix.lower() in {".pem", ".cer", ".crt", ".der"}:
                try:
                    roots.append(load_cert_from_pemder(path))
                except Exception:
                    # Ignore unreadable files, but do not silently mark a signature trusted.
                    continue
        if roots:
            kwargs["trust_roots"] = roots
    return ValidationContext(**kwargs)


def result_for_file(filename: str, content: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": str(uuid4()),
        "filename": filename,
        "status": "ERROR",
        "signature_count": 0,
        "signatures": [],
        "message": "",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "size_bytes": len(content),
    }

    if not filename.lower().endswith(".pdf"):
        result.update(status="ERROR", message="Only PDF files are accepted.")
        metrics["errors"] += 1
        return result

    try:
        stream = io.BytesIO(content)
        reader = PdfFileReader(stream)
        signatures = reader.embedded_signatures
        result["signature_count"] = len(signatures)

        if not signatures:
            result.update(
                status="NOT_SIGNED",
                message="No embedded PDF digital signatures were found.",
            )
            return result

        metrics["files_with_signatures"] += 1
        validation_context = make_validation_context()
        per_signature = []
        all_bottom_line_valid = True

        for index, signature in enumerate(signatures, start=1):
            try:
                status = validate_pdf_signature(signature, validation_context)
                bottom_line = bool(status.bottom_line)
                if not bottom_line:
                    all_bottom_line_valid = False
                details = status.pretty_print_details()
                per_signature.append({
                    "signature_number": index,
                    "status": "VALID" if bottom_line else "NOT_VALID_OR_UNTRUSTED",
                    "bottom_line": bottom_line,
                    "details": str(details),
                })
            except Exception as exc:
                all_bottom_line_valid = False
                per_signature.append({
                    "signature_number": index,
                    "status": "INDETERMINATE",
                    "bottom_line": False,
                    "details": f"Validation could not be completed: {type(exc).__name__}",
                })

        result["signatures"] = per_signature
        if all_bottom_line_valid:
            result.update(
                status="VALID",
                message="All detected signatures passed the configured validation checks.",
            )
            metrics["valid_results"] += 1
        else:
            result.update(
                status="NOT_VALID_OR_UNTRUSTED",
                message=(
                    "At least one signature did not pass all configured validation checks. "
                    "This can indicate an invalid signature, an untrusted certificate, "
                    "missing trust configuration, or an indeterminate validation result. "
                    "Review signature details before drawing a conclusion."
                ),
            )
            metrics["not_valid_or_untrusted_results"] += 1
        return result

    except Exception as exc:
        # Do not expose stack traces, document bytes, or internal paths to clients.
        result.update(
            status="ERROR",
            message=f"Could not parse or validate this PDF ({type(exc).__name__}).",
        )
        metrics["errors"] += 1
        return result


def csv_bytes(results: list[dict[str, Any]]) -> bytes:
    output = io.StringIO(newline="")
    fields = [
        "filename", "status", "signature_count", "size_bytes",
        "checked_at", "message",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for item in results:
        writer.writerow({key: item.get(key, "") for key in fields})
    return output.getvalue().encode("utf-8-sig")


@app.get("/", response_class=HTMLResponse)
def home():
    with open("app/static/index.html", "r", encoding="utf-8") as f:
        return f.read()


@app.get("/admin", response_class=HTMLResponse)
def admin_page():
    with open("app/static/admin.html", "r", encoding="utf-8") as f:
        return f.read()


@app.get("/health")
def health():
    return {"ok": True, "service": APP_NAME, "version": "0.1.0"}


@app.post("/api/validate")
async def validate_files(files: list[UploadFile] = File(...)):
    if not files:
        raise HTTPException(status_code=400, detail="Upload at least one PDF.")
    if len(files) > MAX_BATCH_FILES:
        raise HTTPException(
            status_code=413,
            detail=f"Maximum {MAX_BATCH_FILES} files per batch.",
        )

    metrics["batches"] += 1
    results = []
    for upload in files:
        content = await upload.read(MAX_FILE_BYTES + 1)
        metrics["files_received"] += 1
        if len(content) > MAX_FILE_BYTES:
            result = {
                "id": str(uuid4()),
                "filename": upload.filename or "unnamed.pdf",
                "status": "ERROR",
                "signature_count": 0,
                "signatures": [],
                "message": f"File exceeds the {MAX_FILE_MB} MB limit.",
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "size_bytes": len(content),
            }
            metrics["errors"] += 1
        else:
            result = result_for_file(upload.filename or "unnamed.pdf", content)
        results.append(result)
        await upload.close()

    return JSONResponse({
        "batch_id": str(uuid4()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(results),
        "results": results,
        "privacy_note": "Uploaded PDF bytes are processed in memory and are not saved by this app.",
    })


@app.post("/api/export/csv")
async def export_csv(payload: dict[str, Any]):
    results = payload.get("results")
    if not isinstance(results, list) or len(results) > MAX_BATCH_FILES:
        raise HTTPException(status_code=400, detail="Invalid results payload.")
    data = csv_bytes(results)
    return Response(
        content=data,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="deepproof-report.csv"'},
    )


@app.post("/api/export/zip")
async def export_zip(payload: dict[str, Any]):
    results = payload.get("results")
    if not isinstance(results, list) or len(results) > MAX_BATCH_FILES:
        raise HTTPException(status_code=400, detail="Invalid results payload.")
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("verification-report.csv", csv_bytes(results))
        archive.writestr(
            "verification-report.json",
            json.dumps(results, ensure_ascii=False, indent=2).encode("utf-8"),
        )
        archive.writestr(
            "README.txt",
            "DeepProof report export.\n"
            "VALID means the configured validation checks passed.\n"
            "NOT_VALID_OR_UNTRUSTED is not a definitive diagnosis of forgery; "
            "review the signature details and trust configuration.\n",
        )
    return Response(
        content=memory_file.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="deepproof-reports.zip"'},
    )


@app.get("/api/admin/stats")
def admin_stats(x_admin_token: str | None = Header(default=None)):
    if not ADMIN_TOKEN or x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Admin authentication failed.")
    return {
        **metrics,
        "max_file_mb": MAX_FILE_MB,
        "max_batch_files": MAX_BATCH_FILES,
        "trust_roots_configured": bool(TRUST_ROOTS_DIR),
        "note": "In-memory metrics reset when the service restarts; not persistent audit records.",
    }
