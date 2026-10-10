# DeepProof — PDF Signature Verification Starter

A beginner-friendly FastAPI + pyHanko starter with:
- Single and batch PDF upload
- Cryptographic PDF signature validation through pyHanko
- CSV export
- ZIP containing CSV + JSON report
- Token-protected admin metrics endpoint and a basic `/admin` dashboard
- Responsive dark professional UI
- Uploaded PDF bytes are processed in memory; this app does not intentionally persist the PDFs

## Important limitations

This is a starter project, not an official government service and not a production-certified validation service.
- `VALID` means pyHanko's configured validation checks passed.
- `NOT_VALID_OR_UNTRUSTED` is deliberately not a definitive forgery verdict. It can mean invalid cryptographic data, an untrusted certificate, missing trust roots, or an inconclusive result.
- Configure and test the appropriate trusted CA roots, revocation checks, timestamp validation, and applicable Indian CCA trust chain before public use.
- pyHanko's document modification/difference analysis has documented limitations; do not treat its output as an infallible legal conclusion.
- Admin metrics are in memory and reset on restart.
- The admin endpoint is API-protected by `ADMIN_TOKEN`; the included visual dashboard is a basic metrics page, not a full login/user-management system.
- Free hosting is for testing, not production or sensitive documents.

## 1. Requirements

Install Python 3.11 or 3.12 and Git. Then open a terminal in this folder.

### Windows PowerShell
```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
$env:ADMIN_TOKEN="replace-with-a-long-random-secret"
uvicorn app.main:app --reload
```

### macOS / Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
export ADMIN_TOKEN="replace-with-a-long-random-secret"
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000

Interactive API docs: http://127.0.0.1:8000/docs

Health check: http://127.0.0.1:8000/health

## 2. Admin dashboard and metrics API

Open http://127.0.0.1:8000/admin and enter the `ADMIN_TOKEN` value you set in your terminal. This is a basic metrics dashboard, not a full user-management system.


Use the same secret you set in `ADMIN_TOKEN`:

```bash
curl -H "X-Admin-Token: replace-with-a-long-random-secret" http://127.0.0.1:8000/api/admin/stats
```

This endpoint returns temporary process metrics. Do not expose the token in browser JavaScript or commit it to Git.

## 3. Configure trusted roots

For a meaningful trust decision, explicitly configure a reviewed directory of trusted CA certificates in PEM/DER form. Set `TRUST_ROOTS_DIR` to that directory. Do not download random certificates and trust them. Obtain and maintain roots from authoritative sources and verify their fingerprints and policy.

Example:
```bash
export TRUST_ROOTS_DIR="trust_roots"
```

On Windows PowerShell:
```powershell
$env:TRUST_ROOTS_DIR="trust_roots"
```

If no trust roots are configured, the app may be unable to establish trust for otherwise mathematically valid signatures. It will not automatically call such a result `VALID`.

## 4. Free deployment (testing only)

1. Create a GitHub repository and push this project.
2. Create a Render account and choose **New → Blueprint** or create a Python web service.
3. Connect the repository. `render.yaml` contains a starter deployment configuration.
4. Set `ADMIN_TOKEN` to a strong secret in the service's environment settings.
5. Deploy and test with non-sensitive sample PDFs first.

Free Render services can sleep, have ephemeral filesystems and usage limits. Do not use free hosting for confidential certificates or as a production-grade service. See https://render.com/docs/free

## 5. Suggested next steps before launch

1. Add a real visual admin page and authenticated login/session handling.
2. Add queue/background jobs for large batches and strict resource limits.
3. Add rate limiting, request size limits at the proxy, malware scanning, and abuse controls.
4. Add tests with valid, invalid, unsigned, expired, revoked, and untrusted sample PDFs.
5. Configure Indian CCA/CA trust anchors and revocation policy based on authoritative sources.
6. Add retention policy, privacy notice, terms, and security review.
7. Use persistent database only for non-sensitive aggregate metrics; avoid storing user documents by default.
