# Secure Document Library

Secure Document Library is a small, offline Python package for building a searchable library from approved files without placing the full document text in the search index. It is designed to be the secure evidence and retrieval layer beneath an AI analysis, chat, or question-answering application.

It is useful when documents must stay in a controlled source folder, search should remain local, and the text needed for later evidence retrieval must be encrypted at rest. An AI application can search this library, retrieve only the selected authorized documents, and give those documents to a model as grounded evidence for a source-cited answer. The project contains only generic implementation code and synthetic tests; it contains no document corpus, credentials, company configuration, or generated data.

## How it supports AI analysis

This package does **not** choose, call, or host an AI model. Instead, it supplies the part an AI application needs in order to answer questions from approved internal knowledge safely:

1. The user asks an AI application a question.
2. The application searches this library's lightweight index without exposing or decrypting all document text.
3. The application applies its authenticated user's authorization grants.
4. It retrieves only the top matching, permitted `document_id` values.
5. The application passes that bounded evidence to its selected AI provider or local model.
6. The model answers using that evidence and cites the document titles/relative paths supplied by the application.

This pattern helps reduce unnecessary data exposure, makes answers easier to ground in known documents, and lets the application state when it did not retrieve enough evidence. It also means a future AI integration can be changed—from a local model to an approved hosted provider—without changing the cache or search design.

## What it does

Given an approved source folder, the library:

1. Reads supported files without modifying them.
2. Extracts their text into one or more document parts.
3. Encrypts each extracted text value with AES-256-GCM in an external, content-addressed cache.
4. Writes a compact JSONL index containing safe metadata, content hashes, and HMAC-SHA256 token frequencies—not plaintext document bodies.
5. Searches the index using metadata and hashed body terms without decrypting documents.
6. Retrieves selected content only by indexed `document_id`, after an authorization grant is supplied.

```text
Approved source files
        |
        v
Offline parsers --> encrypted cache (AES-256-GCM)
        |                     ^
        v                     |
lightweight JSONL index -------+
        |
        v
authorized search --> document ID --> selected decryption
```

In a production AI workflow, the final “selected decryption” step is where the caller assembles a short, authorized evidence bundle for the model. It should enforce document and total-character limits, avoid writing plaintext evidence to temporary files, and instruct the model to disclose evidence gaps instead of inventing an answer.

## Supported formats

| Format | Handling |
| --- | --- |
| Markdown / TXT | UTF-8, UTF-8 with BOM, then GB18030 fallback |
| YAML / JSON | Safely parsed to verify syntax, then indexed as text |
| DOCX | Paragraphs and tables are extracted; macros are not executed |
| XLSX | Read-only mode, cached formula values only, no external-link loading; each worksheet becomes a document part |

Files are subject to conservative size and extracted-character limits. Unsupported extensions are skipped.

## What is stored where

The source folder is never modified, renamed, copied, or deleted by the package.

| Location | Contains | Must not be committed |
| --- | --- | --- |
| Source root | Original approved files | Usually yes |
| Cache root | AES-GCM encrypted parsed text | Yes |
| Index output | Titles, relative paths, types, document IDs, content hashes, HMAC token frequencies, opaque cache references | Yes for sensitive deployments |
| Repository | Source code, tests, documentation, package metadata | Suitable for public review after your own review |

The index does not contain the full parsed text. An HMAC token frequency cannot be searched without the separate search key, but metadata such as titles and relative paths may still be sensitive and should be protected accordingly.

## Security properties and boundaries

- AES-256-GCM provides confidentiality and tamper detection for cached text.
- Each newly encrypted object uses a random 96-bit nonce and authenticated metadata.
- Cache objects are deduplicated by normalized-content SHA-256 hash.
- Encryption and HMAC-search keys are separate environment variables and must decode to different 32-byte values.
- Search returns no results until a caller supplies authorized source IDs.
- Retrieval accepts an indexed document ID, not an arbitrary filesystem path.
- Search does not decrypt cache objects; only `retrieve` decrypts a selected record.
- The package makes no network calls for parsing, building, searching, or retrieval.

The caller remains responsible for any AI-provider call. If evidence is sent to a hosted model, that transfer is governed by the provider agreement, enterprise approval, model configuration, and the caller's authorization policy—not by the cache encryption alone.

This is a library, not a complete production access-control system. A real deployment must authenticate users, map identities to source grants, protect the service identity and filesystem ACLs, and use an enterprise secret manager instead of development environment variables.

## Requirements

- Python 3.11 or later
- `cryptography`, `PyYAML`, `python-docx`, and `openpyxl` (installed automatically from `pyproject.toml`)
- A cache location outside this repository and outside public/shared user folders
- Two distinct base64-encoded 32-byte random keys

Generate development-only keys with Python:

```powershell
python -c "import base64, secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

Run it twice: once for `SECURE_LIBRARY_CACHE_KEY` and once for `SECURE_LIBRARY_SEARCH_KEY`.

## Installation

```powershell
git clone <your-public-repository-url>
Set-Location secure-document-library
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
```

Set the required runtime settings for the current PowerShell session:

```powershell
$env:SECURE_LIBRARY_CACHE_ROOT = 'D:\secure-library-cache'
$env:SECURE_LIBRARY_CACHE_KEY = '<base64-encoded-32-byte-encryption-key>'
$env:SECURE_LIBRARY_SEARCH_KEY = '<different-base64-encoded-32-byte-search-key>'
```

Never put real values for these variables in code, committed configuration files, or GitHub Actions secrets visible to untrusted workflows.

## Command-line workflow

Build an index from a source folder:

```powershell
secure-library build --source-root D:\approved-documents --output .\index
```

Search the existing index. `--authorized-source default` is the generic example grant used by this standalone package; a real service must derive grants from authenticated identity and policy.

```powershell
secure-library search "example terms" --index .\index --authorized-source default
```

Retrieve one selected document after search. Use the `document_id` returned by the search result:

```powershell
secure-library retrieve <document-id> --index .\index --authorized-source default
```

Do not expose this retrieval command directly to untrusted users without adding real authentication, authorization, audit logging, rate limiting, and output controls.

## Python API

```python
from pathlib import Path
from secure_document_library.library import build, search, retrieve

build(Path(r"D:\approved-documents"), Path("index"))
results = search(Path("index"), "example terms", {"default"})
text = retrieve(Path("index"), results[0]["document_id"], {"default"})
```

`search()` returns metadata and a score only. `retrieve()` returns decrypted text only when the requested ID belongs to an authorized source.

## Testing

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m unittest discover -s tests -v
```

The included test verifies encrypted build/search/retrieval behavior, denied search without authorization, and that sample plaintext is absent from the encrypted cache file.

## Production checklist

- Use a dedicated, non-administrator service account.
- Grant source roots read-only access to that account only.
- Store cache data and generated indexes outside the repository with separate restrictive ACLs.
- Use BitLocker or approved volume encryption in addition to AES-GCM object encryption.
- Replace the environment-key method with Windows or enterprise secret management.
- Use HTTPS and enterprise authentication for any remote service.
- Treat titles, paths, and index metadata as potentially sensitive.
- Back up encrypted cache data and keys under equivalent access controls.
- Review retention and key-rotation procedures before production use.

## Limitations

- This minimal generic example does not implement incremental rebuilds, release publication/rollback, document-level audit logs, user identity verification, or an external AI answer workflow. It is the retrieval/evidence component that an AI-answer workflow would use.
- It does not perform OCR, transcription, macro execution, formula calculation, or external search/embedding calls.
- XLSX and DOCX parsing preserves useful text but is not a full fidelity document renderer.

Those features should be added only with an explicit security, authorization, and deployment design appropriate to the organization using it.
