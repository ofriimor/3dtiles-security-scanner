3D Tiles Security Scanner
A proof of concept for scanning and sanitizing 3D Tiles packages before they reach a viewer.
Goal
3D Tiles from untrusted sources are loaded automatically by viewers and servers. The question this POC answers:
Can a 3D Tiles package be checked, cleaned, and returned safe to use, without breaking the tiles?
The scanner takes a ZIP with a `tileset.json` and its GLB files, removes what is unsafe, checks everything again, and returns a clean ZIP with a report.
Threats
GLB (glTF 2.0 binary)
Parser exploitation: a malformed header, wrong chunk lengths, or bufferViews that point past the BIN chunk can trigger out-of-bounds reads in the reader (CVE-2023-21782, CVE-2023-21783, CVE-2023-25884, ZDI-24-1088).
Script injection: any string in the JSON chunk (`asset.generator`, node names, `extras`) can hold `<script>`, `onload=` or `javascript:`, which runs if a web viewer renders it as HTML (CVE-2026-28737).
Hidden external data: the GLB's own buffer is supposed to live inside the file, not at an external `uri`.
tileset.json
External resources: `content.uri` can point to `https://...` or an internal address, so the viewer fetches content nobody approved (SSRF).
Path traversal: `../`, encoded `%2e%2e/`, or absolute paths reach files outside the package.
Broken references: uris to files that don't exist in the package.
The ZIP itself
Zip Slip: entry names that escape the extraction folder.
ZIP bombs: small archives that expand to huge sizes.
Architecture
```
upload.zip
   │
   ▼
safe extract ──────────────────────────── reject (HTTP 400)
   │                                            ▲
   ▼                                            │
tileset_validator ── bad uri? ── sanitize_tileset
   │
   ▼  for every GLB
glb_validator ─── broken? ──────────────────────┤
   │                                            │
   ▼                                            │
glb_security_scanner ── XSS? ── glb_sanitizer   │
   │                                            │
   ▼                                            │
build new ZIP → extract again → scan again ─────┘
   │
   ▼
<name> - scanner.zip  +  report.json
```
Module	Job
`main.py`	FastAPI endpoint, safe extraction, builds and re-checks the output
`tileset_validator.py`	Tileset structure, resolves every `content.uri`
`sanitize_tileset.py`	Removes bad references, keeps the tiles
`glb_validator.py`	GLB 2.0 binary structure
`glb_security_scanner.py`	Finds script patterns in every JSON string
`glb_sanitizer.py`	Removes findings, rebuilds the GLB, scans again
Two rules hold everywhere:
A file that can't be parsed completely is rejected, not repaired.
Every cleaned file is validated again before it is returned.
Run with Docker
Build the image:
```
docker build -t tiles-scanner .
```
Run it:
```
docker run --rm -p 8000:8000 tiles-scanner
```
Open `http://localhost:8000/docs` and upload a ZIP to `/tileset-scanner/`, or:
```
curl -F "file=@city.zip" -o "city - scanner.zip" http://localhost:8000/tileset-scanner/
```
The container runs as a non-root user. For a locked-down run:
```
docker run --rm -p 8000:8000 --read-only --tmpfs /tmp --memory 1g --cpus 1 --security-opt no-new-privileges tiles-scanner
```
Not covered yet
Accessor and `byteStride` bounds in GLB
Image and extra buffer uris inside GLB
B3DM, I3DM, PNTS, CMPT and nested tilesets (copied, listed as `not_scanned`)
