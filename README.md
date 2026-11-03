3D Tiles Security Scanner
A security scanner for 3D Tiles packages.
> **Note**
>
> This is a university project. It is not a full validator for the 3D Tiles specification. For complete specification checks, see the [3D Tiles Validator](https://github.com/CesiumGS/3d-tiles-validator).
Overview
The scanner receives a 3D Tiles package as a ZIP file, checks it for content that could harm a viewer or the server that loads it, removes what can be removed safely, and returns a cleaned copy of the package. It runs as a small web service based on FastAPI, and can be started directly with Python or inside a Docker container.
The scanner only cleans files that it could parse completely. A file with a broken structure is rejected and is not repaired. After cleaning, the new package is extracted again and goes through all checks a second time, and it is only returned when this second run finds nothing.
Note: The checks and the report format may still change.
Implemented Features
Safe extraction of the uploaded ZIP file
Every entry is checked before anything is written to disk
Entries with `../`, absolute paths, drive letters or backslashes are rejected (Zip Slip)
Archives with more than 2,000 entries, more than 500 MB of uncompressed data, or a compression ratio above 200:1 are rejected (ZIP bombs)
Symbolic links and encrypted entries are rejected
Validation of the JSON structure of the `tileset.json` file
The required properties `asset`, `geometricError` and `root`, and the `boundingVolume`, `geometricError` and `refine` of the root tile
Validation of every `content.uri` in the tile tree
The uri is decoded first, so that `%2e%2e/` is treated as `../`
External uris (`https://...`, `//host/...`) are not allowed
The resolved path must stay inside the extracted package, and the file must exist
An invalid reference is removed from the tileset, while the tile itself is kept
Validation of the binary structure of GLB files
Header, chunk layout, JSON chunk, `asset.version`, buffers and bufferViews
Detection and removal of script content in the JSON chunk of GLB files
`<script>` tags, HTML event handlers like `onload=`, and `javascript:` uris
Flagged values are removed, and the GLB is rebuilt with the original binary data
Tile content in other formats (B3DM, I3DM, PNTS, CMPT), images and external tilesets are copied to the output, but are not scanned. They are listed in the report as `not_scanned`.
Installation
The scanner requires Python 3.9 or newer.
Clone the repository:
```
git clone https://github.com/ofriimor/3dtiles-security-scanner.git
cd 3dtiles-security-scanner
```
Create a virtual environment and install the dependencies:
```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```
(On Linux or macOS, activate the environment with `source .venv/bin/activate` instead.)
Usage
Start the service
```
uvicorn main:app --port 8000
```
The service is then available at `http://localhost:8000`. An interactive page for trying out the API is available at `http://localhost:8000/docs`.
Scan a package
```
curl -F "file=@city.zip" -o "city - scanner.zip" http://localhost:8000/tileset-scanner/
```
The uploaded file must be a ZIP file that contains exactly one `tileset.json` file. The tileset may be located in a subdirectory of the ZIP file. The response is a new ZIP file with the same name as the upload, followed by ` - scanner`.
The new ZIP file only contains the `tileset.json` file, the files that are referenced by the tileset, and a `report.json` file. Other files from the upload are not copied.
When the package cannot be cleaned, the response has the status code 400, and the reason is given in the `detail` property of the JSON response. No partial package is returned in this case.
Report File
The `report.json` file in the output describes what was changed. For example:
```
{
  "removed_uris": [
    {
      "uri": "https://example.com/model.glb",
      "location": "root.children[1].content",
      "file_type": "GLB",
      "status": "ALERT",
      "message": "External URI is not allowed"
    }
  ],
  "sanitized_glbs": [
    {
      "file": "tiles/a.glb",
      "removed": [
        "glb_json.asset.generator",
        "glb_json.nodes[0].name"
      ]
    }
  ],
  "not_scanned": [
    "tiles/b.b3dm"
  ]
}
```
The `location` values describe the path of the removed value in the JSON. For `removed_uris`, this is the path in the `tileset.json` file. For `sanitized_glbs`, this is the path in the JSON chunk of the GLB file.
Docker
The repository contains a `Dockerfile` for running the scanner in a container. The image is based on `python:3.12-slim`, and the service runs as a user without root permissions.
Build the image:
```
docker build -t tiles-scanner .
```
Run a container:
```
docker run --rm -p 8000:8000 tiles-scanner
```
The service is then available at `http://localhost:8000`, in the same way as described in Usage.
To limit what the container can do, it can be started with a read-only file system and resource limits. The scanner only writes to `/tmp`, so this directory is given as a temporary file system:
```
docker run --rm -p 8000:8000 --read-only --tmpfs /tmp --memory 1g --cpus 1 --security-opt no-new-privileges tiles-scanner
```
Implementation Notes
The checks are split into validators, which only report problems, and sanitizers, which change files and then call the validators again on the result:
`main.py` contains the FastAPI endpoint. It extracts the upload, calls the sanitizers, builds the new ZIP file and runs the final check.
`tileset_validator.py` checks the structure of the `tileset.json` file and resolves every uri in the tile tree.
`sanitize_tileset.py` removes invalid references from the tileset and validates the new file.
`glb_validator.py` checks the binary structure of a GLB file.
`glb_security_scanner.py` checks every string in the JSON chunk of a GLB file and reports the location of each finding.
`glb_sanitizer.py` removes the reported values, rebuilds the GLB file and scans it again.
Values are removed by their location, for example `nodes[0].name`. When several entries of the same list are removed, they are removed starting from the highest index, so that removing one entry does not change the index of the others.
Known Limitations
Accessors and `byteStride` in GLB files are not validated yet
Uris inside GLB files (images and additional buffers) are not checked yet
There are no limits for the depth of the JSON, the number of tiles, or the processing time
Tile formats other than GLB and external tilesets are not scanned
