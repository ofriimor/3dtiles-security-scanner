from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import Response
from pathlib import Path
import json
from urllib.parse import quote
import tempfile
import zipfile
import shutil
import stat
from tileset_validator import validate_tileset_and_collect_uris
from glb_security_scanner import scan_glb_security
from sanitize_tileset import sanitize_tileset
from glb_sanitizer import sanitize_glb


app = FastAPI(
    title="3D Tiles Security Scanner",
    description="api for sanitizing 3D tiles zip packages",
    version="0.2.0"
)


def extract_zip_safely(zip_path, extract_dir): ## zip path in my computer , extract dir - the dir i want to put in the exrtacted zip
    extract_root = extract_dir.resolve()  ## if :extract_dir = Path("temp/extracted") then :C:\project\temp\extracted
    ## resolve() makes it  cwd , current working directory instead of relative path


    total_size = 0 ## now i want to make sure im not getting Dos attack on my app
    with zipfile.ZipFile(zip_path, "r") as zip_file:
        items = zip_file.infolist()  # the number of the resources in the zip 
        if len(items) > 50000: ## 
            raise ValueError("zip contains too many files") ## ive read that this is the appropriate ammount for rejecteing 
        ## the files can be so tiny , and casue a lot of effort to extract them
        # check every file before extracting anything
        for item in items:   
            total_size += item.file_size ## for each item in the loop we are getting his file size and adding to the total size
            if total_size > 500 * 1024 * 1024: # 500 MiB if its reaches this size in some point 
                raise ValueError("zip is too large")

            if item.compress_size > 0 and item.file_size / item.compress_size > 200: ## the division of the compression 
                ## apperntly it can cost zipbomb attack
                ##wiki : a malicious, tiny archive file designed to crash, freeze, or overwhelm a computer system or server by 
                #expanding into an enormous amount of data when unzipped!! , thats why i need to check 
                ## if the 400 - the filesize , and the compressed is 1mb i will do 400/1 = reject cause > 200
                raise ValueError("suspicious zip compression ratio")
            
            if item.flag_bits & 0x1: # Bitwise AND, asks if the first bit is up(1) , if so , its encrypted
                raise ValueError("encrypted ZIP files are not supported")
            ## 0001 - encrypted , the rightest byte is 1 , 000010 - not 
            output_path = (extract_dir / item.filename).resolve() # C:\scanner\temp\extracted / models/building.glb , not division but connecting the paths C:\scanner\temp\extracted\models\building.glb

            if "\\" in item.filename or not output_path.is_relative_to(extract_root):  ## the final path is within the extract root?
                raise ValueError("unsafe path found inside the zip")

        zip_file.extractall(extract_dir)   ## 


# find the one tileset.json inside the folder
def find_tileset(folder):
    tileset_files = list(folder.rglob("tileset.json")) ## finds files with this name in all dirs and their dirs 
    # and returninng them all in a list
    if not tileset_files:
        raise ValueError("tileset.json file is not inside the zip") ## there isnt tileset at all

    if len(tileset_files) > 1: # for this scan , supposed to be one tileset
        raise ValueError("more than one tileset.json found")
    return tileset_files[0]


# clean tileset.json and every GLB, returns the files to keep and a report
def sanitize_package(tileset_path, extract_dir):

    # we get the clean tileset , (the file i want to clean,the extracted dir, the path that the files are going to be saved in overriding the first )
    tileset_result = sanitize_tileset(tileset_path, extract_dir, tileset_path)

    if tileset_result["status"] == "REJECT":   ## meaning the structure is currpted or couldnt sanatize well
        raise HTTPException(status_code=400, detail={
            "error": "invalid tileset.json", 
            "findings": tileset_result["findings"]
        })

    report = {   ## give it either way
        "removed_uris": tileset_result.get("removed", []),
        "sanitized_glbs": [],
        "not_scanned": []
    }

    # Step 2: Clean every GLB
    for item in tileset_result["files"]:

        # other file types are kept, but not scanned, not deleting it - FOR NOW....
        if item["file_type"] != "GLB": # ill focus on them in the future 
            report["not_scanned"].append(item["uri"]) ## just add the uri of them for now 
            continue ## moving   to the next file 

        glb_result = sanitize_glb(item["path"], item["path"])     # (where we have the item we want to scan , overriding it with the sanatized file)

        if glb_result["status"] == "REJECT":
            raise HTTPException(status_code=400, detail={
                "error": "glb could not be sanitized",
                "file": item["uri"],
                "reason": glb_result["error"]
            })

        if glb_result["status"] == "SANITIZED":
            report["sanitized_glbs"].append({
                "file": item["uri"],
                "removed": glb_result["removed"]
            })

    return tileset_result["files"], report


# Build a new ZIP with only tileset.json, the files it uses and the report
def build_zip(extract_dir, tileset_path, files, report, new_zip_path):

    added = []

    with zipfile.ZipFile(new_zip_path, "w", zipfile.ZIP_DEFLATED) as new_zip:

        new_zip.write(tileset_path, tileset_path.relative_to(extract_dir))

        for item in files:

            path = Path(item["path"])

            if path not in added:  ## the same GLB can be used by many tiles
                new_zip.write(path, path.relative_to(extract_dir))
                added.append(path)

        new_zip.writestr("report.json", json.dumps(report, indent=2))


# Open the new ZIP and check the whole package again
def check_new_zip(new_zip_path, check_dir):

    check_dir.mkdir()
    extract_zip_safely(new_zip_path, check_dir)

    tileset_path = find_tileset(check_dir)
    result = validate_tileset_and_collect_uris(tileset_path, check_dir)

    if result["status"] != "valid" or result["uri_findings"]:
        return False

    for item in result["files"]:
        if item["file_type"] == "GLB":
            if scan_glb_security(item["path"])["security_status"] != "NO_FINDINGS":
                return False

    return True


@app.post("/tileset-scanner/")
def inspect_tileset_endpoint(file: UploadFile = File(...)):

    # Check that the uploaded file is a ZIP
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Please upload a ZIP file")

    # Create a temporary folder for this scan
    with tempfile.TemporaryDirectory() as temp_dir:

        temp_path = Path(temp_dir).resolve()
        extract_dir = temp_path / "extracted"
        extract_dir.mkdir()

        zip_path = temp_path / "uploaded.zip"

        # Save the uploaded ZIP file
        with open(zip_path, "wb") as saved_file:
            shutil.copyfileobj(file.file, saved_file)

        try:

            # Step 1: Extract the ZIP
            extract_zip_safely(zip_path, extract_dir)

            # Step 2: Find tileset.json
            tileset_path = find_tileset(extract_dir)

            # Step 3: Clean tileset.json and the GLB files
            files, report = sanitize_package(tileset_path, extract_dir)

            # Step 4: Build the new ZIP
            new_zip_path = temp_path / "sanitized.zip"
            build_zip(extract_dir, tileset_path, files, report, new_zip_path)

            # Step 5: Check the new ZIP again
            if not check_new_zip(new_zip_path, temp_path / "check"):
                raise HTTPException(status_code=400, detail="Package failed the final check")

            # Step 6: Return the sanitized ZIP, with the same name + " - scanner"
            new_name = Path(file.filename).stem + " - scanner.zip"

            return Response(
                content=new_zip_path.read_bytes(),
                media_type="application/zip",
                ## quote() so names in Hebrew or with spaces work too
                headers={"Content-Disposition": "attachment; filename*=UTF-8''" + quote(new_name)}
            )

        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error))

        except zipfile.BadZipFile:
            raise HTTPException(status_code=400, detail="Invalid ZIP file")
