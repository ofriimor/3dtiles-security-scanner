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

        zip_file.extractall(extract_dir)   ## extract all is a python function that does the extract


# find the one tileset.json inside the folder
def find_tileset(folder):
    tileset_files = list(folder.rglob("tileset.json")) ## finds files with this name in all dirs and their dirs 
    # and returninng them all in a list
    if not tileset_files:
        raise ValueError("tileset.json file is not inside the zip") ## there isnt tileset at all

    if len(tileset_files) > 1: # for this scan , supposed to be one tileset
        raise ValueError("more than one tileset.json found")
    return tileset_files[0]

## figured id do the same thing i did in the validator here. 
def is_glb_by_magic(filepath):
    with open(filepath, "rb") as file:
        magic = file.read(4)

    return magic == b"glTF"


# clean tileset.json and every glb, returns the files to keep and a report
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

    # check every file the tileset uses 
    for item in tileset_result["files"]:

        is_glb = is_glb_by_magic(item["path"])

        # 1. not a 3D Tiles file at all (html, exe...)
        if item["file_type"] == "OTHER":
            raise HTTPException(status_code=400,
                detail=f"invalid file in 3D Tiles package: {item['uri']}")

        #  .glb extension but not glb magic
        if item["file_type"] == "GLB" and not is_glb:
            raise HTTPException(status_code=400,
                detail=f"invalid glb magic bytes: {item['uri']}")

        # other extension but glb magic (a GLB file hiding as .b3dm) - idk why , but not approved
        if item["file_type"] != "GLB" and is_glb:
            raise HTTPException(status_code=400,
                detail=f"glb magic bytes with wrong extension: {item['uri']}")

        # a known 3D Tiles type we can't scan yet
        if item["file_type"] != "GLB":
            report["not_scanned"].append(item["uri"])
            continue

        # what's left is a real GLB: scan it
        glb_result = sanitize_glb(item["path"], item["path"])     # (where we have the item we want to scan , overriding it with the sanatized file)

        if glb_result["status"] == "REJECT":  ## coudtnt sanatize it . or the structure incorrect
            raise HTTPException(status_code=400, detail={
                "error": "glb could not be sanitized",
                "file": item["uri"],
                "reason": glb_result["error"]
            })

        if glb_result["status"] == "SANITIZED":   
            report["sanitized_glbs"].append({
                "file": item["uri"],   ## get the uri of each sanatized from the sanatized tileset
                "removed": glb_result["removed"] ## from the tileset_result["files"]
            })

    return tileset_result["files"], report  


# build a new zip with only tileset.json, the files it uses and the report
def build_zip(extract_dir, tileset_path, files, report, new_zip_path):

    added = [] ## all the paths , so i will not add somthing that was already in the list

    with zipfile.ZipFile(new_zip_path, "w", zipfile.ZIP_DEFLATED) as new_zip: ## w for write
        ## zipfile - object that represent the file , zip_deflated lets me do the compression
        ## returnin the zip compressed

        new_zip.write(tileset_path, tileset_path.relative_to(extract_dir)) ## adding tilesetpath to the tileset_path.relative_to(extract_dir)

        for item in files:

            path = Path(item["path"])   ## take the path of the item and turn it into path item

            if path not in added:  ## the same glb can be used by many tiles
                new_zip.write(path, path.relative_to(extract_dir)) ## then take the file within this path 
                ## and put this in the relative path within the zip
                added.append(path) ## add it to the added list , so i will not add twiice

        new_zip.writestr("report.json", json.dumps(report, indent=2)) ## create report.json file 
        ## use the report from the sanatize_package, json dumps coverts python dict to json
        # with indent , google recommended , cause its pretty print that way (hazahot)


# open the new zip and check the whole package again
def check_new_zip(new_zip_path, check_dir):

    check_dir.mkdir() ## new dir called check_dir
    extract_zip_safely(new_zip_path, check_dir) ## extracts the new zip built , into the checkdir 

    tileset_path = find_tileset(check_dir) ## search the tileset.json in the new dir , if doesnt exist or exit 2 is invlid
    result = validate_tileset_and_collect_uris(tileset_path, check_dir) # gets the tileset i jsut extracted , validate it from within

    if result["status"] != "valid" or result["uri_findings"]: ## tilset not valid or there are uri findings
       return False ## the new zip is not safe

    for item in result["files"]:
        if item["file_type"] == "GLB":   ## i want to change it to magic types, in the future 
            if scan_glb_security(item["path"])["security_status"] != "NO_FINDINGS":
                return False

    return True


@app.post("/tileset-scanner/") ## telling the fast api: when a post http request is coming to /tileset-scanner/
## when it happens , run this func
def inspect_tileset_endpoint(file: UploadFile = File(...)): # upload file meaning we are excpectiing a file that thw user uploaded
    ## and the file... meaning its a must parameter, 

    # check that the uploaded file is a zip by its extension(i need to figure out a clever way to do that)
    if not file.filename or not file.filename.lower().endswith(".zip"): 
        raise HTTPException(status_code=400, detail="upload a zip file")

    # create a temporary folder for this scan
    with tempfile.TemporaryDirectory() as temp_dir: ## when the user sends zip
        ## temp dir is a str for the path of the file 
        temp_path = Path(temp_dir).resolve()  ## makes the tempdir to path object the python can work with 
        ## the resolve for 
        extract_dir = temp_path / "extracted" ## sub dir named extracted
        extract_dir.mkdir() ## creating it , currently empty

        zip_path = temp_path / "uploaded.zip" ## same thing 
        ## temp - extracted dir, uploaded zip in it 

        # Save the uploaded ZIP file
        with open(zip_path, "wb") as saved_file: # opening the zip path , and writing binary
            ## apparently only using w isnt enough , cause it would write text by default
            ## thats how we write the bytes in the most accurate way
            shutil.copyfileobj(file.file, saved_file)  # file.file is the content of the file in zip_path, that we uploaded
            # saved_file is the file we write in, and shutil.copyfileobj copies the data from one zip to the saved_file 

        try:

            extract_zip_safely(zip_path, extract_dir) ## trying to extract 
            ## if succeded.. 
            tileset_path = find_tileset(extract_dir)  # get the tileset.json
            ## raise = just stopping the func and using the try/except handling errors engine
            # Step 3: Clean tileset.json and the GLB files
            files, report = sanitize_package(tileset_path, extract_dir) ## making sure its clean and gettin the files and the json report

            # building the new zip now 
            new_zip_path = temp_path / "sanitized.zip" ## only declaring that this is the path i want to put the anatized in
            build_zip(extract_dir, tileset_path, files, report, new_zip_path) ## buliding evrything in this path

            ## checking the new zip again , making sure 
            if not check_new_zip(new_zip_path, temp_path / "check"): # with the path to the new zip, and :  temp_path / "check" is another path that the func will extract her zip into , to check it 
                raise HTTPException(status_code=400, detail="package failed the final check")

            #return the sanitized zip, with the same name + " - scanner"
            new_name = Path(file.filename).stem + " - scanner.zip" # i figured this will be ok , like the bgn does

            ## now building the http response that is sent back to the user, using the fastapi library
            ## this library has everything.
            # nfm - newzipfile is the path to sanatized.zip, read_bytes reads the binary data and returns it as bytes
            return Response(
                content=new_zip_path.read_bytes(), ## the path to the new zip , read the bytes out of him and send it 
                media_type="application/zip",
                ## quote() so names in Hebrew or with spaces work too
                headers={"Content-Disposition": "attachment; filename*=UTF-8''" + quote(new_name)}
            )

        except ValueError as error: ## saving the object valueerror in error variable
            raise HTTPException(status_code=400, detail=str(error)) # making it string 
        ## for example if there is in extract zip : raise ValueError("the zip contains too much files")
        # it will return this exactly with this status code

        except zipfile.BadZipFile: ## is the zip is unreadable
            raise HTTPException(status_code=400, detail="invalid ZIP file")  ## hardcoded , not somthing xpecific , using the badzipfile method
