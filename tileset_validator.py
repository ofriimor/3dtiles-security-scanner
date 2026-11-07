
import json ## 
from pathlib import Path ## for handling better with path of files , for opening the tileset and getting the correct dr 
from urllib.parse import urlparse, unquote ## splits url , for the uri %20 instead of space with unquote 


# check the tileset validation
def inspect_tileset(file_path): ## path to tileset

    findings = [] #

    # check if the tileset even exists
    if not Path(file_path).is_file():
        return {
            "status": "invalid",
            "findings": ["file does not exist"] ## rejected in the end 
        }

    # starts reading the file 
    try:  ## cause i can read it but it can be corrupted 
        with open(file_path, "r", encoding="utf-8") as file: ## with lets me open it , open(/3dtiles/tileset.json, read only, for understanign languages )
            tileset_json = json.load(file)  ## now instead of text , python converts it to json dict

    except (json.JSONDecodeError, UnicodeDecodeError) as error: ## corrupted , not really json 
        ## using try instead of if cause i dont know  whats goinng to fail, i assume it  can happen
        ##json.JSONDecodeError -- not json , UnicodeDecodeError - the utf-8 was not right 
        return {
            "status": "invalid",
            "findings": [f"invalid json: {error}"]
        }

    if not isinstance(tileset_json, dict):  ## we reas the json , but its not dict , structure not right 
        return {
            "status": "invalid",
            "findings": ["tilest must be a json object"]
        }


    required_fields = ["asset", "geometricError", "root"]  ## https://github.com/CesiumGS/3d-tiles/blob/main/specification/schema/tileset.schema.json

    for field in required_fields: ## for each field , checks if it exists in the 
        if field not in tileset_json:
            findings.append(f"Missing required field: {field}")

    # Check asset
    asset = tileset_json.get("asset")

    if not isinstance(asset, dict):
        findings.append("Field 'asset' must be an object")  ## append adds object to the end of the list

    elif not isinstance(asset.get("version"), str):
        findings.append("Field 'asset.version' must be a string")

    # Check geometricError
    geometric_error = tileset_json.get("geometricError")

    if (
        not isinstance(geometric_error, (int, float))
        or geometric_error < 0 ## how much can i present a tile with error , if  i get closer to the model , the geometric error will be smaller
    ):
        findings.append(
            "field 'geometricError' must be a positive number"
        )

    # Check root tile
    root = tileset_json.get("root")

    if not isinstance(root, dict):   ## also has to be dict 
        findings.append("field 'root' must be an object")

    else:

        if "boundingVolume" not in root:   
            findings.append("Missing required field: root.boundingVolume")

        if "geometricError" not in root:
            findings.append("Missing required field: root.geometricError")
        ## both have to be under root field 
        elif (
            not isinstance(root["geometricError"], (int, float))
            or root["geometricError"] < 0
        ):
            findings.append(
                "root.geometricError must be a positive number"
            )

        if "refine" in root: ## optional one , it adds children , each present more data on the tile 
            if root["refine"] not in ["ADD", "REPLACE"]:  ## are the 2 possibilites for refine value 
                findings.append("root.refine must be ADD or REPLACE")

    return {
        "status": "invalid" if findings else "valid", ## if finding not [] retrun valid
        "findings": findings,
        "tileset_json": tileset_json ## return the entire json load of the tilset, so the next func can use it s
    }

def collect_tileset_uris(tileset_json):

    uris = [] ## empty list

    
    ## ok problem :"root": {
 ## "content": {"uri": "city.glb"},
 ## "children": [
  ##  {"content": {"uri": "building1.glb"}},
   ## {"content": {"uri": "building2.glb"},
    ## "children": [
       ##{"content": {"uri": "window.glb"}}
     ##]}
  ##]
##} every children can have his childern and so on , i need to get to evry single tile without missing
# not just the glb tile father

    def scan_tile(tile, location):  # value of the tile , location of it in the json

        if not isinstance(tile, dict): ## has to be dict 
            return

        content = tile.get("content")  ## "content": {"uri": "city.glb"}, (and the rest) we are getting the dict in the content
        if isinstance(content, dict):  # is this really dict
            uri = content.get("uri") or content.get("url")  # city.glb string
            ## if there are 2 of them , it will return the first one he found - bug
            if isinstance(uri, str): # just checking
                uris.append({   ## add to the uris list the uri and its location in the json 
                    "uri": uri, ## city.glb
                    "location": f"{location}.content"  ## root.content
                })

        children = tile.get("children", [])  ## if it doesnt have a children , it goes back to the  father 

        if isinstance(children, list): ## empty list ? not running
            for index, child in enumerate(children):  ## taking the value and the index so ill know what to delete
                child_location = f"{location}.children[{index}]"
                scan_tile(child, child_location) ## root.children[0]

    scan_tile(tileset_json.get("root"), "root") ## when doesnt have chikdren , python lets you go back to the next child if there is under the root 
    ## python has a stack of memory or smt
    return uris


# identify the file type by its extension
def get_file_type(uri):

    uri_path = urlparse(uri).path # url parse splits the ? when its usually in urls 
    extension = Path(uri_path).suffix.lower()  ## the extension with lowercase letters , will return .glb

    if extension == ".glb":
        return "GLB"

    if extension == ".gltf":
        return "GLTF"

    if extension == ".json":  
        return "JSON"

    if extension in [".b3dm", ".i3dm", ".pnts", ".cmpt"]:  ## in the future ill support then too
        return "3D_TILES"

    if extension == ".subtree":
        return "SUBTREE"

    if extension in [".png", ".jpg", ".jpeg", ".webp"]:
        return "IMAGE"

    if extension in [".ktx", ".ktx2"]:
        return "TEXTURE"

    return "OTHER"
        ## i want to do that so i can block some file types that are not supposed to be in the zip 

# check every URI and find its real path inside the extracted ZIP
def resolve_tileset_uris(uris, tileset_path, extract_dir):

    resolved_files = []
    findings = []

    # get the main folders
    tileset_directory = Path(tileset_path).resolve().parent  ## directory of the tileset.json
    extract_root = Path(extract_dir).resolve()  ## can be the root of the directory of the tileset , cause tilest can be in dr too

    for item in uris:  ## each item has uri and location of it 

        original_uri = item["uri"]  ## get the uri building1.glb
        uri = unquote(original_uri) ## maybe it has building%20.png , soit cleans it to building .png

        file_type = get_file_type(uri) ## get the extension using my func

        parsed_uri = urlparse(uri) ## checking if its local and not https://ofri.png

        # external uris are not downloaded or opened
        if parsed_uri.scheme or parsed_uri.netloc: ## scheme is the https maybe , netloc is the domain 

            findings.append({
                "uri": original_uri,
                "location": item["location"],
                "file_type": file_type,
                "status": "ALERT",
                "message": "External URI is not allowed"
            })
            continue

        if "\\" in uri:  ## its not within the zip , confusing , blocking path travelsel

            findings.append({
                "uri": original_uri,
                "location": item["location"],
                "file_type": file_type,
                "status": "ALERT",
                "message": "Backslashes in URI are not allowed"
            })
            continue

        relative_path = parsed_uri.path  ## models\ofri.glb , hacking\ofri.exe

        if not relative_path or relative_path.startswith("/"):  
            findings.append({
                "uri": original_uri,
                "location": item["location"],
                "file_type": file_type,
                "status": "ALERT",
                "message": "Empty or absolute URI path"
            })
            continue

        try:
            # build the path relative to tileset.json
            file_path = (tileset_directory / relative_path).resolve()  ## 3dtiles/hacking/ofri.exe , reslve handles ...

            # check that the file stays inside the extracted zip folder
            file_path.relative_to(extract_root)  ## 
            ##extract_root = Path("C:/temp/3dtiles")
            ##tileset_directory = Path("C:/temp/3dtiles")
            ##relative_path = "models/building.glb"
            ## returns path object , if not working returns the value error models/building.glb
        except (ValueError, OSError):
            findings.append({
                "uri": original_uri,
                "location": item["location"],
                "file_type": file_type,
                "status": "ALERT",
                "message": "URI points outside the ZIP directory"
            })
            continue

        # check if the referenced file exists
        if not file_path.is_file():  ## it can be relative but not really exist

            findings.append({
                "uri": original_uri,
                "location": item["location"],
                "file_type": file_type,
                "status": "ALERT",
                "message": "Referenced file does not exist inside the ZIP"
            })
            continue

        # Save the URI and its real path
        resolved_files.append({
            "uri": original_uri,
            "location": item["location"],
            "path": str(file_path),
            "file_type": file_type,
            "inside_zip": True
        })

    return resolved_files, findings


# main function that checks the tileset and all its uris
def validate_tileset_and_collect_uris(tileset_path, extract_dir):

    # first, check if tileset.json is valid
    validation = inspect_tileset(tileset_path) 

    if validation["status"] != "valid":
        return {
            "status": "invalid",
            "findings": validation["findings"],
            "files": [],
            "uri_findings": []
        }

    # collect all uris with my func 
    uris = collect_tileset_uris(validation["tileset_json"]) ## the tileset json , collecting its uris 

    ## resolved files - all the glb files that their uris are checkd and are good !!, uri findings - all the uris 
    ## uris findings is the findings from the func 
    resolved_files, uri_findings = resolve_tileset_uris(
        uris,  ## getting all the uris that are all the uris bad
        tileset_path,  ## to the tileset.json
        extract_dir ## to the zip 
    )

    return {
        "status": "valid", ## meaning only the structure is correct , not saying anything on the uris
        "findings": [],   ## no structure problems
        "files": resolved_files,   ## all the good that were checked
        "uri_findings": uri_findings  ## all the bad uri things
    }
