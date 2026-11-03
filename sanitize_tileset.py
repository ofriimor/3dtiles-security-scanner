import json
from tileset_validator import validate_tileset_and_collect_uris


# turn "root.children[0].content" into ["root", "children", 0, "content"]
def location_to_steps(location):

    steps = []

    for part in location.split("."):
        if "[" in part:  ## like "children[0]"
            name, number = part.split("[")
            steps.append(name)
            steps.append(int(number[:-1]))  ## remove the "]"
        else:
            steps.append(part)

    return steps


# write the cleaned json as a new tileset file
def rebuild_tileset(tileset_json, output_path):

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(tileset_json, file, indent=2)


# remove bad uris and save a new tileset.json, the tiles themselves stay
# output_path must be in the same folder as tileset_path, so the uris still work
def sanitize_tileset(tileset_path, extract_dir, output_path):

    result = validate_tileset_and_collect_uris(tileset_path, extract_dir)  # dict returnd from the validtor

    if result["status"] != "valid":  ## structure tilset problem
        return {"status": "REJECT", "findings": result["findings"]}  ## not mulban

    if not result["uri_findings"]:  ## structure valid , no harm on the uris 
        return {"status": "NO_FINDINGS", "path": tileset_path, "files": result["files"]}

    with open(tileset_path, "r", encoding="utf-8") as file:
        tileset_json = json.load(file)   ## as json 

    all_steps = []
    for finding in result["uri_findings"]: ## for each bad uri in the validator 
        all_steps.append(location_to_steps(finding["location"]))  ## returns list ["root", "chilldern", "0", "content"]
        ## uri findings contains a field in the list called location , the location is root.children[0].content, location to steps makes it list 
        ## so i can delette it 

    # remove from the end to the start, so list indexes don't move
    for steps in sorted(all_steps, reverse=True):  ## reverse true - start from the end 
            ### if you need to delete children[0] + children[2] , you need to not corrupt the structure of the list objects
            ## if i delete the 0 , the 2 will become 1 , so i delete from the end , so the indexes not move
        parent = tileset_json
        for step in steps[:-1]:  ## -1 is the last root.children[0].content
            parent = parent[step]   ## parent is the children[0] value

        if isinstance(parent, list): 
            parent.pop(steps[-1])  
        else:
            del parent[steps[-1]] ## deleting the last dict in the children 

    rebuild_tileset(tileset_json, output_path) ## rebuilds the tileset after deleting the malicus uris

    # check the new file again, with the original func, so there are no problems 
    check = validate_tileset_and_collect_uris(output_path, extract_dir)

    if check["status"] != "valid" or check["uri_findings"]:  ## the strcutre invalid or the uri findings 
        return {"status": "REJECT", "findings": ["problems are left after cleaning"]}

    return {"status": "SANITIZED", "path": output_path, "removed": result["uri_findings"], "files": check["files"]}
