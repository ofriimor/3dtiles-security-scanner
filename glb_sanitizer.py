import json
import struct  ## to read bin data
from glb_validator import inspect_glb 
from glb_security_scanner import scan_for_xss, scan_glb_security


# turn a location like "glb_json.nodes[0].name" into ["nodes", 0, "name"]
def location_to_steps(location):

    if location.startswith("glb_json."): ## the root
        location = location[len("glb_json."):]  ## remove the start, and start with node[]name

    steps = [] ## empty list

    for part in location.split("."):  ##nodes0 , name

        if "[" in part:  ## like "nodes[0]" 
            name, rest = part.split("[", 1) ## nodes, 0 matrix[1][0] -error cause it excepts one [
            ## name before the [ , rest after ]
            if name: ## not empty
                steps.append(name)
            for number in rest.split("["): ## for times when its :matrix[1][0] , when theres nested list
                ## when theres no opening bracket, only one index, it will return only the string rest
                steps.append(int(number.replace("]", "")))
        else:
            steps.append(part)

    return steps


# remove every value the scanner found
def remove_xss_findings(glb_json, findings):
    ## each path is saved only once,
    ## even when two rules found the same value
    all_steps = []  # empty list
    for finding in findings:  ## each finding is a dict that contains the "location" key
        steps = location_to_steps(finding["location"])  ## "glb_json.nodes[0].name" -> ["nodes", 0, "name"]
        if steps not in all_steps:  ## the same value can match more than one rule
            ## without this check we would delete the same key twice -> KeyError
            all_steps.append(steps)
    # remove from the end to the start, so list indexes don't move
    for steps in sorted(all_steps, reverse=True):
        ## without reverse: deleting tags[0] first shifts tags[2] to tags[1],
        ## so we get an IndexError or delete the wrong item
        parent = glb_json  ## start at the root of the json 
        for step in steps[:-1]:  ## all the steps except the last one
            parent = parent[step]  # go one level deeper (i like to think about that like opening a folder)
        ## now parent is the list/dict that holds the bad value
        last = steps[-1]  # the key or index of the bad value itself
        if isinstance(parent, list):
            parent.pop(last)  # list: remove by index, pop is a py func for deleting object in a list
        else:
            del parent[last]  # dict: remove the key and its value

    return glb_json  ## same object, changed in place

# rebuild the glb with the cleaned json and original binary data
def rebuild_glb(original_path, new_json, output_path):

    with open(original_path, "rb") as file: #3 open the original path of the glb and read it as binary
        data = file.read() ## and now in data reads it and put it in a bytes object

    magic, version, old_length = struct.unpack_from("<4sII", data, 0) 
    # <4sII : is format language , of the struct moudule in python called format string , I is int
    ## start reading from zero
    #(i added old length cause tuple needs 3 values and i needed to add 3 parametrs)
    # it returns a tuple 
    # takes the bytes and turns them into python values by some patttern
    # < - is for the little endian method from earlier , where the first byte is the most important - 4 bytes
    # 4s is the magic bytes , the version is I , and the oldlength is I - 12 bytes in total

    ## some fun info : little endian and big indian both present the same num 
    ## like a number that takes 4 bytes needs to be saved in some order
    ## why little endian ? first its written in : https://registry.khronos.org/glTF/specs/2.0/glTF-2.0.html#buffers-and-buffer-views-overview


    json_length, json_type = struct.unpack_from("<II", data, 12) ## 8 BYTES

    # keep everything after the json chunk (the bin chunk)
    binary_data = data[20 + json_length:]

    json_bytes = json.dumps(new_json, ensure_ascii=False).encode("utf-8") ## convert dict to text , from text to bytes
    ## א  - u65d0 ascii is only english , 

    # add padding so the json length is divisible by 4
    # why ? casue the glb format docs requiers , when its 61 bytes we need to complete it to 64
    padding = (4 - len(json_bytes) % 4) % 4 ## 61 % 4 is 1, hasheerit for it do be dividable by 4
    ## then 4 - 3 = 1 , 3 % 4   - so the result is 3 , i need to padd it by 3
    json_bytes += b" " * padding # so ill multiply the space by 3 to add 3 bytes to the json_bytes

    json_header = struct.pack("<II", len(json_bytes), json_type)  # length of the new json_bytes after padding , and the json type
    new_length = 12 + 8 + len(json_bytes) + len(binary_data) ## the header + the json type+length + json bytes + binary data with his header
    new_header = struct.pack("<4sII", magic, version, new_length)  ## now its good , just the length is corrected
    ## doing it so if when i remove and sanatized things , i need to keep the padding % 4 = 0

    with open(output_path, "wb") as file: ## now write binary
        file.write(new_header) ## add each piece
        file.write(json_header)
        file.write(json_bytes)
        file.write(binary_data)


# main function: scan the glb, remove what the scanner found, check again
def sanitize_glb(filepath, output_path): ## path to the glb we want to sanatize, the path the glb will be save in after the sanatization

    result = inspect_glb(filepath) ## validating the structure of the glb, returning result dictionary 
    ## with the fields status and glb json ill use

    if result.get("status") != "STRUCTURALLY_VALID": ## not sanatizing if not valid structure
        return {"status": "REJECT", "error": result.get("error")}

    glb_json = result["glb_json"]  ## getting the actual json
    findings = scan_for_xss(glb_json)   ## getting the findings dict of the xss findings in the glb

    if not findings:  ## empty
        return {"status": "NO_FINDINGS", "path": filepath}

    try: ## not empty , needs to be sanatized
        remove_xss_findings(glb_json, findings)
    except (KeyError, IndexError, ValueError, TypeError): ##  for one of these reasons , throw error 
        return {"status": "REJECT", "error": "could not remove the findings"}

    rebuild_glb(filepath, glb_json, output_path) ## now it successfuly removed the xss if there were any

    # check the new file again: structure + security
    check = scan_glb_security(output_path) ## check dict with the outputpath parameter 

    if check["structure_status"] != "STRUCTURALLY_VALID": ## getting the field from the scanglb result
        return {"status": "REJECT", "error": "glb is broken after cleaning"}

    if check["security_findings"]: ## even after cleaning , not empty secuirty finding list
        return {"status": "REJECT", "error": "there are suspicious findings left after cleaning"}

    ## i figured it will be clever to make a list of all the locations in which i found suspicious values 
    ## in the scan for xss 
    ## and findings can contain more than one location , cause i identified in my glb more than one sus thing 
    ## so i need to make sure there are no duplicates in my removed list before i insert into it 
    removed = [] #
    for finding in findings: 
        if finding["location"] not in removed:  ## making sure 
            removed.append(finding["location"]) ## inserting 

    return {"status": "SANITIZED", "path": output_path, "removed": removed} # sanatized, the path to the glb after the sanatize, and the removed locations   
