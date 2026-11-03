import json
import struct  ## to read bin data
from glb_validator import inspect_glb 
from glb_security_scanner import scan_for_xss, scan_glb_security


# turn a location like "glb_json.nodes[0].name" into ["nodes", 0, "name"]
def location_to_steps(location):

    if location.startswith("glb_json."):
        location = location[len("glb_json."):]  ## remove the start

    steps = []

    for part in location.split("."):

        if "[" in part:  ## like "nodes[0]"
            name, rest = part.split("[", 1)
            if name:
                steps.append(name)
            for number in rest.split("["):
                steps.append(int(number.replace("]", "")))
        else:
            steps.append(part)

    return steps


# remove every value the scanner found
def remove_xss_findings(glb_json, findings):

    all_steps = []

    for finding in findings:
        steps = location_to_steps(finding["location"])
        if steps not in all_steps:  ## the same value can match more than one rule
            all_steps.append(steps)

    # remove from the end to the start, so list indexes don't move
    for steps in sorted(all_steps, reverse=True):

        parent = glb_json
        for step in steps[:-1]:  ## walk to the thing that holds the value
            parent = parent[step]

        last = steps[-1]
        if isinstance(parent, list):
            parent.pop(last)
        else:
            del parent[last]

    return glb_json


# Rebuild the GLB with the cleaned JSON and original binary data
def rebuild_glb(original_path, new_json, output_path):

    with open(original_path, "rb") as file:
        data = file.read()

    magic, version, old_length = struct.unpack_from("<4sII", data, 0)
    json_length, json_type = struct.unpack_from("<II", data, 12)

    # Keep everything after the JSON chunk (the BIN chunk)
    binary_data = data[20 + json_length:]

    json_bytes = json.dumps(new_json, ensure_ascii=False).encode("utf-8")

    # Add padding so the JSON length is divisible by 4
    padding = (4 - len(json_bytes) % 4) % 4
    json_bytes += b" " * padding

    json_header = struct.pack("<II", len(json_bytes), json_type)
    new_length = 12 + 8 + len(json_bytes) + len(binary_data)
    new_header = struct.pack("<4sII", magic, version, new_length)

    with open(output_path, "wb") as file:
        file.write(new_header)
        file.write(json_header)
        file.write(json_bytes)
        file.write(binary_data)


# main function: scan the glb, remove what the scanner found, check again
def sanitize_glb(filepath, output_path):

    result = inspect_glb(filepath)

    if result.get("status") != "STRUCTURALLY_VALID":
        return {"status": "REJECT", "error": result.get("error")}

    glb_json = result["glb_json"]
    findings = scan_for_xss(glb_json)

    if not findings:
        return {"status": "NO_FINDINGS", "path": filepath}

    try:
        remove_xss_findings(glb_json, findings)
    except (KeyError, IndexError, ValueError, TypeError):
        return {"status": "REJECT", "error": "Could not remove the findings"}

    rebuild_glb(filepath, glb_json, output_path)

    # check the new file again: structure + security
    check = scan_glb_security(output_path)

    if check["structure_status"] != "STRUCTURALLY_VALID":
        return {"status": "REJECT", "error": "GLB is broken after cleaning"}

    if check["security_findings"]:
        return {"status": "REJECT", "error": "Findings are left after cleaning"}

    removed = []
    for finding in findings:
        if finding["location"] not in removed:
            removed.append(finding["location"])

    return {"status": "SANITIZED", "path": output_path, "removed": removed}
