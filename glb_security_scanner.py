import re   ## working with regex to search the patterns
from glb_validator import inspect_glb ## making sure its validated


# Scan the GLB JSON for suspicious XSS patterns
def scan_for_xss(glb_json):

    suspicious_patterns = {
        "SCRIPT_TAG": r"<\s*script\b", 
        ## r - raw string, finding < in the string , \s for tab or space , * - 0 times or more, finding the word script
        ## an the \b is for the end of the word , so i will not find <scriptttt>
        "HTML_EVENT_HANDLER": r"\bon[a-z]+\s*=", ## "on" has to be in it , then lowercase letter in english like onload
        ## + : at least one time , again the tab can be zero times or more, and find the sign "="
        ## like onclick()= onload()= that runs js code
        "JAVASCRIPT_URI": r"javascript\s*:" ## trying to find uris that use javascript funcs 
        # <a href="javascript:alert('xss things')">click</a>
    }

    findings = []  ## empty list 

    # check every value inside the json
    def check_value(value, location):  

        if isinstance(value, dict): 

            for key, nested_value in value.items(): 

                new_location = f"{location}.{key}"

                check_value(nested_value, new_location)

        elif isinstance(value, list):

            for index, nested_value in enumerate(value):

                new_location = f"{location}[{index}]"

                check_value(nested_value, new_location)

        elif isinstance(value, str):

            for rule, pattern in suspicious_patterns.items():

                if re.search(pattern, value, re.IGNORECASE):

                    findings.append({
                        "category": "POTENTIAL_XSS",
                        "rule": rule,
                        "location": location,
                        "value_preview": value[:100],
                        "message": "suspicious xss pattern found in glb json"
                    })

    check_value(glb_json, "glb_json")  ## python somhow retruns to where we were before a value wasnt a match
    ## without us telling him where to continue reading, the stop of the running is when all the there are not more recursive checks


    return findings


# the scan main func for each glb
def scan_glb_security(filepath):

    # validate the glb structure
    validation_result = inspect_glb(filepath)

    if validation_result.get("status") != "STRUCTURALLY_VALID": ## wasnt valid in the validatoor

        return {
            "structure_status": validation_result.get("status"),
            "security_status": "NOT_SCANNED",
            "structure_error": validation_result.get("error"),
            "security_findings": []
        }

    # gets the json from the validated GLB, when its valid
    glb_json = validation_result["glb_json"]

    xss_findings = scan_for_xss(glb_json)

    all_findings = []  
    all_findings.extend(xss_findings)

    if all_findings:  ## not empty 
        security_status = "REVIEW"
    else:
        security_status = "NO_FINDINGS"

    return {
        "structure_status": "STRUCTURALLY_VALID",
        "security_status": security_status,
        "security_findings": all_findings
    }