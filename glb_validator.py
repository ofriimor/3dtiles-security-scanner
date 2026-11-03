
import os
import json


def inspect_glb(filepath: str):  ## assuming ill get a string, not forcing it tho

    try:
        with open(filepath, "rb") as file: ## the rb stands for read as binary

            header = file.read(12)

            if len(header) < 12:  ## glb file supposed to have at least 12 bytes!
                return {
                    "filepath": filepath,
                    "is_glb": False,
                    "status": "REJECT",
                    "error": "File is too small to contain a GLB header"
                }

            magic = header[:4]  ## reading the file signature bytes
            version_bytes = header[4:8] ## reading the glb version in bytes
            bytes_length = header[8:12] ## reading the declared bytes length

            if magic != b"glTF":
                return {
                    "filepath": filepath,
                    "is_glb": False,
                    "status": "REJECT",
                    "error": "Invalid GLB magic"
                }

            actual_length = os.path.getsize(filepath)
            declared_length = int.from_bytes(bytes_length, "little")
            version = int.from_bytes(version_bytes, "little")

            if version != 2:
                return {
                    "filepath": filepath,
                    "is_glb": True,
                    "status": "UNSUPPORTED",
                    "error": f"Unsupported GLB version: {version}"
                }

            if declared_length != actual_length:
                return {
                    "filepath": filepath,
                    "is_glb": False,
                    "status": "REJECT",
                    "error": "Declared file length does not match actual file length"
                }

            if declared_length < 20:  ## 12 for header , 8 for json header by the docs
                return {
                    "filepath": filepath,
                    "is_glb": False,
                    "status": "REJECT",
                    "error": "GLB file is too small to contain a JSON chunk header"
                }

            # read all the glb chunks
            chunks = []
            json_chunk = None
            bin_chunk_length = None

            while file.tell() < declared_length:  ## file tell returns the location in the file 

                chunk_header = file.read(8) ## header of the chunk 

                if len(chunk_header) != 8:
                    return {
                        "filepath": filepath,
                        "is_glb": False,
                        "status": "REJECT",
                        "error": "Incomplete chunk header"
                    }

                chunk_length = int.from_bytes(chunk_header[:4], "little")  ## for the chunk length
                chunk_type = chunk_header[4:8]

                # every glb chunk must have a length divisible by 4
                if chunk_length % 4 != 0:
                    return {
                        "filepath": filepath,
                        "is_glb": False,
                        "status": "REJECT",
                        "error": "Chunk length must be divisible by 4"
                    }

                # Check that the chunk does not exceed the file length
                if chunk_length > declared_length - file.tell():
                    return {
                        "filepath": filepath,
                        "is_glb": False,
                        "status": "REJECT",
                        "error": "Chunk length exceeds available file data"
                    }

                chunk_data = file.read(chunk_length) ## chunk length = chunk data , without the header

                if len(chunk_data) != chunk_length:  ## just making sure , maybe its corrupted
                    return {
                        "filepath": filepath,
                        "is_glb": False,
                        "status": "REJECT",
                        "error": "Incomplete chunk data"
                    }

                chunks.append({  ## inserting to the chunks list these 2 dict
                    "type": chunk_type,
                    "length": chunk_length
                })

                if len(chunks) == 1:

                    if chunk_type != b"JSON":
                        return {
                            "filepath": filepath,
                            "is_glb": False,
                            "status": "REJECT",
                            "error": "First GLB chunk must be JSON"
                        }

                    json_chunk = chunk_data  ## saving it when its json , the data itself in bytes

                elif chunk_type == b"BIN\x00":

                    if bin_chunk_length is not None:  # already read the bin chunk 
                        return {
                            "filepath": filepath,
                            "is_glb": False,
                            "status": "REJECT",
                            "error": "More than one BIN chunk found"
                        }

                    bin_chunk_length = chunk_length  ## saving the bin length 

            if json_chunk is None:
                return {
                    "filepath": filepath,
                    "is_glb": False,
                    "status": "REJECT",
                    "error": "Missing JSON chunk"
                }

            try:
                json_text = json_chunk.decode("utf-8") ## used try to catch the error while the program is running
                glb_json = json.loads(json_text)

            except (UnicodeDecodeError, json.JSONDecodeError) as e: ## catch the error in e
                return {
                    "filepath": filepath,
                    "is_glb": False,
                    "status": "REJECT",
                    "error": f"Invalid JSON chunk: {str(e)}"
                }

            if not isinstance(glb_json, dict): ## built in func checks the var type
                return {
                    "filepath": filepath,
                    "is_glb": False,
                    "status": "REJECT",
                    "error": "JSON root must be an object"
                }

            if "asset" not in glb_json: ## asset is a must field in the gltf file
                return {
                    "filepath": filepath,
                    "is_glb": False,
                    "status": "REJECT",
                    "error": "Missing required asset object"
                }

            if not isinstance(glb_json["asset"], dict):
                return {
                    "filepath": filepath,
                    "is_glb": False,
                    "status": "REJECT",
                    "error": "Asset must be an object"
                }

            if "version" not in glb_json["asset"]:
                return {
                    "filepath": filepath,
                    "is_glb": False,
                    "status": "REJECT",
                    "error": "Version must be specified in the asset section"
                }

            if (
                not isinstance(glb_json["asset"]["version"], str)
                or glb_json["asset"]["version"] != "2.0"
            ):
                return {
                    "filepath": filepath,
                    "is_glb": False,
                    "status": "REJECT",
                    "error": "Unsupported glTF asset version"
                }

            buffers = glb_json.get("buffers", []) ## if not finding the buffers, return []

            if not isinstance(buffers, list):
                return {
                    "filepath": filepath,
                    "is_glb": False,
                    "status": "REJECT",
                    "error": "Buffers must be a list"
                }

            for index, buffer in enumerate(buffers):

                if not isinstance(buffer, dict):
                    return {
                        "filepath": filepath,
                        "is_glb": False,
                        "status": "REJECT",
                        "error": "Each buffer must be an object"
                    }

                if "byteLength" not in buffer:
                    return {
                        "filepath": filepath,
                        "is_glb": False,
                        "status": "REJECT",
                        "error": "Missing byteLength in buffer"
                    }

                if (
                    not isinstance(buffer["byteLength"], int)
                    or buffer["byteLength"] < 0
                ):
                    return {
                        "filepath": filepath,
                        "is_glb": False,
                        "status": "REJECT",
                        "error": "Not valid byteLength in buffer"
                    }

                # The first buffer in a glb is stored inside the bin chunk
                if index == 0:

                    if "uri" in buffer:
                        return {
                            "filepath": filepath,
                            "is_glb": False,
                            "status": "REJECT",
                            "error": "The first GLB buffer must not have an external URI"
                        }

                    buffer_byte_length = buffer["byteLength"]

                    if bin_chunk_length is None and buffer_byte_length > 0: ## bin is optional , the file cn be gltf
                        return {
                            "filepath": filepath,
                            "is_glb": False,
                            "status": "REJECT",
                            "error": "Missing BIN chunk for the internal buffer"
                        }

                    if bin_chunk_length is not None:

                        if not (
                            0 <= bin_chunk_length - buffer_byte_length <= 3
                        ):
                            return {
                                "filepath": filepath,
                                "is_glb": False,
                                "status": "REJECT",
                                "error": "BIN chunk length does not match the declared buffer length"
                            }

            buffer_views = glb_json.get("bufferViews", [])

            if not isinstance(buffer_views, list):
                return {
                    "filepath": filepath,
                    "is_glb": False,
                    "status": "REJECT",
                    "error": "bufferViews must be a list"
                }

            for buffer_view in buffer_views:

                if not isinstance(buffer_view, dict):
                    return {
                        "filepath": filepath,
                        "is_glb": False,
                        "status": "REJECT",
                        "error": "Each bufferView must be an object"
                    }

                buffer_index = buffer_view.get("buffer")
                byte_offset = buffer_view.get("byteOffset", 0)
                byte_length = buffer_view.get("byteLength")

                if (
                    not isinstance(buffer_index, int)
                    or buffer_index < 0
                    or buffer_index >= len(buffers)  ## exceeding the mount of buffers in the list
                ):
                    return {
                        "filepath": filepath,
                        "is_glb": False,
                        "status": "REJECT",
                        "error": "Invalid bufferView buffer index"
                    }

                if (
                    not isinstance(byte_offset, int)
                    or byte_offset < 0
                ):
                    return {
                        "filepath": filepath,
                        "is_glb": False,
                        "status": "REJECT",
                        "error": "Invalid bufferView byteOffset"
                    }

                if (
                    not isinstance(byte_length, int)
                    or byte_length < 0
                ):
                    return {
                        "filepath": filepath,
                        "is_glb": False,
                        "status": "REJECT",
                        "error": "Invalid bufferView byteLength"
                    }

                # find the buffer that this bufferView points to
                referenced_buffer = buffers[buffer_index]   ## buffer dict in the list

                if byte_offset + byte_length > referenced_buffer["byteLength"]:  ## from the bufferview :byte_offset + byte_length
                    return {
                        "filepath": filepath,
                        "is_glb": False,
                        "status": "REJECT",
                        "error": "bufferView exceeds buffer boundaries"
                    }

            return {
                "filepath": filepath,
                "is_glb": True,
                "status": "STRUCTURALLY_VALID",
                "glb_json": glb_json,
                "message": "GLB passed all current validation checks"
            }

    except FileNotFoundError: ## didnt even meange to open it , not found 
        return {
            "filepath": filepath,
            "status": "REJECT",
            "error": "File not found"
        }

    except PermissionError: ## exits but no permission
        return {
            "filepath": filepath,
            "status": "REJECT",
            "error": "Permission denied"
        }
