import os
outpath = os.path.join("C:", os.sep, "Users", "techn", "Documents", "bof_template", "extract_tgs_hash.py")
with open(outpath, "w") as out:
    out.write(open(os.path.join("C:", os.sep, "Users", "techn", "Documents", "bof_template", "script_parts.py")).read())
print("Generated: " + outpath)
