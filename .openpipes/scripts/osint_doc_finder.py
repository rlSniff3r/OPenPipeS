#!/usr/bin/env python3
import os, sys, json, subprocess

target = sys.argv[1]
outdir = sys.argv[2]

os.makedirs(outdir, exist_ok=True)

extensions = ('.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt')
results = []

for root, _, files in os.walk("."):
    for f in files:
        if f.lower().endswith(extensions):
            path = os.path.join(root, f)
            meta = subprocess.getoutput(f"exiftool -json '{path}'")
            results.append(json.loads(meta)[0])

with open(f"{outdir}/metadata.json", "w") as f:
    json.dump(results, f, indent=2)

print(f"[✔] Metadados coletados em {outdir}/metadata.json")
