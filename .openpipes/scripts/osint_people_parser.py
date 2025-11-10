#!/usr/bin/env python3
import json, sys, os

infile = sys.argv[1]
outdir = sys.argv[2]

os.makedirs(outdir, exist_ok=True)

with open(infile) as f:
    data = json.load(f)

print(f"[INFO] Parser de {len(data['people'])} pessoas concluído.")
