#!/usr/bin/env python3
import json, sys

target = sys.argv[1]
outfile = sys.argv[2]

people = [
    {
        "name": "John Doe",
        "email": "john.doe@example.com",
        "role": "CTO",
        "photo": "https://example.com/john.jpg",
        "github": "https://github.com/johndoe",
        "linkedin": "https://linkedin.com/in/johndoe",
        "source": "github"
    }
]

json.dump({"people": people}, open(outfile, "w"), indent=2)
print(f"[INFO] Coleta simulada salva em {outfile}")
