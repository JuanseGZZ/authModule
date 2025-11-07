#!/usr/bin/env python3
"""
main.py
Thin entrypoint that imports the module `auth` and mounts its paths.
Run with:  uvicorn main:app --host 0.0.0.0 --port 8000
"""
import os
from auth import build_app

app = build_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=False)
