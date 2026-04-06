#!/bin/bash

# --- S3-Hunter Pro: One-Click Launcher ---
# Automated Bootstrap Script for Linux/macOS

echo "------------------------------------------------"
echo "   🚀 S3-Hunter Pro: Initializing Elite Engine"
echo "------------------------------------------------"

# 1. Check for Python
if ! command -v python3 &> /dev/null; then
    echo "[!] Error: python3 is not installed. Please install it first."
    exit 1
fi

# 2. Setup Virtual Environment
if [ ! -d "venv" ]; then
    echo "[*] Creating isolated Python environment (venv)..."
    python3 -m venv venv
fi

source venv/bin/activate

# 3. Install Requirements
echo "[*] Ensuring dependencies are up-to-date..."
pip install --upgrade pip
pip install -r backend/requirements.txt

# 4. Check for Frontend Build
if [ ! -d "frontend/dist" ]; then
    echo "[!] Warning: Frontend 'dist' not found. Dashboard may not load."
    echo "[*] To fix this, run: cd frontend && npm install && npm run build"
fi

# 5. Launch Monolith
echo "------------------------------------------------"
echo "   📡 Server Starting on http://localhost:8000"
echo "   Dashboard: http://localhost:8000"
echo "------------------------------------------------"

cd backend
python3 main.py
