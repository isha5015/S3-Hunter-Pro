# 🎯 S3-Hunter Elite 3.0: The Offensive S3 Framework

The definitive AWS S3 security assessment platform for professional Red Teams and Penetration Testers.

S3-Hunter Elite transforms the tedious process of S3 bucket discovery and exploitation into a high-speed, automated, and visually immersive experience. Built for scale, it handles thousands of concurrent probes, performs deep recursive object mapping, and identifies critical secrets using an advanced RegEx engine — all accessible via a cyberpunk-inspired terminal dashboard.

---

## ⚡ Key Features (Elite Edition)

* 🚀 High-speed multi-threaded S3 bucket discovery
* 🔍 Deep object enumeration & recursive mapping
* 🧠 25+ advanced regex-based secret detection engine
* 🎯 Subdomain takeover detection (NoSuchBucket analysis)
* 🌐 WAF/CDN detection (CloudFront, Cloudflare, Akamai, Fastly)
* 📡 Real-time terminal log streaming inside UI
* 📊 Interactive radar visualization for scan activity
* 🧱 Modular FastAPI backend architecture

---

## 🚀 Quick Start (One-Click Mode)

```bash
chmod +x start.sh
./start.sh
```

### What this does:

* Creates Python virtual environment
* Installs backend dependencies
* Builds frontend automatically (if needed)
* Launches full platform at:

👉 http://localhost:8000

---

## ⚙️ Manual Setup (Recommended for Developers)

### 🔹 1. Backend Setup

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

👉 Backend runs on:

```
http://localhost:8000
```

---

### 🔹 2. Frontend Setup (Development Mode)

```bash
cd frontend
npm install
npm run dev
```

👉 Frontend runs on:

```
http://localhost:5173
```

---

### 🔹 3. Frontend Production Build (Optional)

```bash
npm run build
```

👉 This creates:

```
frontend/dist/
```

If backend is configured to serve static files, it will use this build.

---

## 🧠 Execution Flow (Important)

You have **2 ways to run the project:**

### ✅ Option 1 (Easy Mode)

```bash
./start.sh
```

### ✅ Option 2 (Manual Mode)

* Run backend (terminal 1)
* Run frontend (terminal 2)

👉 No need to run `start.sh` in this case

---

## 🛡️ Usage Strategy

**Recon Phase:**
Use dashboard payloads with prefixes (dev, test, staging) and suffixes (backup, logs, data)

**Monitoring Phase:**
Track responses via live terminal logs and radar visualization

**Exploitation Phase:**

* Identify public buckets
* Extract sensitive data
* Detect takeover vectors

**Deep Dive:**
Use Bucket Explorer to enumerate objects and analyze exposed files

---

## ⚖️ Legal Disclaimer

This tool is intended strictly for **authorized security testing and research purposes only**.

Unauthorized use against systems without explicit permission is illegal.
The developers assume no responsibility for misuse or damage.

---

## 💚 Developed for the Security Community.

Built for bug bounty hunters, red teamers, and offensive security researchers.
