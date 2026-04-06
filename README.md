# 🎯 S3-Hunter Elite 3.0: The Offensive S3 Framework

> **The definitive AWS S3 security assessment platform for professional Red Teams and Penetration Testers.**

S3-Hunter Elite transforms the tedious process of S3 bucket discovery and exploitation into a high-speed, automated, and visually immersive experience. Built for scale, it handles thousands of concurrent probes, performs deep recursive object mapping, and identifies critical secrets using an advanced RegEx engine—all accessible via a stunning, cyberpunk-inspired terminal dashboard.

---

## ⚡ Key Upgrades (Elite Edition)

- **One-Click Deployment:** No more managing NPM, Node.js, or multiple terminals. Our new Monolith Architecture serves the entire frontend directly from the Python backend on a single port (`8000`).
- **Real-Time Log Stream:** A live, raw system terminal built into the UI provides internal engine logs, HTTP status codes, and instant vulnerability alerts as they happen.
- **Subdomain Takeover Detection:** Automatically identifies `NoSuchBucket` responses hidden behind `AmazonS3` headers—flagging potential high-severity CNAME takeover vectors.
- **WAF & CDN Revelation:** Built-in logic to detect and transparently report targets shielded by AWS CloudFront, Cloudflare, Akamai, or Fastly.
- **Secrets Exfiltration Engine:** Over 25+ aggressive regex rules designed to hunt down RSA keys, Stripe/AWS secrets, MongoDB URIs, and JWTs deep within public objects.
- **Animated Tactical Radar:** A live-sync CSS radar sweep that visually represents active cloud-hunting sequences in real-time.

---

## 🚀 "One-Click" Quick Start

We’ve removed all the friction. To launch the full platform (Frontend + Backend + Database) on Linux or macOS, simply run:

```bash
chmod +x start.sh
./start.sh
```

**What this does:** 
1. Initializes an isolated Python environment (`venv`).
2. Installs all required security libraries.
3. Automatically launches the platform at **http://localhost:8000**.

---

## ⚙️ Manual Installation (Developers)

If you prefer to run the components manually for development:

### 1. Backend (FastAPI Monolith)
The backend is responsible for scanning, database management, and serving the static frontend files.
```bash
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

### 2. Frontend (Optional Dev Mode)
If you wish to modify the UI, you can run the Vite dev server separately:
```bash
cd frontend
npm install
npm run dev
```

---

## 🛡️ Usage Strategy

1. **Recon Phase:** Use the **Dashboard** to input your target payloads. Configure prefixes (e.g., `dev`, `staging`) and suffixes (`backup`, `data`) to maximize discovery hits.
2. **Monitoring Phase:** Watch the **Live Hacker Terminal** and **Radar Sweep** to monitor engine health and real-time HTTP response patterns.
3. **Exploitation Phase:** Discovered buckets appear as **Server Blades** in your feed. Green lights indicate "Racked" assets; red pulses indicate "Vulnerable" targets.
4. **Deep Dive:** Jump into the **Bucket Explorer** to traverse file systems, preview sensitive documents, or use the **CLI Sync** feature for massive data exfiltration.

---

## ⚖️ Ethical Disclosure
**S3-Hunter Elite** is an offensive security tool designed strictly for authorized penetration testing, security research, and infrastructure auditing. Use of this tool against targets without prior written consent is illegal. The developers assume no responsibility for misuse or damage caused by this software.

---

**Developed with 💚 for the Global Security Community.**
