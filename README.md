# S3-Hunter Elite 3.0

S3-Hunter Elite 3.0 is a high-performance AWS S3 security framework designed for red teamers and bug bounty hunters. It combines real-time scanning, advanced secret detection, and subdomain takeover analysis into a single monolithic platform.

## Features

- Multi-threaded S3 bucket scanning
- 25+ advanced regex-based secret detection (AWS keys, RSA, tokens)
- Subdomain takeover detection
- Real-time terminal logging UI
- FastAPI backend with React frontend
- One-click execution using start.sh
- WAF/CDN detection (CloudFront, Cloudflare)

## Setup

```bash
git clone https://github.com/yourusername/S3-Hunter-Pro.git
cd S3-Hunter-Pro
chmod +x start.sh
./start.sh
