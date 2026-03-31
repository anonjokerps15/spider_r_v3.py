# Spider-R - Advanced Automated Web Vulnerability Scanner

**Developer:** @7md4n01 (Telegram: @h4mdan01)  
**License:** MIT

Spider-R is a comprehensive web security scanner with a modern dashboard, background task queue, real‑time updates, and brute‑force capabilities. It is designed for educational and authorized testing only.

## Features
- **Web crawling** and injection (SQLi, XSS, CMDi, SSTI, CSRF, SSRF)
- **Login brute‑force** with Kali Linux wordlists (supports form and HTTP Basic Auth)
- **Celery** background job queue
- **WebSocket** real‑time progress updates
- **User authentication** (Flask‑Login)
- **HTML reports**
- **NVD CVE integration** (optional)
- **Headless browser support** (optional)

## Requirements
- Python 3.8+
- Redis (for Celery)
- Kali Linux wordlists (optional, for brute‑force)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/spider-r.git
   cd spider-r
