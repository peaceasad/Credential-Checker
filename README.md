# Credentials Checker

A lightweight Flask-based web tool for **authorized penetration testers** to bulk-validate a set of credentials (username/password) against a list of target IPs over **SMB**, **SSH**, and **FTP** — plus a quick ICMP **ping/reachability** check for the same list.

![status](https://img.shields.io/badge/status-active-brightgreen) ![python](https://img.shields.io/badge/python-3.9%2B-blue)

> ⚠️ **Authorized use only.** This tool performs live authentication attempts and host probing against the targets you supply. Only use it against systems you own or have explicit written authorization to test. Unauthorized access attempts are illegal in most jurisdictions.

## Features

- ✅ **Ping check** — fast reachability check using the OS's native `ping` binary (works cross-platform, no admin/root required)
- ✅ **SMB credential check** — validates username/password over SMB (default port 445)
- ✅ **SSH credential check** — validates username/password over SSH (default port 22)
- ✅ **FTP credential check** — validates username/password over FTP (default port 21)
- ✅ **Custom port override** — point any of the above checks at a non-default port
- ✅ **Pre-flight port reachability check** — distinguishes "host unreachable" from "authentication failed" so you're not misled by closed ports
- ✅ **Concurrent scanning** via a thread pool (configurable worker count)
- ✅ **Clean dark-mode UI** with live status badges (success / failed / unreachable / error)
- ✅ **CSV export** of results for reporting
- ✅ **Bulk IP input** — paste your whole target list, one IP per line

## Screenshot

_Add a screenshot of the UI here after your first run (e.g. `docs/screenshot.png`)._

## Requirements

- Python 3.9+
- pip

## Installation

```bash
git clone https://github.com/peaceasad/credentials-checker.git
cd credentials-checker
pip install -r requirements.txt
```

## Usage

```bash
python app.py
```

Then open `http://127.0.0.1:9000` (or `http://<host-ip>:9000` if running on a remote box) in your browser.

1. Paste your target IP list (one per line) into the **Target IPs** box.
2. Enter the credentials you want to validate (not required for ping-only checks).
3. Select which checks to run: Ping, SMB, SSH, FTP.
4. Optionally override the default port for a non-standard service port.
5. Click **Run** and review results in the live-updating table.
6. Export results to CSV for your report.

## Project structure

```
credentials-checker/
├── app.py                  # Flask backend + check logic
├── requirements.txt
├── templates/
│   └── index.html          # UI
└── README.md
```

## Security notes

- This app ships with **no built-in authentication** on its own web UI. If you expose it beyond `127.0.0.1`, put it behind a firewall rule (allow only your own IP) or a reverse proxy with basic auth.
- Passwords submitted through the form are not stored to disk by the app, but they do pass through your browser and local network in plaintext over HTTP by default — run this only on trusted/isolated networks, or add HTTPS via a reverse proxy (e.g., nginx + Let's Encrypt or a self-signed cert) if needed.
- This is a **development Flask server** (Werkzeug). Do not expose it directly to the internet; it is not hardened for production/adversarial traffic.

## Disclaimer

This project is intended strictly for use in **authorized security assessments**. The author(s) take no responsibility for misuse of this tool. Always obtain written authorization before testing any system you do not own.

## License

MIT — see [LICENSE](LICENSE).
