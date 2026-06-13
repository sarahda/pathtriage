#!/bin/bash
# PathTriage Scenario 02 - deliberately SSRF-vulnerable image-fetcher service.
# This is intentionally insecure (no URL validation) for lab use only.
set -euxo pipefail

dnf install -y python3 python3-pip
pip3 install flask requests

mkdir -p /opt/app
cat > /opt/app/app.py <<'PYEOF'
from flask import Flask, request
import requests

app = Flask(__name__)


@app.route("/")
def index():
    return (
        "Image preview service.\n"
        "Usage: /fetch?url=https://example.com/image.png\n"
    )


@app.route("/fetch")
def fetch():
    # VULNERABLE BY DESIGN: no allow-list, no scheme/host validation.
    # Server fetches any URL the client supplies -> classic SSRF.
    url = request.args.get("url")
    if not url:
        return "missing url parameter", 400
    try:
        resp = requests.get(url, timeout=3)
        return resp.text
    except Exception as exc:  # noqa: BLE001 - lab code
        return f"fetch error: {exc}", 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
PYEOF

cat > /etc/systemd/system/pathtriage-app.service <<'SVCEOF'
[Unit]
Description=PathTriage vulnerable image-fetcher
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/app/app.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable --now pathtriage-app.service
