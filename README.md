# Network Discovery Dashboard

A defensive local-network discovery dashboard using Python's standard library.

## Features
- Private IPv4 CIDR input
- Maximum 256 addresses per scan
- Checks common TCP ports: 22, 53, 80, 443, 445, 3389, 8080
- Reverse DNS when available
- Browser dashboard with IP, hostname and service results

## Run

```bash
python3 scanner.py
```

Open `http://127.0.0.1:8000`.

Example network: `192.168.1.0/24`

## Authorized use

Use only on networks and systems you own or have explicit permission to assess. This project does not scan cellular infrastructure or arbitrary public networks.

## GitHub

This is a Python application, so GitHub Pages is not used to run the scanner. Upload the files to GitHub as a code repository and run it on your own computer or server.

## Files
- `scanner.py`
- `requirements.txt`
- `README.md`
- `.gitignore`
