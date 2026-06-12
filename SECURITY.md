# Security Policy

## ⚠️ Important Warning

SENTINEL PRO is an **educational security framework** designed for a university OS course. It contains working attack simulation scripts (`tests/`) that generate real OS events.

## Safe Usage

- Always run in `--dry-run` mode first: `python app.py --dry-run`
- **Never run attack scripts on machines you do not own**
- The auth/registry attack scripts require Administrator privileges and modify real Windows state — review them before running
- The quarantine/ directory may contain files moved by the enforcement engine

## Responsible Use

This project is intended for:
- Educational demonstration of OS concepts
- Testing on your own isolated Windows machine
- Understanding endpoint security architecture

Do not use the attack simulation scripts in production environments or against any system without explicit authorisation.
