# Password Manager Tool (GUI)

This is a lightweight, secure, and local password manager built with Python using `tkinter` and `cryptography`.

## Features
- AES-256 encryption with master password
- Offline storage (`vault.bin`)
- Add, delete, search accounts
- Password hidden by default; shown only per selection
- Scrollable GUI interface

## Setup

```bash
# Optional: Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the app
python gui_password_manager.py
