# Cipher Asset Inventory

Cipher Asset Inventory is a **desktop-based IT asset inventory and encrypted QR code system** designed for secure, offline-friendly environments.  
It combines encrypted asset storage, QR-based identification, and a streamlined GUI for day-to-day IT operations.

This project was built as a **portfolio-grade application** with a strong emphasis on security, usability, and real-world IT workflows.

---

## ✨ Key Features

### Cipher Asset Inventory App
- Desktop GUI built with **PyQt5**
- Asset inventory backed by **SQLite**
- Secure login and user management (salted password hashes)
- Encrypted-at-rest inventory database using **Fernet (AES)**
- Inventory decrypted **only while the app is running**
- CSV import/export (Send / Receive workflow)
- Optional cloud folder shortcuts (user-configured)
- Designed for offline or restricted-network environments

### Encrypted QR Asset Generator
- Standalone QR generator designed specifically for Cipher Asset Inventory
- Produces **encrypted QR payloads**
- Supports **13-field structured asset data**
- Generates print-ready QR codes sized for **1" × 2-1/8" DYMO labels**
- Uses the **same encryption key** as the inventory application
- Prevents plaintext asset data from ever appearing in QR codes

---

## 🔐 Security Design

Security is a core design goal of this project.

- Inventory database is encrypted at rest using **AES (Fernet)**
- Decryption occurs **only while the application is running**
- Encryption key is derived from an environment variable:
  - `ITINV_DB_KEY` (recommended)
- A compiled fallback key exists for **local testing only**
- QR codes contain **encrypted payloads**, not plaintext asset data
- Secrets, databases, and encryption artifacts are excluded via `.gitignore`

---

## 🔳 Encrypted QR Payload Format

The QR generator creates encrypted payloads using the following plaintext structure **before encryption**:

## License
MIT License © 2025 Dennis Shaull

