# qr_asset_13field_generator_app.py
#
# Cipher Asset QR Code Generator
# - 13-field payload
# - Encrypted using cryptography/Fernet
# - Optional visual watermark on generated labels
#
# Plaintext payload format (before encryption):
#   DeviceType$Name$Make$Department$Serial$OS$WindowsVersion$
#   Model$RAM$Storage$Processor$Location$Status
#
# QR contents:
#   ENC1:<Fernet-encrypted-token>
#
# Inventory desktop application:
#   - Detects ENC1-prefixed QR payloads
#   - Decrypts using the same Fernet key
#     (recommended via ITINV_DB_KEY environment variable)
#   - Splits decrypted payload on "$" into 13 structured fields
#   - NOTE: Encryption keys and secrets are not included in this repository.
#
# QR PNG label output:
#   - Sized for 1" × 2-1/8" label stock (e.g., DYMO-compatible)
#   - QR code is physically small but optimized to remain scannable


import os
import tkinter as tk
from tkinter import messagebox
import qrcode
import base64
import hashlib

# Pillow for watermarking
from PIL import Image, ImageDraw, ImageFont

# --- cryptography imports (pip install cryptography) ---
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ---------------------------------------------------
# Debug / rollout toggle
# ---------------------------------------------------
VERBOSE_POPUPS = True   # set False when you roll this out to others


# -------------------------------------------------------------------
# Paths / constants
# -------------------------------------------------------------------

# Root folder in the user's home, shared with your main inventory app
APP_DATA_ROOT = os.path.join(os.path.expanduser("~"), "ITInventoryScannerData")

# Folder where QR PNGs will be saved (shared with inventory app)
OUTPUT_DIR = os.path.join(APP_DATA_ROOT, "qr_asset_codes")

# Salt file used for key derivation (shared with inventory app)
SALT_PATH = os.path.join(APP_DATA_ROOT, "db_salt.bin")

# Fallback passphrase used if ITINV_DB_KEY env var not set
DEFAULT_DB_PASSPHRASE = "ITINV_DEFAULT_FALLBACK_PASSPHRASE_change_me"

# Marker prefix that indicates an encrypted QR payload
ENC_PREFIX = "ENC1:"

# -------------------------------------------------------------------
# Branding / watermark customization (safe for public repo)
# -------------------------------------------------------------------

# Allows users to override watermark text via environment variable
# Example:
#   set ITINV_WATERMARK_OWNER="Property of Acme Corp"
WATERMARK_OWNER = os.environ.get(
    "ITINV_WATERMARK_OWNER",
    "Property of Company"
)


# The 13 fields in order (must match Cipher parsing order)
FIELDS = [
    "Device Type",
    "Name",
    "Make",
    "Department",
    "Serial #",
    "OS",
    "Windows Version",
    "Model",
    "RAM",
    "Storage",
    "Processor",
    "Location",
    "Status",
]

DELIM = "$"

# ---- Label / QR sizing for 1" × 2-1/8" DYMO labels ----
# Most DYMO label printers are 300 DPI, so use that as the physical basis.
LABEL_DPI = 600
LABEL_SHORT_IN = 1.0
LABEL_LONG_IN = 2.125
MAX_LABEL_SHORT_PX = int(LABEL_DPI * LABEL_SHORT_IN)  # ≈ 300 px

# Target physical sizes (at 300 DPI):
#   - QR square ≈ 0.35" high  (small but scannable)
#   - Text strip ≈ 0.20" high
TARGET_QR_IN = 0.15
TARGET_TEXT_IN = 0.20

QR_IMAGE_SIZE_PX = int(LABEL_DPI * TARGET_QR_IN)          # ≈ 90 px
QR_WATERMARK_HEIGHT_PX = int(LABEL_DPI * TARGET_TEXT_IN)  # ≈ 120 px
# total image height ≈ 0.55" → leaves top/bottom margin on 1" label

# Shared Fernet instance
_FERNET = None


# -------------------------------------------------------------------
# Encryption helpers (shared key with Cipher app)
# -------------------------------------------------------------------

def get_shared_fernet() -> Fernet:
    """
    Derive a Fernet key from ITINV_DB_KEY (or fallback) and a stored salt.
    This must match the logic used in the Cipher inventory app so that
    QR codes encrypted here can be decrypted there.
    """
    global _FERNET
    if _FERNET is not None:
        return _FERNET

    os.makedirs(APP_DATA_ROOT, exist_ok=True)

    passphrase = os.environ.get("ITINV_DB_KEY", DEFAULT_DB_PASSPHRASE)
    passphrase_bytes = passphrase.encode("utf-8")

    # Salt: persisted to disk so the same password gives the same key
    if os.path.exists(SALT_PATH):
        with open(SALT_PATH, "rb") as f:
            salt = f.read()
    else:
        salt = os.urandom(16)
        with open(SALT_PATH, "wb") as f:
            f.write(salt)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend(),
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase_bytes))
    _FERNET = Fernet(key)
    return _FERNET


# -------------------------------------------------------------------
# QR helpers
# -------------------------------------------------------------------

def ensure_output_folder():
    """Make sure the data directories exist."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def encode_payload(values: dict) -> str:
    """
    Build plaintext payload (13 fields):
    DeviceType$Name$Make$Department$Serial$OS$WindowsVersion$
    Model$RAM$Storage$Processor$Location$Status
    """
    parts = []
    for field in FIELDS:
        raw = values.get(field, "") or ""
        parts.append(raw.strip())
    return DELIM.join(parts)


def _make_watermark_text(location: str) -> str:
    """
    Return watermark text shown under the QR.
    Uses a generic default but supports environment-based branding.
    """
    loc = (location or "").strip().upper()

    if loc:
        return f"{WATERMARK_OWNER} • {loc}"

    return WATERMARK_OWNER


def generate_qr(payload: str, serial: str, location: str) -> tuple[str, str, str]:
    """
    Encrypt the payload, generate a watermarked QR PNG, and save it.

    Args:
      payload  : plaintext 13-field string (what Cipher will see after decryption)
      serial   : asset serial (used in filename)
      location : Location field (used to choose watermark text)

    Returns:
      (filepath, qr_text, checksum)
        filepath : path to saved PNG
        qr_text  : encrypted text actually stored in the QR
        checksum : hex checksum of the plaintext payload
    """
    ensure_output_folder()

    # Clean serial for filename
    safe_serial = "".join(c for c in (serial or "asset") if c.isalnum() or c in "-_")
    if not safe_serial:
        safe_serial = "asset"

    filename = safe_serial + ".png"
    filepath = os.path.join(OUTPUT_DIR, filename)

    # --- checksum of plaintext payload (for display/logging only) -------
    checksum = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:8]

    # --- Encrypt the payload --------------------------------------------
    f = get_shared_fernet()
    token_bytes = f.encrypt(payload.encode("utf-8"))   # Fernet token (bytes)
    token_str = token_bytes.decode("utf-8")            # URL-safe base64 text
    qr_text = ENC_PREFIX + token_str                   # what goes into the QR
    # --------------------------------------------------------------------

    # Build base QR image (larger, then we resize so it fits the label)
    qr = qrcode.QRCode(
        version=None,  # let library choose minimal version
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=2,
        border=4,      # keep at least 4 for proper quiet zone
    )
    qr.add_data(qr_text)
    qr.make(fit=True)
    base_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")

    # Resize QR square so it has the target physical size on the label
    base_img = base_img.resize(
        (QR_IMAGE_SIZE_PX, QR_IMAGE_SIZE_PX), resample=Image.LANCZOS
    )

    # --- Add watermark BELOW the QR so the code itself stays clean ------
    wm_text = _make_watermark_text(location)
    w, h = base_img.size  # both == QR_IMAGE_SIZE_PX
    extra_h = QR_WATERMARK_HEIGHT_PX  # space for watermark text

    final_img = Image.new("RGB", (w, h + extra_h), "white")
    final_img.paste(base_img, (0, 0))

    draw = ImageDraw.Draw(final_img)
    try:
        font = ImageFont.load_default()
    except Exception:
        font = None

    bbox = draw.textbbox((0, 0), wm_text, font=font)
    text_w = bbox[2] - bbox[0]
    text_h = bbox[3] - bbox[1]

    x = max(0, (w - text_w) // 2)
    y = h + max(0, (extra_h - text_h) // 2)
    draw.text((x, y), wm_text, fill="black", font=font)

    final_img.save(filepath)

    return filepath, qr_text, checksum


# -------------------------------------------------------------------
# GUI
# -------------------------------------------------------------------

def build_gui():
    """Create and run the Tkinter GUI."""
    root = tk.Tk()
    root.title("Cipher Asset QR Generator (Encrypted + Watermarked)")

    entries = {}
    row = 0

    hints = {
        "Device Type": "e.g. LAPTOP, DESKTOP, MONITOR",
        "Name": "Short device label (e.g. HP7040-01)",
        "Make": "e.g. HP, DELL, LENOVO",
        "Department": "e.g. IT, ADMIN, HR",
        "Serial #": "Required (e.g. UH524)",
        "OS": "e.g. Windows",
        "Windows Version": "e.g. 10 22H2, 11 24H2",
        "Model": "e.g. ProBook, ZBook, OptiPlex 7040",
        "RAM": "e.g. 8 GB, 16 GB, 32 GB",
        "Storage": "e.g. 256 GB SSD, 1 TB HDD",
        "Processor": "e.g. i5, i7, i9, M1",
        "Location": "e.g. HQ-01, WH-02, BR-03, REMOTE",
        "Status": "e.g. IN USE, INVENTORY, RETIRED",
    }

    def on_generate():
        # Collect data from GUI
        values = {label: entries[label].get() for label in FIELDS}

        serial = values["Serial #"].strip()
        if not serial:
            messagebox.showerror("Error", "Serial # is required.")
            return

        # Build plaintext payload string your Cipher-style app expects
        payload = encode_payload(values)
        location = values.get("Location", "").strip()

        try:
            png_path, qr_text, checksum = generate_qr(payload, serial, location)
            if VERBOSE_POPUPS:
                # Full verbose popup (testing only)
                messagebox.showinfo(
                    title="QR Generated",
                    message=(
                        f"QR code created:\n{png_path}\n\n"
                        f"Plaintext payload checksum: {checksum}\n"
                        "(checksum is of the 13-field string BEFORE encryption)\n\n"
                        "Encrypted QR content (what any QR reader will see):\n"
                        f"{qr_text}\n\n"
                        "When scanned in your Cipher-style app, the app will:\n"
                        "1) Detect the 'ENC1:' prefix\n"
                        "2) Decrypt the token using ITINV_DB_KEY + db_salt.bin\n"
                        "3) Parse the 13 fields from the decrypted text."
                    ),
                )
            else:
                # Minimal popup (safe for production)
                messagebox.showinfo(
                    title="QR Generated",
                    message="QR code created successfully.",
                )

        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate QR code:\n{e}")

    # Build the form
    for label in FIELDS:
        tk.Label(root, text=label + ":").grid(
            row=row, column=0, sticky="e", padx=4, pady=2
        )

        frame = tk.Frame(root)
        frame.grid(row=row, column=1, sticky="w", padx=4, pady=2)

        e = tk.Entry(frame, width=35)
        e.pack(side="left")
        entries[label] = e

        hint = hints.get(label, "")
        if hint:
            hint_lbl = tk.Label(frame, text=hint, fg="gray", font=("Segoe UI", 8))
            hint_lbl.pack(side="left", padx=4)

        row += 1

    btn = tk.Button(root, text="Generate Secure QR Code", command=on_generate)
    btn.grid(row=row, column=0, columnspan=2, pady=10)

    # Run the Tkinter main loop
    root.mainloop()


def main():
    ensure_output_folder()
    build_gui()


if __name__ == "__main__":
    main()
