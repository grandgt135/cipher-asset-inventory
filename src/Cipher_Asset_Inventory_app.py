# Cipher_Asset_Inventory_app.py
# IT Inventory Scanner - desktop app
# - Dashboard with colorful tiles
# - Inventory screen backed by SQLite
# - CSV import/export (Send / Receive)
# - New File, Files, Preferences all functional
# - Secure login / user management (SQLite, salted password hashes)
# - Simple Wi-Fi Scanner placeholder dialog
# - New Asset From Scan dialog with larger, easy-to-read dropdowns
# - QR / multi-field scan support:
#   DeviceType$Name$Serial$OS$Model$Storage$Processor
# - Auto-add unknown models into the Model dropdown
# - Barcode column displays QR icon instead of raw text
# - Auto scan mode: IN or OUT
#   * Press IN  → subsequent scans add +1
#   * Press OUT → subsequent scans subtract −1
#
# - Optional: user-configured cloud folder shortcuts
#   (e.g., OneDrive, Dropbox, Google Drive – local sync paths only)
#
# - Optional database encryption using cryptography/Fernet:
#   * inventory.db is decrypted only while the app is running
#   * inventory.enc represents the encrypted-at-rest copy
#   * Encrypted backup file is refreshed after database changes
#   * "Backup encrypted database" allows exporting a secure copy
#
# - Encryption key handling:
#   * Recommended: provide key via ITINV_DB_KEY environment variable
#   * Keys are never stored in the repository
#   * Compiled-in fallback is intended for development/testing only
#
# - Encrypted QR payload format:
#   * QR codes contain: ENC1:<Fernet-token>
#   * App decrypts token, then parses a 13-field "$"-separated payload


import os
import sys
import csv
import sqlite3
import hashlib
import platform
import io  # for QR image conversion
import shutil
import base64
from datetime import datetime

from PyQt5.QtCore import Qt, QSize, QSettings, QUrl, QTimer
from PyQt5.QtGui import QFont, QDesktopServices, QPixmap, QIcon
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QHBoxLayout,
    QVBoxLayout,
    QLabel,
    QPushButton,
    QListWidget,
    QListWidgetItem,
    QStackedWidget,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QComboBox,
    QLineEdit,
    QFileDialog,
    QSpacerItem,
    QSizePolicy,
    QDialog,
    QFormLayout,
    QDialogButtonBox,
    QGroupBox,
    QHeaderView,
    QCheckBox,
    QInputDialog,
    QTextEdit,
)

# Pillow for watermarked QR PNGs
from PIL import Image, ImageDraw, ImageFont

# --- cryptography imports (pip install cryptography) ---
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

APP_NAME = "Cipher Asset Inventory"
ORG_NAME = "DennisShaullLabs"

# Toggle verbose popups / sensitive path details
VERBOSE_POPUPS = True   # set to False when rolling out to others

# Store data in a fixed folder under the user home so the .app / .exe
# can live anywhere and still find the DB.
DATA_DIR = os.path.join(os.path.expanduser("~"), "ITInventoryScannerData")
os.makedirs(DATA_DIR, exist_ok=True)

# Where regenerated QR PNGs will be stored (shared with QR generator app)
QR_OUTPUT_DIR = os.path.join(DATA_DIR, "qr_asset_codes")
os.makedirs(QR_OUTPUT_DIR, exist_ok=True)

# ===============================
# OPTIONAL SYNC REPOSITORY (SharePoint/OneDrive/Dropbox folder)
# ===============================
# If the user has a local synced folder, set:
#   ITINV_REPO_ROOT="C:\Users\<you>\OneDrive - <Org>\Inventory-Repository"
# If not set, Publish Snapshot will still work by exporting to a local folder you choose.

REPO_ROOT = os.environ.get("ITINV_REPO_ROOT", "").strip()

REPO_DB_DIR = os.path.join(REPO_ROOT, "Master-Database") if REPO_ROOT else ""
REPO_EXPORT_DIR = os.path.join(REPO_ROOT, "Daily-Exports") if REPO_ROOT else ""



# Plaintext DB path (used only while the app is running)
DB_PATH = os.path.join(DATA_DIR, "inventory.db")
# Encrypted DB path (at rest)
ENC_DB_PATH = os.path.join(DATA_DIR, "inventory.enc")
# Salt file for key derivation
SALT_PATH = os.path.join(DATA_DIR, "db_salt.bin")

# Fallback passphrase used if ITINV_DB_KEY env var not set
DEFAULT_DB_PASSPHRASE = "ITINV_DEFAULT_FALLBACK_PASSPHRASE_change_me"

# QR / encoded payload constants
QR_DELIM = "$"
QR_FIELD_COUNT = 13  # DeviceType, Name, Make, Dept, Serial, OS, WinVer, Model, RAM, Storage, Processor, Location, Status

# Prefix for encrypted QR codes produced by the generator app
ENC_PREFIX = "ENC1:"

# Optional watermark branding override (via env var)
WATERMARK_OWNER = os.environ.get("ITINV_WATERMARK_OWNER", "Property of Company")


# ---- Label / QR sizing for 1" × 2-1/8" DYMO labels ----
LABEL_DPI = 600
LABEL_SHORT_IN = 1.0
LABEL_LONG_IN = 2.125
MAX_LABEL_SHORT_PX = int(LABEL_DPI * LABEL_SHORT_IN)  # ≈ 600 px

# Target physical sizes (at 300 DPI):
#   - QR square ≈ 0.55" high  (a bit over half the label height)
#   - Text strip ≈ 0.20" high
TARGET_QR_IN = 0.15
TARGET_TEXT_IN = 0.20

QR_IMAGE_SIZE_PX = int(LABEL_DPI * TARGET_QR_IN)          # ≈ 90 px
QR_WATERMARK_HEIGHT_PX = int(LABEL_DPI * TARGET_TEXT_IN)  # ≈ 120 px
# total image height ≈ 0.75" → leaves top/bottom margin on 1" label

# Global Fernet instance (initialized lazily)
_FERNET = None


# ---------- Encryption helpers ----------

def _get_fernet() -> Fernet:
    """
    Derive a Fernet key from ITINV_DB_KEY (or fallback) and a stored salt.
    Returns a global Fernet instance.
    """
    global _FERNET
    if _FERNET is not None:
        return _FERNET

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


def decrypt_db_if_needed():
    """
    If an encrypted DB exists but no plaintext DB, decrypt ENC_DB_PATH
    into DB_PATH so sqlite3 can open it.
    """
    if not os.path.exists(ENC_DB_PATH):
        return
    if os.path.exists(DB_PATH):
        return

    fernet = _get_fernet()
    try:
        with open(ENC_DB_PATH, "rb") as f:
            ciphertext = f.read()
        plaintext = fernet.decrypt(ciphertext)
    except InvalidToken:
        # Wrong key / corrupted file
        print(
            "ERROR: Unable to decrypt inventory.enc. "
            "Check ITINV_DB_KEY and db_salt.bin.",
            file=sys.stderr,
        )
        sys.exit(1)

    with open(DB_PATH, "wb") as f:
        f.write(plaintext)


def write_encrypted_copy(delete_plaintext: bool = False):
    """
    Encrypt DB_PATH into ENC_DB_PATH.
    If delete_plaintext is True, remove DB_PATH after writing.
    """
    if not os.path.exists(DB_PATH):
        return

    fernet = _get_fernet()
    with open(DB_PATH, "rb") as f:
        data = f.read()
    ciphertext = fernet.encrypt(data)

    with open(ENC_DB_PATH, "wb") as f:
        f.write(ciphertext)

    if delete_plaintext:
        try:
            os.remove(DB_PATH)
        except OSError:
            pass

# ============================================================
# 📁 SHAREPOINT REPOSITORY HELPERS
# ============================================================

def ensure_sharepoint_repo_folders():
    """
    Ensure the optional synced repository folders exist locally.
    If ITINV_REPO_ROOT is not set, return False with a friendly message.
    """
    if not REPO_ROOT:
        return False, (
            "ITINV_REPO_ROOT is not set.\n\n"
            "Set ITINV_REPO_ROOT to a locally-synced folder (OneDrive/SharePoint/etc), "
            "or use the export-to-folder option."
        )
    try:
        os.makedirs(REPO_DB_DIR, exist_ok=True)
        os.makedirs(REPO_EXPORT_DIR, exist_ok=True)
        return True, ""
    except Exception as e:
        return False, str(e)


def get_all_locations() -> list:
    """
    Return a sorted list of distinct inventory locations
    (e.g., HQ-01, WH-02, BR-03, REMOTE)
    from the items table.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT DISTINCT location
        FROM items
        WHERE location IS NOT NULL AND location <> ''
        ORDER BY location
        """
    )
    rows = cur.fetchall()
    conn.close()
    return [(r["location"] or "").strip().upper() for r in rows if r["location"]]



# ---------- SQLite helpers ----------

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Ensure data directory exists, decrypt encrypted DB if needed,
    and create tables if they don't exist yet.
    """
    os.makedirs(DATA_DIR, exist_ok=True)
    # If we only have an encrypted DB, decrypt it to a working copy
    decrypt_db_if_needed()

    conn = get_db_connection()
    cur = conn.cursor()

    # items table
    cur.execute(
    """
    CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY,
        device_type TEXT,
        name TEXT,
        make TEXT,
        department TEXT,
        serial TEXT UNIQUE,
        os TEXT,
        windows_version TEXT,
        model TEXT,
        ram TEXT,
        storage TEXT,
        processor TEXT,
        barcode TEXT,
        location TEXT,
        status TEXT,
        quantity INTEGER DEFAULT 0
    )
    """
)


    # --- schema migration for new columns (windows_version, ram) ---
    cur.execute("PRAGMA table_info(items)")
    existing_cols = {row[1] for row in cur.fetchall()}

    if "windows_version" not in existing_cols:
        cur.execute("ALTER TABLE items ADD COLUMN windows_version TEXT")

    if "ram" not in existing_cols:
        cur.execute("ALTER TABLE items ADD COLUMN ram TEXT")

    # Move old Storage values into RAM on first migration (optional)
    if "storage" in existing_cols and "ram" in existing_cols:
        cur.execute("""
            UPDATE items
            SET ram = COALESCE(ram, storage),
                storage = NULL
            WHERE ram IS NULL AND storage IS NOT NULL
        """)


    # users table for login / admin
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    # maintenance history table (per-asset lifecycle & maintenance events)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS maintenance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            serial TEXT NOT NULL,
            company TEXT,
            location TEXT,
            event_date TEXT NOT NULL,   -- ISO date string: YYYY-MM-DD
            event_type TEXT NOT NULL,   -- e.g. DEPLOYED, REPAIRED, MOVED, RETIRED
            notes TEXT
        )
        """
    )

    conn.commit()
    conn.close()


# ---------- password helpers ----------

def hash_password(password: str) -> str:
    """Return salted SHA-256 hash in form 'salt$hash'."""
    salt = os.urandom(16).hex()
    h = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return f"{salt}${h}"


def verify_password(stored: str, password: str) -> bool:
    try:
        salt, stored_hash = stored.split("$", 1)
    except ValueError:
        return False
    test_hash = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return test_hash == stored_hash


# ---------- Preferences dialog ----------

class PreferencesDialog(QDialog):
    def __init__(self, parent, current_theme: str, current_accent: str):
        super().__init__(parent)
        self.setWindowTitle("Preferences")
        self.setModal(True)
        self.resize(360, 200)

        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Light", "Dark"])
        self.theme_combo.setCurrentText(current_theme.capitalize())

        self.accent_combo = QComboBox()
        self.accent_combo.addItems(["Blue", "Green", "Orange", "Purple", "Red", "Gray"])

        combo_style = """
        QComboBox {
            font-size: 13px;
            padding: 4px;
            min-width: 160px;
        }
        QComboBox QAbstractItemView {
            font-size: 13px;
            selection-background-color: #0078D7;
        }
        """
        self.theme_combo.setStyleSheet(combo_style)
        self.accent_combo.setStyleSheet(combo_style)

        self.accent_combo.setCurrentText(current_accent.capitalize())

        form = QFormLayout()
        form.addRow("Theme:", self.theme_combo)
        form.addRow("Accent color:", self.accent_combo)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout()
        layout.addLayout(form)
        layout.addWidget(buttons)
        self.setLayout(layout)

    def selected_theme(self) -> str:
        return self.theme_combo.currentText().lower()

    def selected_accent(self) -> str:
        return self.accent_combo.currentText().lower()


# ---------- Inventory page ----------

class InventoryPage(QWidget):
    # Column indices for clarity
    COL_MAINT = 0
    COL_DEVICE = 1
    COL_NAME = 2
    COL_MAKE = 3
    COL_DEPT = 4
    COL_SERIAL = 5
    COL_OS = 6
    COL_WINVER = 7
    COL_MODEL = 8
    COL_RAM = 9
    COL_STORAGE = 10
    COL_PROCESSOR = 11
    COL_BARCODE = 12
    COL_LOCATION = 13
    COL_STATUS = 14
    COL_QTY = 15

    HEADERS = [
        "🛠",
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
        "Barcode",
        "Location",
        "Status",
        "Quantity",
    ]

    DEVICE_VALUES = ["", "Desktop", "Laptop", "Monitor", "Dock", "Printer"]
    NAME_VALUES = [""]  # will fill dynamically from DB/QR
    MAKE_VALUES = ["", "Dell", "HP", "Lenovo", "Apple"]
    DEPT_VALUES = ["", "IT", "HR", "Legal", "Operations"]

    OS_VALUES = ["", "Windows 10 Pro", "Windows 11 Pro", "Mac"]
    WINVER_VALUES = [""]  # e.g. "22H2", "23H2", etc – grows dynamically
    MODEL_VALUES = [
        "",
        "OptiPlex 5050",
        "OptiPlex 5070",
        "OptiPlex 7010",
        "OptiPlex 7040",
        "OptiPlex 7050",
        "OptiPlex 7060",
        "OptiPlex 7070",
        "OptiPlex 7080",
        "OptiPlex 7090",
    ]
    RAM_VALUES = ["", "8 GB", "16 GB", "32 GB", "64 GB"]
    STORAGE_VALUES = [""]  # grows dynamically (256 GB SSD, etc.)

    PROCESSOR_VALUES = ["", "i5", "i7", "i9", "M1", "M2", "M3", "M4"]
    LOCATION_VALUES = ["", "HQ", "REMOTE", "WAREHOUSE", "BRANCH-1", "BRANCH-2"]
    STATUS_VALUES = ["", "IN USE", "INVENTORY", "RETIRED", "INACTIVE"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent  # MainWindow

        # current scan mode: "in" (default) or "out"
        self.scan_mode = "in"

        layout = QVBoxLayout(self)

        header_row = QHBoxLayout()
        title = QLabel("Asset Tracking Console")
        title.setFont(QFont("Segoe UI", 12, QFont.Bold))
        header_row.addWidget(title)
        header_row.addStretch()
        layout.addLayout(header_row)

        # table
        self.table = QTableWidget(0, len(self.HEADERS))
        self.table.setHorizontalHeaderLabels(self.HEADERS)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)

        for i, w in enumerate([40, 110, 120, 110, 110, 120, 130, 110, 110, 80, 110, 120, 110, 110, 80, 60]):
            self.table.setColumnWidth(i, w)

        layout.addWidget(self.table)

        # row controls
        row_controls = QHBoxLayout()
        self.add_btn = QPushButton("Add Row")
        self.delete_btn = QPushButton("Delete Row")
        self.save_btn = QPushButton("Save All")
        self.regen_qr_btn = QPushButton("Update QR for Row")
        self.maint_btn = QPushButton("Maintenance")

        self.add_btn.clicked.connect(self.add_empty_row)
        self.delete_btn.clicked.connect(self.delete_selected_row)
        self.save_btn.clicked.connect(self.save_all_to_db)
        self.regen_qr_btn.clicked.connect(self.regenerate_qr_for_selected_row)
        self.maint_btn.clicked.connect(self.open_maintenance_for_selected_row)

        row_controls.addWidget(self.add_btn)
        row_controls.addWidget(self.delete_btn)
        row_controls.addWidget(self.save_btn)
        row_controls.addWidget(self.regen_qr_btn)
        row_controls.addWidget(self.maint_btn)
        row_controls.addStretch()
        layout.addLayout(row_controls)

        # bottom scan controls
        bottom = QHBoxLayout()
        bottom.addWidget(QLabel("Scan / type barcode or Serial #:"))
        self.scan_edit = QLineEdit()
        self.scan_edit.setPlaceholderText("Scan here...")
        bottom.addWidget(self.scan_edit, stretch=3)

        # Auto scan timer
        self.scan_timer = QTimer(self)
        self.scan_timer.setSingleShot(True)
        self.scan_timer.timeout.connect(lambda: self.handle_scan_safe(self.scan_mode))
        self.scan_edit.textChanged.connect(self.on_scan_text_changed)

        bottom.addItem(QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))

        self.in_btn = QPushButton("IN (+1)")
        self.out_btn = QPushButton("OUT (-1)")
        self.in_btn.setMinimumWidth(90)
        self.out_btn.setMinimumWidth(90)

        self.in_btn.clicked.connect(self.set_scan_in)
        self.out_btn.clicked.connect(self.set_scan_out)

        bottom.addWidget(self.in_btn)
        bottom.addWidget(self.out_btn)

        layout.addLayout(bottom)

        self.reload_from_db()

        # Nice-to-have: pull distinct locations from DB into the dropdown list
        try:
            db_locs = get_all_locations()
            for loc in db_locs:
                if loc and loc not in self.LOCATION_VALUES:
                    self.LOCATION_VALUES.append(loc)
        except Exception:
            pass

    def set_scan_in(self):
        self.scan_mode = "in"

    def set_scan_out(self):
        self.scan_mode = "out"

    # --- scan timer handler ---

    def on_scan_text_changed(self, text: str):
        if not text:
            self.scan_timer.stop()
            return
        self.scan_timer.start(250)

    def on_in_clicked(self):
        if self.scan_edit.text().strip():
            self.handle_scan_safe("in")

    def on_out_clicked(self):
        if self.scan_edit.text().strip():
            self.handle_scan_safe("out")

    # ---- QR display helpers ----

    def _generate_qr_pixmap(self, data: str, size: int = 80) -> QPixmap:
        if not data:
            return QPixmap()
        try:
            import qrcode
            qr_img = qrcode.make(data)
            buf = io.BytesIO()
            qr_img.save(buf, format="PNG")
            pixmap = QPixmap()
            pixmap.loadFromData(buf.getvalue(), "PNG")
            return pixmap.scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        except Exception:
            return QPixmap()

    def _make_qr_item(self, data: str) -> QTableWidgetItem:
        item = QTableWidgetItem("")
        item.setTextAlignment(Qt.AlignCenter)
        item.setData(Qt.UserRole, data or "")
        pixmap = self._generate_qr_pixmap(data)
        if not pixmap.isNull():
            item.setIcon(QIcon(pixmap))
        return item

    # ---- helpers for widgets inside the table ----

    def _make_line_item(self, text: str) -> QTableWidgetItem:
        return QTableWidgetItem(text)

    def _make_combo(self, values, current: str, values_attr: str = None) -> QComboBox:
        """
        Editable combo that:
        - selects case-insensitive match
        - if current/new text not in list, adds it
        - if user types a new value later, auto-adds it to the backing list (values_attr)
          and pushes it into all rows for that column.
        """
        combo = QComboBox()
        combo.setEditable(True)
        combo.addItems(values)

        def normalize(s: str) -> str:
            return (s or "").strip()

        def ensure_in_list(val: str):
            val = normalize(val)
            if not val:
                return

            # backing list update
            if values_attr:
                backing = getattr(self, values_attr, None)
                if isinstance(backing, list):
                    # case-insensitive existence check
                    if not any(v.lower() == val.lower() for v in backing):
                        backing.append(val)

            # ensure this combo has it
            if combo.findText(val, Qt.MatchFixedString) < 0:
                combo.addItem(val)

            combo.setCurrentText(val)

            # push into ALL combos in that column (so future rows see it)
            if values_attr:
                col = getattr(self, f"COL_{values_attr.split('_')[0].upper()}", None)
                # (we'll map columns explicitly below instead of guessing)

        # set initial current
        if current:
            cur = normalize(current)
            # try to match existing by case-insensitive compare
            match = None
            for v in values:
                if v.lower() == cur.lower():
                    match = v
                    break
            if match:
                combo.setCurrentText(match)
            else:
                combo.addItem(cur)
                combo.setCurrentText(cur)
                if values_attr:
                    backing = getattr(self, values_attr, None)
                    if isinstance(backing, list) and not any(v.lower() == cur.lower() for v in backing):
                        backing.append(cur)

        # when user types something new
        combo.lineEdit().editingFinished.connect(lambda: self._on_combo_edited(combo, values_attr))

        return combo

    def _on_combo_edited(self, combo: QComboBox, values_attr: str):
        """
        Fired when user finishes typing into an editable combo.
        Adds the value to the backing list and updates all combos in that column.
        """
        if not values_attr:
            return

        text = (combo.currentText() or "").strip()
        if not text:
            return

        backing = getattr(self, values_attr, None)
        if not isinstance(backing, list):
            return

        if not any(v.lower() == text.lower() for v in backing):
            backing.append(text)

        # update every row's combo in the matching column
        col_map = {
            "DEVICE_VALUES": self.COL_DEVICE,
            "MAKE_VALUES": self.COL_MAKE,
            "DEPT_VALUES": self.COL_DEPT,
            "WINVER_VALUES": self.COL_WINVER,
            "RAM_VALUES": self.COL_RAM,
            "NAME_VALUES": self.COL_NAME,
            "MODEL_VALUES": self.COL_MODEL,
            "STORAGE_VALUES": self.COL_STORAGE,
            "PROCESSOR_VALUES": self.COL_PROCESSOR,
            "LOCATION_VALUES": self.COL_LOCATION,
            "STATUS_VALUES": self.COL_STATUS,
            "OS_VALUES": self.COL_OS,
        }
        col = col_map.get(values_attr)
        if col is None:
            return

        for r in range(self.table.rowCount()):
            w = self.table.cellWidget(r, col)
            if isinstance(w, QComboBox):
                # add if missing (fixed-string)
                if w.findText(text, Qt.MatchFixedString) < 0:
                    w.addItem(text)

    def add_empty_row(self):
        r = self.table.rowCount()
        self.table.insertRow(r)

        combo_cols = {
            self.COL_DEVICE,
            self.COL_NAME,
            self.COL_MAKE,
            self.COL_DEPT,
            self.COL_OS,
            self.COL_WINVER,
            self.COL_MODEL,
            self.COL_RAM,
            self.COL_STORAGE,
            self.COL_PROCESSOR,
            self.COL_LOCATION,
            self.COL_STATUS,
        }

        # Base items
        for col in range(self.table.columnCount()):
            if col in combo_cols:
                continue
            if col == self.COL_QTY:
                item = self._make_line_item("0")
            elif col == self.COL_BARCODE:
                item = self._make_qr_item("")
            else:
                item = self._make_line_item("")
            self.table.setItem(r, col, item)

        # Combos
        self.table.setCellWidget(r, self.COL_DEVICE, self._make_combo(self.DEVICE_VALUES, "", "DEVICE_VALUES"))
        self.table.setCellWidget(r, self.COL_NAME, self._make_combo(self.NAME_VALUES, "", "NAME_VALUES"))
        self.table.setCellWidget(r, self.COL_MAKE, self._make_combo(self.MAKE_VALUES, "", "MAKE_VALUES"))
        self.table.setCellWidget(r, self.COL_DEPT, self._make_combo(self.DEPT_VALUES, "", "DEPT_VALUES"))

        self.table.setCellWidget(r, self.COL_OS, self._make_combo(self.OS_VALUES, "", "OS_VALUES"))
        self.table.setCellWidget(r, self.COL_WINVER, self._make_combo(self.WINVER_VALUES, "", "WINVER_VALUES"))
        self.table.setCellWidget(r, self.COL_MODEL, self._make_combo(self.MODEL_VALUES, "", "MODEL_VALUES"))
        self.table.setCellWidget(r, self.COL_RAM, self._make_combo(self.RAM_VALUES, "", "RAM_VALUES"))
        self.table.setCellWidget(r, self.COL_STORAGE, self._make_combo(self.STORAGE_VALUES, "", "STORAGE_VALUES"))
        self.table.setCellWidget(r, self.COL_PROCESSOR, self._make_combo(self.PROCESSOR_VALUES, "", "PROCESSOR_VALUES"))
        self.table.setCellWidget(r, self.COL_LOCATION, self._make_combo(self.LOCATION_VALUES, "", "LOCATION_VALUES"))
        self.table.setCellWidget(r, self.COL_STATUS, self._make_combo(self.STATUS_VALUES, "", "STATUS_VALUES"))

    def delete_selected_row(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Delete Row", "No row selected.")
            return

        serial_item = self.table.item(row, self.COL_SERIAL)
        serial = serial_item.text().strip() if serial_item else ""

        if QMessageBox.question(
            self,
            "Delete Row",
            "Delete selected row from table and database?",
            QMessageBox.Yes | QMessageBox.No,
        ) == QMessageBox.No:
            return

        self.table.removeRow(row)

        if serial:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("DELETE FROM items WHERE serial = ?", (serial,))
            conn.commit()
            conn.close()
            # Update encrypted-at-rest copy
            write_encrypted_copy(delete_plaintext=False)

    # ---- DB interaction ----

    def reload_from_db(self):
        self.table.setRowCount(0)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT device_type,
                   name,
                   make,
                   department,
                   serial,
                   os,
                   windows_version,
                   model,
                   ram,
                   storage,
                   processor,
                   barcode,
                   location,
                   status,
                   quantity
            FROM items
            ORDER BY device_type, name
            """
        )

        rows = cur.fetchall()
        conn.close()

        for db_row in rows:
            row_idx = self.table.rowCount()
            self.table.insertRow(row_idx)

            serial = db_row["serial"] or ""
            has_maint = self._has_maintenance_records(serial)
            maint_item = QTableWidgetItem("🛠" if has_maint else "")
            maint_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row_idx, self.COL_MAINT, maint_item)

            db_model = db_row["model"] or ""
            if db_model and db_model not in self.MODEL_VALUES:
                self.MODEL_VALUES.append(db_model)

            mapping = [
                ("device_type", self.COL_DEVICE),
                ("name", self.COL_NAME),
                ("make", self.COL_MAKE),
                ("department", self.COL_DEPT),
                ("serial", self.COL_SERIAL),
                ("barcode", self.COL_BARCODE),
                ("quantity", self.COL_QTY),
            ]

            for col_name, col_idx in mapping:
                value = db_row[col_name] if db_row[col_name] is not None else ""
                if col_idx == self.COL_BARCODE:
                    self.table.setItem(row_idx, col_idx, self._make_qr_item(str(value)))
                else:
                    self.table.setItem(
                        row_idx, col_idx, self._make_line_item(str(value))
                    )

            # before: you set item cells for device/name/make/department as QTableWidgetItem
            # change those four (and winver/ram) to combos, not plain items

            self.table.setCellWidget(
                row_idx, self.COL_DEVICE,
                self._make_combo(self.DEVICE_VALUES, db_row["device_type"] or "", "DEVICE_VALUES")
            )
            self.table.setCellWidget(
                row_idx, self.COL_NAME,
                self._make_combo(self.NAME_VALUES, db_row["name"] or "", "NAME_VALUES")
            )
            self.table.setCellWidget(
                row_idx, self.COL_MAKE,
                self._make_combo(self.MAKE_VALUES, db_row["make"] or "", "MAKE_VALUES")
            )
            self.table.setCellWidget(
                row_idx, self.COL_DEPT,
                self._make_combo(self.DEPT_VALUES, db_row["department"] or "", "DEPT_VALUES")
            )

            self.table.setCellWidget(
                row_idx, self.COL_OS,
                self._make_combo(self.OS_VALUES, db_row["os"] or "", "OS_VALUES")
            )
            self.table.setCellWidget(
                row_idx, self.COL_WINVER,
                self._make_combo(self.WINVER_VALUES, db_row["windows_version"] or "", "WINVER_VALUES")
            )
            self.table.setCellWidget(
                row_idx, self.COL_MODEL,
                self._make_combo(self.MODEL_VALUES, db_model, "MODEL_VALUES")
            )
            self.table.setCellWidget(
                row_idx, self.COL_RAM,
                self._make_combo(self.RAM_VALUES, db_row["ram"] or "", "RAM_VALUES")
            )
            self.table.setCellWidget(
                row_idx, self.COL_STORAGE,
                self._make_combo(self.STORAGE_VALUES, db_row["storage"] or "", "STORAGE_VALUES")
            )
            self.table.setCellWidget(
                row_idx, self.COL_PROCESSOR,
                self._make_combo(self.PROCESSOR_VALUES, db_row["processor"] or "", "PROCESSOR_VALUES")
            )
            self.table.setCellWidget(
                row_idx, self.COL_LOCATION,
                self._make_combo(self.LOCATION_VALUES, db_row["location"] or "", "LOCATION_VALUES")
            )
            self.table.setCellWidget(
                row_idx, self.COL_STATUS,
                self._make_combo(self.STATUS_VALUES, db_row["status"] or "", "STATUS_VALUES")
            )

    def save_all_to_db(self):
        conn = get_db_connection()
        cur = conn.cursor()

        for row in range(self.table.rowCount()):
            device_type = self._get_text(row, self.COL_DEVICE)
            name = self._get_text(row, self.COL_NAME)
            make = self._get_text(row, self.COL_MAKE)
            dept = self._get_text(row, self.COL_DEPT)
            serial = self._get_text(row, self.COL_SERIAL)

            os_val = self._get_text(row, self.COL_OS)
            winver = self._get_text(row, self.COL_WINVER)
            model = self._get_text(row, self.COL_MODEL)
            ram = self._get_text(row, self.COL_RAM)
            storage = self._get_text(row, self.COL_STORAGE)
            processor = self._get_text(row, self.COL_PROCESSOR)

            barcode = self._get_barcode(row)
            location = self._get_text(row, self.COL_LOCATION)
            status = self._get_text(row, self.COL_STATUS)
            quantity_text = self._get_text(row, self.COL_QTY) or "0"
            try:
                quantity = int(quantity_text)
            except ValueError:
                quantity = 0

            if not serial:
                continue

            cur.execute(
                """
                INSERT INTO items (device_type, name, make, department, serial,
                                   os, windows_version, model, ram, storage, processor, barcode,
                                   location, status, quantity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(serial) DO
                UPDATE SET
                    device_type=excluded.device_type,
                    name =excluded.name,
                    make=excluded.make,
                    department=excluded.department,
                    os=excluded.os,
                    windows_version=excluded.windows_version,
                    model=excluded.model,
                    ram=excluded.ram,
                    storage=excluded.storage,
                    processor=excluded.processor,
                    barcode=excluded.barcode,
                    location=excluded.location,
                    status=excluded.status,
                    quantity=excluded.quantity
                """,
                (
                    device_type,
                    name,
                    make,
                    dept,
                    serial,
                    os_val,
                    winver,  # ✅ add Windows Version
                    model,
                    ram,  # ✅ add RAM
                    storage,
                    processor,
                    barcode,  # ✅ store what was actually scanned (ENC1:... or plain)
                    location,
                    status,
                    quantity,
                ),
            )

        conn.commit()
        conn.close()
        # Update encrypted-at-rest copy
        write_encrypted_copy(delete_plaintext=False)
        QMessageBox.information(self, "Saved", "All rows saved to database.")

    def _get_text(self, row: int, col: int) -> str:
        w = self.table.cellWidget(row, col)
        if isinstance(w, QComboBox):
            return w.currentText().strip()

        item = self.table.item(row, col)
        return item.text().strip() if item else ""

    def _get_barcode(self, row: int) -> str:
        item = self.table.item(row, self.COL_BARCODE)
        if not item:
            return ""
        data = item.data(Qt.UserRole)
        if data:
            return str(data).strip()
        return item.text().strip()

    def _get_combo_text(self, row: int, col: int) -> str:
        w = self.table.cellWidget(row, col)
        if isinstance(w, QComboBox):
            return w.currentText().strip()
        return ""

    def _update_maintenance_indicator_for_row(self, row: int, serial: str):
        """
        Show a wrench icon in the Maint column if this serial has any
        maintenance records.
        """
        if not serial:
            return

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) AS c FROM maintenance WHERE serial = ?",
            (serial,),
        )
        has_maint = cur.fetchone()["c"] > 0
        conn.close()

        item = QTableWidgetItem("🛠" if has_maint else "")
        item.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row, self.COL_MAINT, item)

    def open_maintenance_for_selected_row(self):
        """Open the Maintenance history window for the currently selected asset."""
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.information(
                self,
                "Maintenance",
                "Select a row in the inventory table first.",
            )
            return

        serial = self._get_text(row, self.COL_SERIAL)
        if not serial:
            QMessageBox.warning(
                self,
                "Maintenance",
                "The selected row has no Serial #.",
            )
            return

        # Treat Department as "company" for lifecycle grouping
        company = self._get_text(row, self.COL_DEPT)
        # Use current Location combo value
        location = self._get_combo_text(row, self.COL_LOCATION)

        dlg = MaintenanceDialog(self, serial=serial, company=company, location=location)
        dlg.exec_()

        # After dialog closes, update the indicator
        self._update_maintenance_indicator_for_row(row, serial)

    def _has_maintenance_records(self, serial: str) -> bool:
        if not serial:
            return False
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT 1 FROM maintenance WHERE serial = ? LIMIT 1", (serial,)
        )
        result = cur.fetchone()
        conn.close()
        return result is not None

    # ---- QR regeneration + watermark helpers ----

    def _encrypt_qr_payload(self, plaintext: str) -> str:
        """
        Encrypt an 11-field payload using the same Fernet key and
        ENC_PREFIX used by the QR generator app.
        """
        f = _get_fernet()
        token = f.encrypt(plaintext.encode("utf-8"))
        return ENC_PREFIX + token.decode("utf-8")

    def _determine_watermark_text(self, location: str) -> str:
        loc = (location or "").strip().upper()
        if loc:
            return f"{WATERMARK_OWNER} • {loc}"
        return WATERMARK_OWNER

    def _create_watermarked_qr_image(self, qr_text: str, location: str) -> Image.Image:
        """
        Build a QR code from qr_text, then add a white strip
        underneath with the location-specific watermark text.

        The final image is sized to fit on a 1" × 2-1/8" DYMO label.
        """
        import qrcode

        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=2,
            border=4,
        )
        qr.add_data(qr_text)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGBA")

        qr_img = qr_img.resize(
            (QR_IMAGE_SIZE_PX, QR_IMAGE_SIZE_PX), resample=Image.LANCZOS
        )

        wm_text = self._determine_watermark_text(location)
        if not wm_text:
            return qr_img

        qr_w, qr_h = qr_img.size
        extra_h = QR_WATERMARK_HEIGHT_PX

        new_h = qr_h + extra_h
        canvas = Image.new("RGBA", (qr_w, new_h), "white")
        canvas.paste(qr_img, (0, 0))

        draw = ImageDraw.Draw(canvas)
        try:
            font = ImageFont.load_default()
        except Exception:
            font = None


        bbox = draw.textbbox((0, 0), wm_text, font=font)
        text_w = bbox[2] - bbox[0]
        text_h = bbox[3] - bbox[1]

        x = (qr_w - text_w) // 2
        y = qr_h + (extra_h - text_h) // 2
        draw.text((x, y), wm_text, fill="black", font=font)

        return canvas

    def _ensure_qr_folder(self):
        try:
            os.makedirs(QR_OUTPUT_DIR, exist_ok=True)
        except Exception:
            pass

    def _build_qr_payload_from_row(self, row: int) -> str:
        # DeviceType$Name$Make$Department$Serial$OS$WindowsVersion$Model$RAM$Storage$Processor$Location$Status
        device_type = self._get_text(row, self.COL_DEVICE)
        name = self._get_text(row, self.COL_NAME)
        make = self._get_text(row, self.COL_MAKE)
        department = self._get_text(row, self.COL_DEPT)
        serial = self._get_text(row, self.COL_SERIAL)

        os_val = self._get_text(row, self.COL_OS)
        winver = self._get_text(row, self.COL_WINVER)
        model = self._get_text(row, self.COL_MODEL)
        ram = self._get_text(row, self.COL_RAM)
        storage = self._get_text(row, self.COL_STORAGE)
        processor = self._get_text(row, self.COL_PROCESSOR)
        location = self._get_text(row, self.COL_LOCATION)
        status = self._get_text(row, self.COL_STATUS)

        parts = [
            device_type or "",
            name or "",
            make or "",
            department or "",
            serial or "",
            os_val or "",
            winver or "",
            model or "",
            ram or "",
            storage or "",
            processor or "",
            location or "",
            status or "",
        ]
        return QR_DELIM.join(p.strip() for p in parts)

    def _generate_qr_png_for_row(self, qr_text: str, serial: str, location: str) -> str:
        """
        Save a PNG label for this asset using the **encrypted** qr_text
        and a location-based watermark strip, into QR_OUTPUT_DIR.
        """
        if not qr_text or not serial:
            return ""
        self._ensure_qr_folder()

        safe_serial = "".join(c for c in serial if c.isalnum() or c in "-_") or "asset"
        filename = safe_serial + ".png"
        filepath = os.path.join(QR_OUTPUT_DIR, filename)

        try:
            img = self._create_watermarked_qr_image(qr_text, location)
            img.save(filepath)
            return filepath
        except Exception:
            return ""

    def regenerate_qr_for_selected_row(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.information(
                self, "Update QR", "Select a row in the inventory table first."
            )
            return

        serial = self._get_text(row, self.COL_SERIAL)
        if not serial:
            QMessageBox.warning(
                self,
                "Update QR",
                "The selected row has no Serial #. A serial is required to build the QR.",
            )
            return

        try:
            plaintext_payload = self._build_qr_payload_from_row(row)
            if not plaintext_payload:
                QMessageBox.warning(
                    self,
                    "Update QR",
                    "Could not build QR payload from the selected row.",
                )
                return

            encrypted_payload = self._encrypt_qr_payload(plaintext_payload)

            barcode_item = self._make_qr_item(encrypted_payload)
            self.table.setItem(row, self.COL_BARCODE, barcode_item)

            self._upsert_row_with_barcode(row, encrypted_payload)

            location = self._get_combo_text(row, self.COL_LOCATION)
            png_path = self._generate_qr_png_for_row(encrypted_payload, serial, location)

        except Exception as e:
            QMessageBox.critical(
                self,
                "Update QR - Error",
                f"An error occurred while updating the QR code:\n{e}",
            )
            return

        msg = "QR code updated from current row values."
        if png_path:
            msg += f"\n\nNew PNG file:\n{png_path}"

        QMessageBox.information(self, "Update QR", msg)

    def _upsert_row_with_barcode(self, row: int, barcode_payload: str):
        """
        Save the current row values (including the new barcode payload)
        into the items table using an UPSERT on serial.
        """
        device_type = self._get_text(row, self.COL_DEVICE)
        name = self._get_text(row, self.COL_NAME)
        make = self._get_text(row, self.COL_MAKE)
        dept = self._get_text(row, self.COL_DEPT)
        serial = self._get_text(row, self.COL_SERIAL)
        os_val = self._get_combo_text(row, self.COL_OS)
        winver = self._get_combo_text(row, self.COL_WINVER)
        model = self._get_combo_text(row, self.COL_MODEL)
        ram = self._get_combo_text(row, self.COL_RAM)
        storage = self._get_combo_text(row, self.COL_STORAGE)
        processor = self._get_combo_text(row, self.COL_PROCESSOR)
        location = self._get_combo_text(row, self.COL_LOCATION)
        status = self._get_combo_text(row, self.COL_STATUS)
        quantity_text = self._get_text(row, self.COL_QTY) or "0"
        try:
            quantity = int(quantity_text)
        except ValueError:
            quantity = 0

        if not serial:
            return

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO items (device_type, name, make, department, serial,
                               os, windows_version, model, ram, storage, processor, barcode,
                               location, status, quantity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(serial) DO
            UPDATE SET
                device_type=excluded.device_type,
                name =excluded.name,
                make=excluded.make,
                department=excluded.department,
                os=excluded.os,
                windows_version=excluded.windows_version,
                model=excluded.model,
                ram=excluded.ram,
                storage=excluded.storage,
                processor=excluded.processor,
                barcode=excluded.barcode,
                location=excluded.location,
                status=excluded.status,
                quantity=excluded.quantity
            """,
            (
                device_type,
                name,
                make,
                dept,
                serial,
                os_val,
                winver,
                model,
                ram,
                storage,
                processor,
                barcode_payload,
                location,
                status,
                quantity,
            ),
        )

        conn.commit()
        conn.close()
        write_encrypted_copy(delete_plaintext=False)

    # ---- Scan / IN / OUT ----

    def handle_scan(self, direction: str):
        """
        Handles:
        - Encrypted QR payloads starting with ENC_PREFIX ("ENC1:")
        - Plain QR / encoded payload: 11-field string with "$"
        - Plain serial / barcode text
        """
        raw_text = self.scan_edit.text().strip()
        if not raw_text:
            return

        payload = raw_text

        # If scanner returns only the token (no ENC1:), treat it as encrypted
        if not payload.startswith(ENC_PREFIX) and payload.count(".") == 2:
            payload = ENC_PREFIX + payload

        if payload.startswith(ENC_PREFIX):
            enc_token = payload[len(ENC_PREFIX):].strip()
            try:
                f = _get_fernet()
                decrypted_bytes = f.decrypt(enc_token.encode("utf-8"))
                payload = decrypted_bytes.decode("utf-8")
            except InvalidToken:
                QMessageBox.warning(
                    self,
                    "Scan",
                    "Unable to decrypt QR code.\n\n"
                    "Check that ITINV_DB_KEY and db_salt.bin match between the "
                    "QR generator app and this Cipher Asset app.",
                )
                self.scan_edit.clear()
                return

        conn = get_db_connection()
        cur = conn.cursor()

        # ---- Encoded payload with "$" ----
        if QR_DELIM in payload:
            parts = payload.split(QR_DELIM)
            while len(parts) < QR_FIELD_COUNT:
                parts.append("")

            (
                device_type,
                name,
                make,
                department,
                serial,
                os_val,
                winver,
                model,
                ram,
                storage,
                processor,
                location_code,
                status_code,
            ) = [p.strip() for p in parts[:QR_FIELD_COUNT]]

            for val, lst in [
                (device_type, self.DEVICE_VALUES),
                (name, self.NAME_VALUES),
                (make, self.MAKE_VALUES),
                (department, self.DEPT_VALUES),
                (os_val, self.OS_VALUES),
                (winver, self.WINVER_VALUES),
                (model, self.MODEL_VALUES),
                (ram, self.RAM_VALUES),
                (storage, self.STORAGE_VALUES),
            ]:
                if val and val not in lst:
                    lst.append(val)


            if not serial:
                QMessageBox.warning(
                    self, "Scan", "Serial # is missing in the encoded payload."
                )
                conn.close()
                return

            if model and model not in self.MODEL_VALUES:
                self.MODEL_VALUES.append(model)

            cur.execute(
                "SELECT quantity, location, status FROM items WHERE serial = ?",
                (serial,),
            )
            row = cur.fetchone()
            current_qty = row["quantity"] if row else 0
            current_location = row["location"] if row else ""
            current_status = row["status"] if row else ""

            mode = direction  # "in" or "out"

            if mode == "in":
                new_qty = current_qty + 1
            else:
                new_qty = max(0, current_qty - 1)

            if row:
                location = location_code or current_location or ""
                status = status_code or current_status or ""
            else:
                location = location_code
                status = status_code

            cur.execute(
                """
                INSERT INTO items (device_type, name, make, department, serial,
                                   os, windows_version, model, ram, storage, processor, barcode,
                                   location, status, quantity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(serial) DO
                UPDATE SET
                    device_type=excluded.device_type,
                    name =excluded.name,
                    make=excluded.make,
                    department=excluded.department,
                    os=excluded.os,
                    windows_version=excluded.windows_version,
                    model=excluded.model,
                    ram=excluded.ram,
                    storage=excluded.storage,
                    processor=excluded.processor,
                    barcode=excluded.barcode,
                    location=excluded.location,
                    status=excluded.status,
                    quantity=excluded.quantity
                """,
                (
                    device_type,
                    name,
                    make,
                    department,
                    serial,
                    os_val,
                    winver,  # ✅ windows_version
                    model,
                    ram,  # ✅ ram
                    storage,
                    processor,
                    raw_text,  # ✅ store what was scanned (ENC1:...); payload is decrypted plaintext
                    location,
                    status,
                    new_qty,
                ),
            )


        # ---- Serial-only scan ----
        else:
            cur.execute(
                "SELECT * FROM items WHERE serial = ? OR barcode = ?",
                (payload, payload),
            )
            row = cur.fetchone()

            if not row:
                dlg = NewAssetFromScanDialog(self, scanned_serial=payload)
                if dlg.exec_() != QDialog.Accepted:
                    conn.close()
                    self.scan_edit.clear()
                    return

                data = dlg.data
                mode = direction  # "in" or "out"

                if mode == "in":
                    new_qty = 1
                else:
                    new_qty = 0

                cur.execute(
                    """
                    INSERT INTO items (
                        device_type, name, make, department, serial,
                        os, model, storage, processor, barcode,
                        location, status, quantity
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        data["device_type"],
                        data["name"],
                        data["make"],
                        data["department"],
                        data["serial"],
                        data["os"],
                        data["windows_version"],
                        data["model"],
                        data["ram"],
                        data["storage"],
                        data["processor"],
                        data["barcode"],
                        data["location"],
                        data["status"],
                        new_qty,
                    ),
                )
            else:
                serial = row["serial"]
                current_qty = row["quantity"] or 0
                delta = 1 if direction == "in" else -1
                new_qty = max(0, current_qty + delta)
                cur.execute(
                    "UPDATE items SET quantity = ? WHERE serial = ?",
                    (new_qty, serial),
                )

        conn.commit()
        conn.close()
        self.scan_edit.clear()
        self.reload_from_db()
        write_encrypted_copy(delete_plaintext=False)

    def handle_scan_safe(self, direction: str):
        try:
            self.handle_scan(direction)
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            QMessageBox.critical(
                self,
                "Scan Error (Crash prevented)",
                f"Something went wrong while scanning.\n\n{e}\n\n---\n{tb}"
            )
            try:
                self.scan_edit.clear()
            except Exception:
                pass


# ---------- New Asset From Scan dialog ----------

class NewAssetFromScanDialog(QDialog):
    """Dialog used when a serial-only barcode is scanned for a new asset."""

    def __init__(self, parent=None, scanned_serial: str = ""):
        super().__init__(parent)
        self.setWindowTitle("New Asset from Scan")
        self.setModal(True)
        self.resize(420, 360)
        self.data = {}

        form = QFormLayout()

        self.device_combo = QComboBox()
        self.device_combo.setEditable(True)
        self.device_combo.addItems(InventoryPage.DEVICE_VALUES)

        self.make_combo = QComboBox()
        self.make_combo.setEditable(True)
        self.make_combo.addItems(InventoryPage.MAKE_VALUES)

        self.department_combo = QComboBox()
        self.department_combo.setEditable(True)
        self.department_combo.addItems(InventoryPage.DEPT_VALUES)

        self.name_edit = QLineEdit()
        self.serial_edit = QLineEdit(scanned_serial)

        # Comboboxes
        self.os_combo = QComboBox()
        self.os_combo.addItems(InventoryPage.OS_VALUES)

        self.winver_combo = QComboBox()
        self.winver_combo.addItems(InventoryPage.WINVER_VALUES)

        self.model_combo = QComboBox()
        self.model_combo.addItems(InventoryPage.MODEL_VALUES)

        self.ram_combo = QComboBox()
        self.ram_combo.addItems(InventoryPage.RAM_VALUES)

        self.storage_combo = QComboBox()
        self.storage_combo.addItems(InventoryPage.STORAGE_VALUES)

        self.processor_combo = QComboBox()
        self.processor_combo.addItems(InventoryPage.PROCESSOR_VALUES)

        self.location_combo = QComboBox()
        self.location_combo.addItems(InventoryPage.LOCATION_VALUES)

        self.status_combo = QComboBox()
        self.status_combo.addItems(InventoryPage.STATUS_VALUES)
        idx = self.status_combo.findText("IN USE", Qt.MatchFixedString)
        if idx >= 0:
            self.status_combo.setCurrentIndex(idx)

        combo_style = """
        QComboBox {
            font-size: 13pt;
            padding: 6px;
            min-width: 220px;
        }
        QComboBox QAbstractItemView {
            font-size: 13pt;
            padding: 6px;
            min-width: 220px;
            selection-background-color: #0078D7;
        }
        QScrollBar:vertical {
            width: 18px;
        }
        """
        for combo in [
            self.device_combo,
            self.department_combo,
            self.os_combo,
            self.winver_combo,
            self.model_combo,
            self.ram_combo,
            self.storage_combo,
            self.processor_combo,
            self.location_combo,
            self.status_combo,
        ]:
            combo.setStyleSheet(combo_style)

        form.addRow("Device Type:", self.device_combo)
        form.addRow("Make:", self.make_combo)
        form.addRow("Department:", self.department_combo)
        form.addRow("Name / Label:", self.name_edit)
        form.addRow("Serial #:", self.serial_edit)
        form.addRow("OS:", self.os_combo)
        form.addRow("Windows Version:", self.winver_combo)
        form.addRow("Model:", self.model_combo)
        form.addRow("RAM:", self.ram_combo)
        form.addRow("Storage:", self.storage_combo)
        form.addRow("Processor:", self.processor_combo)
        form.addRow("Location:", self.location_combo)
        form.addRow("Status:", self.status_combo)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.on_accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout()
        layout.addLayout(form)
        layout.addWidget(buttons)
        self.setLayout(layout)

    def on_accept(self):
        serial = self.serial_edit.text().strip()
        if not serial:
            QMessageBox.warning(self, "New Asset", "Serial # is required.")
            return

        self.data = {
            "device_type": self.device_combo.currentText().strip(),
            "make": self.make_combo.currentText().strip(),
            "department": self.department_combo.currentText().strip(),
            "name": self.name_edit.text().strip(),
            "serial": serial,
            "os": self.os_combo.currentText().strip(),
            "windows_version": self.winver_combo.currentText().strip(),
            "model": self.model_combo.currentText().strip(),
            "ram": self.ram_combo.currentText().strip(),
            "storage": self.storage_combo.currentText().strip(),
            "processor": self.processor_combo.currentText().strip(),
            "location": self.location_combo.currentText().strip(),
            "status": self.status_combo.currentText().strip(),
            "barcode": serial,
        }

        self.accept()


# ---------- Maintenance dialogs ----------

class MaintenanceEditDialog(QDialog):
    """
    Dialog to add or edit a single maintenance / lifecycle event
    for a specific asset (by serial).
    """

    def __init__(self, parent=None, serial="", company="", location="", existing=None):
        super().__init__(parent)
        self.setWindowTitle("Maintenance Event")
        self.setModal(True)
        self.resize(420, 320)
        self.result_data = None

        self.serial = serial

        self.date_edit = QLineEdit()
        self.type_combo = QComboBox()
        self.company_edit = QLineEdit(company or "")
        self.location_edit = QLineEdit(location or "")
        self.notes_edit = QTextEdit()

        self.type_combo.addItems([
            "MAINTENANCE",
            "REPAIR",
            "DEPLOYED",
            "MOVED",
            "INSPECTION",
            "RETIREMENT",
            "OTHER",
        ])

        if existing is not None:
            self.date_edit.setText(existing["event_date"] or "")
            idx = self.type_combo.findText(existing["event_type"] or "", Qt.MatchFixedString)
            if idx >= 0:
                self.type_combo.setCurrentIndex(idx)
            self.company_edit.setText(existing["company"] or "")
            self.location_edit.setText(existing["location"] or "")
            self.notes_edit.setPlainText(existing["notes"] or "")
        else:
            from datetime import date
            self.date_edit.setText(date.today().isoformat())

        form = QFormLayout()
        form.addRow("Date (YYYY-MM-DD):", self.date_edit)
        form.addRow("Event type:", self.type_combo)
        form.addRow("Company:", self.company_edit)
        form.addRow("Location:", self.location_edit)
        form.addRow("Notes:", self.notes_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.on_accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout()
        layout.addLayout(form)
        layout.addWidget(buttons)
        self.setLayout(layout)

    def on_accept(self):
        date_str = self.date_edit.text().strip()
        event_type = self.type_combo.currentText().strip()

        if not date_str or not event_type:
            QMessageBox.warning(
                self, "Maintenance", "Date and Event type are required."
            )
            return

        self.result_data = {
            "serial": self.serial,
            "event_date": date_str,
            "event_type": event_type,
            "company": self.company_edit.text().strip(),
            "location": self.location_edit.text().strip(),
            "notes": self.notes_edit.toPlainText().strip(),
        }
        self.accept()


class MaintenanceDialog(QDialog):
    """
    Shows maintenance / lifecycle history for a given serial,
    and lets you add/edit/delete events.
    """

    def __init__(self, parent, serial: str, company: str = "", location: str = ""):
        super().__init__(parent)
        self.serial = serial
        self.default_company = company or ""
        self.default_location = location or ""

        self.setWindowTitle(f"Maintenance History – {serial}")
        self.resize(720, 420)

        layout = QVBoxLayout(self)

        header = QLabel(f"Maintenance / Lifecycle history for Serial: {serial}")
        header.setFont(QFont("Segoe UI", 10, QFont.Bold))
        layout.addWidget(header)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["Date", "Type", "Company", "Location", "Notes"]
        )
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)

        layout.addWidget(self.table)

        btn_row = QHBoxLayout()
        self.add_btn = QPushButton("Add")
        self.edit_btn = QPushButton("Edit")
        self.del_btn = QPushButton("Delete")
        self.close_btn = QPushButton("Close")

        self.add_btn.clicked.connect(self.add_record)
        self.edit_btn.clicked.connect(self.edit_record)
        self.del_btn.clicked.connect(self.delete_record)
        self.close_btn.clicked.connect(self.accept)

        btn_row.addWidget(self.add_btn)
        btn_row.addWidget(self.edit_btn)
        btn_row.addWidget(self.del_btn)
        btn_row.addStretch()
        btn_row.addWidget(self.close_btn)
        layout.addLayout(btn_row)

        self.reload_records()

    def reload_records(self):
        self.table.setRowCount(0)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, serial, company, location, event_date, event_type, notes
            FROM maintenance
            WHERE serial = ?
            ORDER BY event_date ASC, id ASC
            """,
            (self.serial,),
        )
        rows = cur.fetchall()
        conn.close()

        for r in rows:
            row = self.table.rowCount()
            self.table.insertRow(row)

            self.table.setItem(row, 0, QTableWidgetItem(r["event_date"] or ""))
            self.table.setItem(row, 1, QTableWidgetItem(r["event_type"] or ""))
            self.table.setItem(row, 2, QTableWidgetItem(r["company"] or ""))
            self.table.setItem(row, 3, QTableWidgetItem(r["location"] or ""))
            notes_item = QTableWidgetItem(r["notes"] or "")
            self.table.setItem(row, 4, notes_item)

            notes_item.setData(Qt.UserRole, r["id"])

    def _current_record_id(self):
        row = self.table.currentRow()
        if row < 0:
            return None
        item = self.table.item(row, 4)
        if not item:
            return None
        return item.data(Qt.UserRole)

    def add_record(self):
        dlg = MaintenanceEditDialog(
            self,
            serial=self.serial,
            company=self.default_company,
            location=self.default_location,
        )
        if dlg.exec_() != QDialog.Accepted or not dlg.result_data:
            return

        data = dlg.result_data
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO maintenance (serial, company, location, event_date, event_type, notes)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                data["serial"],
                data["company"],
                data["location"],
                data["event_date"],
                data["event_type"],
                data["notes"],
            ),
        )
        conn.commit()
        conn.close()

        self.reload_records()

    def edit_record(self):
        rec_id = self._current_record_id()
        if rec_id is None:
            QMessageBox.information(self, "Maintenance", "Select a record to edit.")
            return

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, serial, company, location, event_date, event_type, notes
            FROM maintenance
            WHERE id = ?
            """,
            (rec_id,),
        )
        row = cur.fetchone()
        conn.close()

        if not row:
            return

        dlg = MaintenanceEditDialog(
            self,
            serial=row["serial"],
            company=row["company"] or "",
            location=row["location"] or "",
            existing=row,
        )
        if dlg.exec_() != QDialog.Accepted or not dlg.result_data:
            return

        data = dlg.result_data
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE maintenance
            SET company = ?, location = ?, event_date = ?, event_type = ?, notes = ?
            WHERE id = ?
            """,
            (
                data["company"],
                data["location"],
                data["event_date"],
                data["event_type"],
                data["notes"],
                rec_id,
            ),
        )
        conn.commit()
        conn.close()

        self.reload_records()

    def delete_record(self):
        rec_id = self._current_record_id()
        if rec_id is None:
            QMessageBox.information(self, "Maintenance", "Select a record to delete.")
            return

        if QMessageBox.question(
            self,
            "Delete Maintenance Record",
            "Delete the selected maintenance event?",
            QMessageBox.Yes | QMessageBox.No,
        ) == QMessageBox.No:
            return

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM maintenance WHERE id = ?", (rec_id,))
        conn.commit()
        conn.close()

        self.reload_records()


# ---------- Dashboard page ----------

class DashboardPage(QWidget):
    def __init__(self, main_window):
        super().__init__(main_window)
        self.main_window = main_window

        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(30)

        row1 = QHBoxLayout()
        row1.setSpacing(30)
        row1.addWidget(self._make_tile("New File", "#f44336", self.main_window.on_new_file))
        row1.addWidget(
            self._make_tile("Continue File", "#ff9800", self.main_window.on_continue_file)
        )
        row1.addWidget(
            self._make_tile("Send / Receive", "#4caf50", self.main_window.on_send_receive)
        )
        layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.setSpacing(30)
        row2.addWidget(self._make_tile("Files", "#9c27b0", self.main_window.on_files))
        row2.addWidget(
            self._make_tile("Scan", "#00bcd4", self.main_window.show_inventory_page)
        )
        row2.addWidget(
            self._make_tile("Preferences", "#2196f3", self.main_window.on_preferences)
        )
        layout.addLayout(row2)

        # Third row — Maintenance + SharePoint snapshot
        row3 = QHBoxLayout()
        row3.setSpacing(30)
        row3.addWidget(
            self._make_tile("Maintenance", "#607d8b", self.main_window.show_maintenance_history)
        )
        row3.addWidget(
            self._make_tile("Publish Snapshot", "#795548", self.main_window.publish_snapshot_to_sharepoint)
        )
        row3.addStretch()
        layout.addLayout(row3)

    def _make_tile(self, text: str, color: str, handler):
        btn = QPushButton(text)
        btn.setMinimumSize(QSize(260, 140))
        btn.setFont(QFont("Segoe UI", 11, QFont.Bold))
        btn.clicked.connect(handler)
        btn.setStyleSheet(
            f"""
            QPushButton {{
                background-color: {color};
                border-radius: 12px;
                color: white;
            }}
            QPushButton:hover {{
                background-color: {color}CC;
            }}
            """
        )
        return btn


# ---------- WiFi Scanner dialog (placeholder) ----------

class WifiScannerDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("WiFi Scanner")
        self.setModal(True)
        self.resize(480, 260)

        layout = QVBoxLayout(self)

        info = QLabel(
            "WiFi Scan (desktop placeholder)\n\n"
            "- Connect WiFi: open system network settings.\n"
            "- WiFi Scan: simulate scan / show info.\n"
            "- Test Scan: quick connectivity test.\n"
        )
        info.setAlignment(Qt.AlignCenter)
        layout.addWidget(info)

        row1 = QHBoxLayout()
        row1.setSpacing(20)

        self.connect_btn = QPushButton("Connect WiFi")
        self.connect_btn.setMinimumSize(150, 80)
        self.connect_btn.clicked.connect(self.on_connect_wifi)

        self.scan_btn = QPushButton("WiFi Scan")
        self.scan_btn.setMinimumSize(150, 80)
        self.scan_btn.clicked.connect(self.on_wifi_scan)

        row1.addWidget(self.connect_btn)
        row1.addWidget(self.scan_btn)
        layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.setSpacing(20)

        self.test_btn = QPushButton("Test Scan")
        self.test_btn.setMinimumSize(150, 60)
        self.test_btn.clicked.connect(self.on_test_scan)

        self.back_btn = QPushButton("Back")
        self.back_btn.setMinimumSize(150, 60)
        self.back_btn.clicked.connect(self.reject)

        row2.addWidget(self.test_btn)
        row2.addWidget(self.back_btn)
        layout.addLayout(row2)

    def on_connect_wifi(self):
        system = platform.system().lower()
        if system == "darwin":
            QDesktopServices.openUrl(
                QUrl("x-apple.systempreferences:com.apple.preference.network")
            )
        else:
            QMessageBox.information(
                self,
                "Connect WiFi",
                "Open your system's network / WiFi settings to connect.",
            )

    def on_wifi_scan(self):
        QMessageBox.information(
            self,
            "WiFi Scan",
            "This desktop placeholder does not perform real WiFi scanning,\n"
            "but on mobile this would show nearby networks / devices.",
        )

    def on_test_scan(self):
        QMessageBox.information(
            self,
            "Test Scan",
            "Test scan completed.\n\n(Here you could run ping / connectivity tests.)",
        )


# ---------- Login / user management dialogs ----------

class SetupAdminDialog(QDialog):
    """First-run dialog to create initial admin user."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Initial Admin Setup")
        self.setModal(True)
        self.resize(360, 220)

        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("admin")
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.confirm_edit = QLineEdit()
        self.confirm_edit.setEchoMode(QLineEdit.Password)
        self.admin_checkbox = QCheckBox("Make this user an administrator")
        self.admin_checkbox.setChecked(True)

        form = QFormLayout()
        form.addRow("Username:", self.username_edit)
        form.addRow("Password:", self.password_edit)
        form.addRow("Confirm password:", self.confirm_edit)
        form.addRow("", self.admin_checkbox)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.on_accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout()
        layout.addLayout(form)
        layout.addWidget(buttons)
        self.setLayout(layout)

    def on_accept(self):
        username = self.username_edit.text().strip() or "admin"
        pwd = self.password_edit.text()
        confirm = self.confirm_edit.text()

        if not pwd:
            QMessageBox.warning(self, "Admin Setup", "Password cannot be empty.")
            return
        if pwd != confirm:
            QMessageBox.warning(self, "Admin Setup", "Passwords do not match.")
            return

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) AS c FROM users WHERE username = ?", (username,)
        )
        if cur.fetchone()["c"] > 0:
            conn.close()
            QMessageBox.warning(
                self, "Admin Setup", "That username already exists. Choose another."
            )
            return

        cur.execute(
            "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
            (username, hash_password(pwd), 1 if self.admin_checkbox.isChecked() else 0),
        )
        conn.commit()
        conn.close()

        write_encrypted_copy(delete_plaintext=False)

        QMessageBox.information(
            self,
            "Admin Setup",
            f"Admin user '{username}' created. Use these credentials to log in.",
        )
        self.accept()


class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Login")
        self.setModal(True)
        self.resize(320, 180)
        self.user_record = None

        self.username_edit = QLineEdit()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)

        form = QFormLayout()
        form.addRow("Username:", self.username_edit)
        form.addRow("Password:", self.password_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.on_login)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout()
        layout.addLayout(form)
        layout.addWidget(buttons)
        self.setLayout(layout)

    def on_login(self):
        username = self.username_edit.text().strip()
        pwd = self.password_edit.text()

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        conn.close()

        if not row or not verify_password(row["password_hash"], pwd):
            QMessageBox.warning(self, "Login", "Invalid username or password.")
            return

        self.user_record = row
        self.accept()


class ManageUsersDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Manage Users")
        self.setModal(True)
        self.resize(520, 320)

        layout = QVBoxLayout(self)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["ID", "Username", "Is Admin"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.setColumnWidth(0, 50)
        self.table.setColumnWidth(2, 80)

        layout.addWidget(self.table)

        btn_row = QHBoxLayout()
        self.add_btn = QPushButton("Add User")
        self.reset_btn = QPushButton("Reset Password")
        self.delete_btn = QPushButton("Delete User")
        self.close_btn = QPushButton("Close")

        self.add_btn.clicked.connect(self.add_user)
        self.reset_btn.clicked.connect(self.reset_password)
        self.delete_btn.clicked.connect(self.delete_user)
        self.close_btn.clicked.connect(self.accept)

        btn_row.addWidget(self.add_btn)
        btn_row.addWidget(self.reset_btn)
        btn_row.addWidget(self.delete_btn)
        btn_row.addStretch()
        btn_row.addWidget(self.close_btn)
        layout.addLayout(btn_row)

        self.reload()

    def reload(self):
        self.table.setRowCount(0)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, username, is_admin FROM users ORDER BY username")
        rows = cur.fetchall()
        conn.close()

        for r in rows:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(str(r["id"])))
            self.table.setItem(row, 1, QTableWidgetItem(r["username"]))
            self.table.setItem(row, 2, QTableWidgetItem("Yes" if r["is_admin"] else "No"))

    def _selected_user_id(self):
        row = self.table.currentRow()
        if row < 0:
            return None
        item = self.table.item(row, 0)
        return int(item.text()) if item else None

    def add_user(self):
        dlg = SetupAdminDialog(self)
        dlg.setWindowTitle("Add User")
        dlg.admin_checkbox.setText("Make this user an administrator")
        if dlg.exec_() == QDialog.Accepted:
            self.reload()

    def reset_password(self):
        user_id = self._selected_user_id()
        if not user_id:
            QMessageBox.information(self, "Reset Password", "Select a user first.")
            return

        pwd1, ok1 = QInputDialog.getText(
            self, "Reset Password", "New password:", QLineEdit.Password
        )
        if not ok1 or not pwd1:
            return
        pwd2, ok2 = QInputDialog.getText(
            self, "Reset Password", "Confirm password:", QLineEdit.Password
        )
        if not ok2 or pwd1 != pwd2:
            QMessageBox.warning(self, "Reset Password", "Passwords do not match.")
            return

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(pwd1), user_id),
        )
        conn.commit()
        conn.close()
        write_encrypted_copy(delete_plaintext=False)
        QMessageBox.information(self, "Reset Password", "Password updated.")

    def delete_user(self):
        user_id = self._selected_user_id()
        if not user_id:
            QMessageBox.information(self, "Delete User", "Select a user first.")
            return

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT username, is_admin FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return

        username = row["username"]
        is_admin = bool(row["is_admin"])

        if QMessageBox.question(
            self,
            "Delete User",
            f"Delete user '{username}'?",
            QMessageBox.Yes | QMessageBox.No,
        ) == QMessageBox.No:
            conn.close()
            return

        if is_admin:
            cur.execute("SELECT COUNT(*) AS c FROM users WHERE is_admin = 1")
            if cur.fetchone()["c"] <= 1:
                conn.close()
                QMessageBox.warning(
                    self,
                    "Delete User",
                    "You cannot delete the last admin user.",
                )
                return

        cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        write_encrypted_copy(delete_plaintext=False)
        self.reload()


# ---------- Main window ----------
class MaintenanceHistoryPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent

        layout = QVBoxLayout(self)

        title = QLabel("Live Maintenance History")
        title.setFont(QFont("Segoe UI", 12, QFont.Bold))
        layout.addWidget(title)

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText(
            "Search by Serial, Company, Location, Event Type..."
        )
        self.search_edit.textChanged.connect(self.apply_filter)
        layout.addWidget(self.search_edit)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["Serial", "Event Type", "Company", "Location", "Date", "Notes"]
        )
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

        btn_row = QHBoxLayout()
        self.add_btn = QPushButton("Add")
        self.edit_btn = QPushButton("Edit")
        self.delete_btn = QPushButton("Delete")
        self.refresh_btn = QPushButton("Refresh")

        self.add_btn.clicked.connect(self.add_record)
        self.edit_btn.clicked.connect(self.edit_selected)
        self.delete_btn.clicked.connect(self.delete_selected)
        self.refresh_btn.clicked.connect(self.reload)

        btn_row.addWidget(self.add_btn)
        btn_row.addWidget(self.edit_btn)
        btn_row.addWidget(self.delete_btn)
        btn_row.addStretch()
        btn_row.addWidget(self.refresh_btn)
        layout.addLayout(btn_row)

        self.reload()

    def reload(self):
        self.table.setRowCount(0)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, serial, event_type, company, location, event_date, notes
            FROM maintenance
            ORDER BY event_date DESC, id DESC
            """
        )
        rows = cur.fetchall()
        conn.close()

        for r in rows:
            row = self.table.rowCount()
            self.table.insertRow(row)

            self.table.setItem(row, 0, QTableWidgetItem(r["serial"] or ""))
            self.table.setItem(row, 1, QTableWidgetItem(r["event_type"] or ""))
            self.table.setItem(row, 2, QTableWidgetItem(r["company"] or ""))
            self.table.setItem(row, 3, QTableWidgetItem(r["location"] or ""))
            self.table.setItem(row, 4, QTableWidgetItem(r["event_date"] or ""))

            notes_item = QTableWidgetItem(r["notes"] or "")
            notes_item.setData(Qt.UserRole, r["id"])
            self.table.setItem(row, 5, notes_item)

        self.apply_filter()

    def apply_filter(self):
        text = self.search_edit.text().lower().strip()
        for row in range(self.table.rowCount()):
            visible = False
            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                if item and text in item.text().lower():
                    visible = True
                    break
            self.table.setRowHidden(row, not visible)

    def _current_record_id(self):
        row = self.table.currentRow()
        if row < 0:
            return None
        item = self.table.item(row, 5)
        return item.data(Qt.UserRole) if item else None

    def add_record(self):
        dlg = MaintenanceEditDialog(self)
        if dlg.exec_() != QDialog.Accepted or not dlg.result_data:
            return

        data = dlg.result_data
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO maintenance (serial, company, location, event_date, event_type, notes)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                data["serial"],
                data["company"],
                data["location"],
                data["event_date"],
                data["event_type"],
                data["notes"],
            ),
        )
        conn.commit()
        conn.close()
        self.reload()

    def edit_selected(self):
        rec_id = self._current_record_id()
        if not rec_id:
            return

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM maintenance WHERE id = ?", (rec_id,))
        row = cur.fetchone()
        conn.close()

        dlg = MaintenanceEditDialog(
            self,
            serial=row["serial"],
            company=row["company"],
            location=row["location"],
            existing=row,
        )

        if dlg.exec_() != QDialog.Accepted:
            return

        data = dlg.result_data
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE maintenance
            SET serial=?, company=?, location=?, event_date=?, event_type=?, notes=?
            WHERE id=?
            """,
            (
                data["serial"],
                data["company"],
                data["location"],
                data["event_date"],
                data["event_type"],
                data["notes"],
                rec_id,
            ),
        )
        conn.commit()
        conn.close()
        self.reload()

    def delete_selected(self):
        rec_id = self._current_record_id()
        if not rec_id:
            return

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM maintenance WHERE id = ?", (rec_id,))
        conn.commit()
        conn.close()
        self.reload()

class MainWindow(QMainWindow):
    def __init__(self, current_user: sqlite3.Row):
        super().__init__()
        self.current_user = current_user
        self.is_admin = bool(current_user["is_admin"]) if current_user else False

        self.setWindowTitle(APP_NAME)
        self.resize(1200, 700)

        self.settings = QSettings(ORG_NAME, APP_NAME)
        self.current_theme = self.settings.value("theme", "light")
        self.current_accent = self.settings.value("accent", "blue")

        root = QWidget()
        self.setCentralWidget(root)
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)

        # left nav
        self.nav_list = QListWidget()
        self.nav_list.setFixedWidth(150)
        self.nav_list.setSpacing(2)
        self.nav_list.setStyleSheet(
            """
            QListWidget {
                background-color: #004c80;
                color: white;
                border: none;
            }
            QListWidget::item {
                padding: 8px 6px;
            }
            QListWidget::item:selected {
                background-color: #006bb3;
            }
            """
        )
        base_items = [
            "Dashboard",
            "New File",
            "Continue File",
            "Send / Receive",
            "Files",
            "WiFi Scanner",
            "Excel Columns",
            "Inventory",
            "Maintenance History",  # ✅ new nav item
            "Preferences",
        ]
        if self.is_admin:
            base_items.append("Manage Users")

        for name in base_items:
            self.nav_list.addItem(QListWidgetItem(name))

        self.nav_list.currentRowChanged.connect(self.on_nav_changed)
        root_layout.addWidget(self.nav_list)

        # right side
        right = QVBoxLayout()
        right.setContentsMargins(0, 0, 0, 0)
        root_layout.addLayout(right)

        top_bar = QHBoxLayout()
        top_bar.setContentsMargins(10, 6, 10, 6)

        self.title_label = QLabel(APP_NAME)
        self.title_label.setFont(QFont("Segoe UI", 11, QFont.Bold))
        top_bar.addWidget(self.title_label)
        top_bar.addStretch()

        user_label = QLabel(
            f"User: {self.current_user['username']} "
            f"({'Admin' if self.is_admin else 'User'})"
        )
        user_label.setStyleSheet("color: #666666; font-size: 9pt;")
        top_bar.addWidget(user_label)

        self.quit_button = QPushButton("Quit")
        self.quit_button.setMinimumWidth(70)
        self.quit_button.clicked.connect(self.close)
        top_bar.addWidget(self.quit_button)

        right.addLayout(top_bar)

        self.pages = QStackedWidget()
        right.addWidget(self.pages)

        self.dashboard_page = DashboardPage(self)
        self.inventory_page = InventoryPage(self)
        self.maintenance_history_page = MaintenanceHistoryPage(self)  # ✅ ADD THIS

        self.pages.addWidget(self.dashboard_page)
        self.pages.addWidget(self.inventory_page)
        self.pages.addWidget(self.maintenance_history_page)  # ✅ ADD THIS

        self._build_menu()
        self.apply_theme(self.current_theme, self.current_accent)

        self.nav_list.setCurrentRow(0)
        self.pages.setCurrentWidget(self.dashboard_page)

    # ---- Navigation ----

    def on_nav_changed(self, row: int):
        item = self.nav_list.item(row)
        if not item:
            return
        text = item.text()

        if text == "Dashboard":
            self.pages.setCurrentWidget(self.dashboard_page)
        elif text == "Inventory":
            self.show_inventory_page()
        elif text == "Maintenance History":  # ✅ REQUIRED
            self.show_maintenance_history()
        elif text == "New File":
            self.on_new_file()
        elif text == "Continue File":
            self.on_continue_file()
        elif text == "Send / Receive":
            self.on_send_receive()
        elif text == "Files":
            self.on_files()
        elif text == "Preferences":
            self.on_preferences()
        elif text == "WiFi Scanner":
            self.on_wifi_scanner()
        elif text == "Excel Columns":
            self.on_excel_columns()
        elif text == "Manage Users":
            if self.is_admin:
                self.on_manage_users()
            else:
                QMessageBox.warning(
                    self,
                    "Access Denied",
                    "Only administrator accounts can manage users.",
                )
        else:
            QMessageBox.information(
                self,
                text,
                f"'{text}' is not implemented yet.\n\n"
                "Your main working screen is Inventory.",
            )

    def show_inventory_page(self):
        self.pages.setCurrentWidget(self.inventory_page)
        for i in range(self.nav_list.count()):
            if self.nav_list.item(i).text() == "Inventory":
                self.nav_list.setCurrentRow(i)
                break

    def show_maintenance_history(self):
        # ✅ SWITCH THE PAGE
        self.pages.setCurrentWidget(self.maintenance_history_page)

        # ✅ HIGHLIGHT THE NAV ITEM
        for i in range(self.nav_list.count()):
            if self.nav_list.item(i).text() == "Maintenance History":
                self.nav_list.setCurrentRow(i)
                break

        # ✅ AUTO-REFRESH DATA
        if hasattr(self.maintenance_history_page, "reload"):
            self.maintenance_history_page.reload()

    # ---- Cloud / web helpers ----

    def open_outlook_web(self):
        QDesktopServices.openUrl(QUrl("https://outlook.office.com/mail/"))

    def open_excel_web(self):
        QDesktopServices.openUrl(QUrl("https://excel.office.com"))

    def open_dropbox_web(self):
        QDesktopServices.openUrl(QUrl("https://www.dropbox.com/home"))

    def open_google_drive_web(self):
        QDesktopServices.openUrl(QUrl("https://drive.google.com/drive/my-drive"))

    def open_onedrive_web(self):
        QDesktopServices.openUrl(QUrl("https://onedrive.live.com"))

    # ---- Top-level actions ----

    def on_new_file(self):
        reply = QMessageBox.question(
            self,
            "New File",
            "Start a new inventory file?\n\n"
            "This will DELETE all items from the local database.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.No:
            return

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM items")
        conn.commit()
        conn.close()

        try:
            if os.path.exists(ENC_DB_PATH):
                os.remove(ENC_DB_PATH)
        except OSError:
            pass

        self.inventory_page.reload_from_db()
        write_encrypted_copy(delete_plaintext=False)
        self.show_inventory_page()

    def on_continue_file(self):
        self.show_inventory_page()
        QMessageBox.information(
            self,
            "Continue File",
            "Continuing with the existing inventory database.",
        )

    def on_files(self):
        db_abs = os.path.abspath(DB_PATH)
        folder = os.path.dirname(db_abs) or os.getcwd()
        QDesktopServices.openUrl(QUrl.fromLocalFile(folder))
        QMessageBox.information(
            self,
            "Files",
            f"Your working database file is:\n\n{db_abs}\n\n"
            "The containing folder has been opened in your file explorer.\n\n"
            "(Remember: at rest the encrypted file is inventory.enc.)",
        )

    def on_send_receive(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Send / Receive")
        dlg.resize(520, 420)

        layout = QVBoxLayout(dlg)

        # --- Email / local files group ---
        email_box = QGroupBox("Email / Local Files")
        email_layout = QVBoxLayout(email_box)

        export_btn = QPushButton("Export inventory to CSV (for email / backup)")
        import_btn = QPushButton("Import inventory from CSV (restore / receive)")
        backup_btn = QPushButton("Backup encrypted database (inventory.enc)")
        sharepoint_btn = QPushButton("Publish snapshot to SharePoint (DB + CSV)")

        for b in (export_btn, import_btn, backup_btn, sharepoint_btn):
            b.setMinimumHeight(34)

        export_btn.clicked.connect(self.export_to_csv)
        import_btn.clicked.connect(self.import_from_csv)
        backup_btn.clicked.connect(self.backup_encrypted_db)
        sharepoint_btn.clicked.connect(self.publish_snapshot_to_sharepoint)

        email_layout.addWidget(export_btn)
        email_layout.addWidget(import_btn)
        email_layout.addWidget(backup_btn)
        email_layout.addWidget(sharepoint_btn)

        layout.addWidget(email_box)

        # --- Cloud services group ---
        cloud_box = QGroupBox("Cloud Services")
        cloud_layout = QVBoxLayout(cloud_box)

        dropbox_up = QPushButton("Dropbox Upload")
        dropbox_down = QPushButton("Dropbox Download")
        gdrive_up = QPushButton("Google Drive Upload")
        gdrive_down = QPushButton("Google Drive Download")
        onedrive_up = QPushButton("OneDrive Upload")
        onedrive_down = QPushButton("OneDrive Download")

        for b in (
                dropbox_up,
                dropbox_down,
                gdrive_up,
                gdrive_down,
                onedrive_up,
                onedrive_down,
        ):
            b.setMinimumHeight(32)

        dropbox_up.clicked.connect(self.open_dropbox_web)
        dropbox_down.clicked.connect(self.open_dropbox_web)

        gdrive_up.clicked.connect(self.open_google_drive_web)
        gdrive_down.clicked.connect(self.open_google_drive_web)

        onedrive_up.clicked.connect(self.open_onedrive_web)
        onedrive_down.clicked.connect(self.open_onedrive_web)

        cloud_layout.addWidget(dropbox_up)
        cloud_layout.addWidget(dropbox_down)
        cloud_layout.addWidget(gdrive_up)
        cloud_layout.addWidget(gdrive_down)
        cloud_layout.addWidget(onedrive_up)
        cloud_layout.addWidget(onedrive_down)

        layout.addWidget(cloud_box)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)
        layout.addWidget(close_btn, alignment=Qt.AlignRight)

        dlg.exec_()

    def on_preferences(self):
        dlg = PreferencesDialog(self, self.current_theme, self.current_accent)
        if dlg.exec_() == QDialog.Accepted:
            self.current_theme = dlg.selected_theme()
            self.current_accent = dlg.selected_accent()
            self.apply_theme(self.current_theme, self.current_accent)
            self.settings.setValue("theme", self.current_theme)
            self.settings.setValue("accent", self.current_accent)

    def on_wifi_scanner(self):
        dlg = WifiScannerDialog(self)
        dlg.exec_()

    def on_manage_users(self):
        dlg = ManageUsersDialog(self)
        dlg.exec_()

    def on_excel_columns(self):
        self.open_excel_web()

    # ---- Internal helpers used by multiple exports ----

    def _write_inventory_csv_snapshot(self, csv_path: str):
        """
        Write the full inventory table to csv_path.
        Used by both the manual Export and the SharePoint snapshot.
        """
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT device_type, name, make, department, serial, os, windows_version, model, ram, storage,
                    processor, barcode, location, status, quantity
            FROM items
            ORDER BY device_type, name
            """
        )
        rows = cur.fetchall()
        conn.close()

        headers = [
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
            "Barcode",
            "Location",
            "Status",
            "Quantity",
        ]

        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for r in rows:
                writer.writerow(
                    [
                        r["device_type"] or "",
                        r["name"] or "",
                        r["make"] or "",
                        r["department"] or "",
                        r["serial"] or "",
                        r["os"] or "",
                        r["windows_version"] or "",
                        r["model"] or "",
                        r["ram"] or "",
                        r["storage"] or "",
                        r["processor"] or "",
                        r["barcode"] or "",
                        r["location"] or "",
                        r["status"] or "",
                        r["quantity"] or 0,
                    ]
                )

    def _write_maintenance_csv_snapshot(self, csv_path: str):
        """
        Write full maintenance / lifecycle history to csv_path.
        Used by both the manual Export and the SharePoint snapshot.
        """
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT m.serial,
                   i.device_type,
                   i.name,
                   i.make,
                   i.department,
                   i.location AS asset_location,
                   m.company,
                   m.location AS event_location,
                   m.event_date,
                   m.event_type,
                   m.notes
            FROM maintenance m
                     LEFT JOIN items i ON m.serial = i.serial
            ORDER BY m.serial, m.event_date, m.id
            """
        )
        rows = cur.fetchall()
        conn.close()

        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Serial",
                "Device Type",
                "Name",
                "Make",
                "Department",
                "Asset Location",
                "Event Company",
                "Event Location",
                "Event Date",
                "Event Type",
                "Notes",
            ])
            for r in rows:
                writer.writerow([
                    r["serial"] or "",
                    r["device_type"] or "",
                    r["name"] or "",
                    r["make"] or "",
                    r["department"] or "",
                    r["asset_location"] or "",
                    r["company"] or "",
                    r["event_location"] or "",
                    r["event_date"] or "",
                    r["event_type"] or "",
                    (r["notes"] or "").replace("\n", " "),
                ])


    # ---- CSV import / export ----

    def export_to_csv(self):
        """
        Export inventory + maintenance to CSV files in a folder the user chooses.
        GitHub-safe (no SharePoint paths, no org codes).
        """
        folder = QFileDialog.getExistingDirectory(self, "Choose export folder")
        if not folder:
            return

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        inv_path = os.path.join(folder, f"inventory_{ts}.csv")
        maint_path = os.path.join(folder, f"maintenance_{ts}.csv")

        try:
            self._write_inventory_csv_snapshot(inv_path)
            self._write_maintenance_csv_snapshot(maint_path)
        except Exception as e:
            QMessageBox.warning(self, "Export", f"Export failed:\n{e}")
            return

        QMessageBox.information(
            self,
            "Export Complete",
            f"Inventory CSV:\n{inv_path}\n\nMaintenance CSV:\n{maint_path}"
        )

    # ---- CSV import / export ----

    def export_maintenance_to_csv(self):
        """
        Manual export of ALL maintenance / lifecycle history to a single CSV,
        using the helper that also powers the SharePoint snapshot.
        """
        # Default filename – you can tweak this if you want
        ts = datetime.now().strftime("%Y%m%d_%H%M")
        default_name = f"maintenance_history_{ts}.csv"

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export maintenance history to CSV",
            default_name,
            "CSV files (*.csv);;All files (*.*)",
        )
        if not path:
            return

        try:
            self._write_maintenance_csv_snapshot(path)
        except Exception as e:
            QMessageBox.warning(
                self,
                "Export Maintenance",
                f"Failed to export maintenance history:\n{e}",
            )
            return

        QMessageBox.information(
            self,
            "Export Maintenance",
            f"Maintenance history exported to:\n{path}",
        )

    def import_from_csv(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Import inventory from CSV",
            "",
            "CSV files (*.csv);;All files (*.*)",
        )
        if not path:
            return

        if QMessageBox.question(
                self,
                "Import CSV",
                "Importing will replace existing rows for matching Serial #.\n"
                "Continue?",
                QMessageBox.Yes | QMessageBox.No,
        ) == QMessageBox.No:
            return

        conn = get_db_connection()
        cur = conn.cursor()

        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                serial = (row.get("Serial #") or "").strip()
                if not serial:
                    continue
                try:
                    quantity = int(row.get("Quantity", "0"))
                except ValueError:
                    quantity = 0

                cur.execute(
                    """
                    INSERT INTO items (device_type, name, make, department, serial, os, windows_version, model, ram,
                                       storage,
                                       processor, barcode, location, status, quantity)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(serial) DO
                    UPDATE SET
                        device_type=excluded.device_type,
                        name =excluded.name,
                        make=excluded.make,
                        department=excluded.department,
                        os=excluded.os,
                        windows_version=excluded.windows_version,
                        model=excluded.model,
                        ram=excluded.ram,
                        storage=excluded.storage,
                        processor=excluded.processor,
                        barcode=excluded.barcode,
                        location=excluded.location,
                        status=excluded.status,
                        quantity=excluded.quantity
                    """,
                    (
                        row.get("Device Type", ""),
                        row.get("Name", ""),
                        row.get("Make", ""),
                        row.get("Department", ""),
                        serial,
                        row.get("OS", ""),
                        row.get("Windows Version", ""),
                        row.get("Model", ""),
                        row.get("RAM", ""),
                        row.get("Storage", ""),
                        row.get("Processor", ""),
                        row.get("Barcode", ""),
                        row.get("Location", ""),
                        row.get("Status", ""),
                        quantity,
                    ),
                )

        conn.commit()
        conn.close()
        self.inventory_page.reload_from_db()
        write_encrypted_copy(delete_plaintext=False)
        QMessageBox.information(self, "Import", f"Inventory imported from:\n{path}")



    def backup_encrypted_db(self):
        """
        Ensure we have an up-to-date encrypted copy (inventory.enc),
        then let the user save a copy of it.
        """
        write_encrypted_copy(delete_plaintext=False)

        if not os.path.exists(ENC_DB_PATH):
            QMessageBox.warning(
                self,
                "Backup",
                "No encrypted database file was found.",
            )
            return

        default_name = "inventory_backup.enc"
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save encrypted database backup",
            default_name,
            "Encrypted DB (*.enc);;All files (*.*)",
        )
        if not path:
            return

        try:
            shutil.copy2(ENC_DB_PATH, path)
        except Exception as e:
            QMessageBox.warning(
                self,
                "Backup",
                f"Failed to save backup:\n{e}",
            )
            return

        QMessageBox.information(
            self,
            "Backup",
            f"Encrypted database backup saved to:\n{path}\n\n"
            "You can upload this file to OneDrive/SharePoint/Dropbox.",
        )

    def publish_snapshot_to_sharepoint(self):
        """
        1) Make sure inventory.enc is up-to-date
        2) For EACH location code (HQ-01, WH-02, BR-03, REMOTE, ...)
           copy inventory.enc into the SharePoint 'Master-Database' folder using
           that location code as the prefix.
        3) Export INVENTORY + MAINTENANCE CSV snapshots into 'Daily-Exports',
           one pair of files per LOCATION code.
        All of this happens in the local OneDrive-synced path so
        SharePoint gets updated automatically.
        """
        ok, err = ensure_sharepoint_repo_folders()
        if not ok:
            QMessageBox.warning(
                self,
                "SharePoint Snapshot",
                "Could not access the SharePoint repository folder.\n\n"
                f"Details: {err}\n\n"
                "Check that OneDrive is running and the IT Support library "
                "is synced to this PC.",
            )
            return

        # 1) Ensure encrypted DB is current
        write_encrypted_copy(delete_plaintext=False)

        if not os.path.exists(ENC_DB_PATH):
            QMessageBox.warning(
                self,
                "SharePoint Snapshot",
                "No encrypted database (inventory.enc) was found.\n"
                "Try saving some inventory first.",
            )
            return

        from datetime import datetime
        from collections import defaultdict

        now = datetime.now()
        timestamp = now.strftime("%Y%m%d_%H%M")

        # ---- Load data and group by LOCATION ----
        conn = get_db_connection()
        cur = conn.cursor()

        # INVENTORY grouped by items.location
        cur.execute(
            """
            SELECT device_type,
                   name,
                   make,
                   department, 
                   serial,
                   os,
                   windows_version, 
                   model,
                   ram, 
                   storage,
                   processor,
                   barcode,
                   location,
                   status,
                   quantity
            FROM items
            """
        )
        inv_rows = cur.fetchall()

        inv_by_loc = defaultdict(list)
        for r in inv_rows:
            loc = (r["location"] or "").strip().upper() or "UNASSIGNED"
            inv_by_loc[loc].append(r)

        # MAINTENANCE grouped by maintenance.location (event) or asset_location
        cur.execute(
            """
            SELECT m.serial,
                   i.device_type,
                   i.name,
                   i.make,
                   i.department,
                   i.location AS asset_location,
                   m.company,
                   m.location AS event_location,
                   m.event_date,
                   m.event_type,
                   m.notes
            FROM maintenance m
                     LEFT JOIN items i ON m.serial = i.serial
            """
        )
        maint_rows = cur.fetchall()
        conn.close()

        maint_by_loc = defaultdict(list)
        for r in maint_rows:
            loc = (r["event_location"] or r["asset_location"] or "").strip().upper() or "UNASSIGNED"
            maint_by_loc[loc].append(r)

        # union of all locations that appear in either table
        all_locations = sorted(set(inv_by_loc.keys()) | set(maint_by_loc.keys()))

        if not all_locations:
            QMessageBox.information(
                self,
                "SharePoint Snapshot",
                "No inventory or maintenance records found to export.",
            )
            return

        # 2) Copy encrypted DB into Master-Database for EACH location code
        enc_paths = []
        try:
            for loc_code in all_locations:
                # e.g. "HQ-01, WH-02, BR-03, REMOTE"
                loc_prefix = loc_code.replace(" ", "_")

                latest_name = f"{loc_prefix}_inventory_latest.enc"
                dated_name = f"{loc_prefix}_inventory_{timestamp}.enc"

                latest_path = os.path.join(REPO_DB_DIR, latest_name)
                dated_path = os.path.join(REPO_DB_DIR, dated_name)

                shutil.copy2(ENC_DB_PATH, latest_path)
                shutil.copy2(ENC_DB_PATH, dated_path)

                enc_paths.append(latest_path)
                enc_paths.append(dated_path)
        except Exception as e:
            QMessageBox.warning(
                self,
                "SharePoint Snapshot",
                f"Failed to copy encrypted DB to repository:\n{e}",
            )
            return

        # 3) CSV snapshots per location into Daily-Exports
        inv_headers = [
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
            "Barcode",
            "Location",
            "Status",
            "Quantity",
        ]

        maint_headers = [
            "Serial",
            "Device Type",
            "Name",
            "Make",
            "Department",
            "Asset Location",
            "Event Company",
            "Event Location",
            "Event Date",
            "Event Type",
            "Notes",
        ]

        csv_paths = []

        for loc_code in all_locations:
            loc_prefix = loc_code.replace(" ", "_")

            # INVENTORY CSV for this location (if any rows)
            rows_for_loc = inv_by_loc.get(loc_code, [])
            if rows_for_loc:
                inv_name = f"{loc_prefix}_inventory_{timestamp}.csv"
                inv_path = os.path.join(REPO_EXPORT_DIR, inv_name)
                with open(inv_path, "w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    w.writerow(inv_headers)
                    for r in rows_for_loc:
                        w.writerow(
                            [
                                r["device_type"] or "",
                                r["name"] or "",
                                r["make"] or "",
                                r["department"] or "",
                                r["serial"] or "",
                                r["os"] or "",
                                r["windows_version"] or "",
                                r["model"] or "",
                                r["ram"] or "",
                                r["storage"] or "",
                                r["processor"] or "",
                                r["barcode"] or "",
                                r["location"] or "",
                                r["status"] or "",
                                r["quantity"] or 0,
                            ]
                        )
                csv_paths.append(inv_path)

            # MAINTENANCE CSV for this location (if any rows)
            m_rows_for_loc = maint_by_loc.get(loc_code, [])
            if m_rows_for_loc:
                maint_name = f"{loc_prefix}_maintenance_{timestamp}.csv"
                maint_path = os.path.join(REPO_EXPORT_DIR, maint_name)
                with open(maint_path, "w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    w.writerow(maint_headers)
                    for r in m_rows_for_loc:
                        w.writerow(
                            [
                                r["serial"] or "",
                                r["device_type"] or "",
                                r["name"] or "",
                                r["make"] or "",
                                r["department"] or "",
                                r["asset_location"] or "",
                                r["company"] or "",
                                r["event_location"] or "",
                                r["event_date"] or "",
                                r["event_type"] or "",
                                (r["notes"] or "").replace("\n", " "),
                            ]
                        )
                csv_paths.append(maint_path)

        enc_list = "\n  ".join(enc_paths) if enc_paths else "  (none)"
        csv_list = "\n  ".join(csv_paths) if csv_paths else "  (none)"

        if VERBOSE_POPUPS:
            # ✅ Detailed message for testing
            QMessageBox.information(
                self,
                "SharePoint Snapshot",
                "Snapshot published to SharePoint repository.\n\n"
                "Encrypted DB copies:\n"
                f"{enc_list}\n\n"
                "CSV snapshots created:\n"
                f"{csv_list}\n\n"
                "These files were written to your local synced folder.\n"
                "If that folder is connected to OneDrive/SharePoint (or similar), "
                "it will upload them automatically.",
            )
        else:
            # ✅ Minimal, non-sensitive message for production
            QMessageBox.information(
                self,
                "SharePoint Snapshot",
                "Snapshot published.\n\n"
                "Files will sync automatically to the IT Support "
                "SharePoint Inventory-Repository.",
            )

    # ---- Theme / accent ----

    def apply_theme(self, theme: str, accent: str):
        theme = (theme or "light").lower()
        accent = (accent or "blue").lower()

        accent_colors = {
            "blue": "#1976d2",
            "green": "#2e7d32",
            "orange": "#ef6c00",
            "purple": "#7b1fa2",
            "red": "#c62828",
            "gray": "#546e7a",
        }
        accent_color = accent_colors.get(accent, "#1976d2")

        if theme == "dark":
            bg = "#262626"
            fg = "#f0f0f0"
            table_bg = "#303030"
            alt_bg = "#383838"
        else:
            bg = "#f4f5f7"
            fg = "#202020"
            table_bg = "#ffffff"
            alt_bg = "#f0f0f0"

        self.setStyleSheet(
            f"""
            QMainWindow {{
                background-color: {bg};
                color: {fg};
            }}
            QWidget {{
                background-color: {bg};
                color: {fg};
                font-family: 'Segoe UI', Arial;
                font-size: 10pt;
            }}
            QLabel {{
                color: {fg};
            }}
            QTableWidget {{
                background-color: {table_bg};
                alternate-background-color: {alt_bg};
                gridline-color: #cccccc;
            }}
            QHeaderView::section {{
                background-color: {accent_color};
                color: white;
                padding: 4px;
                border: none;
            }}
            QPushButton {{
                background-color: {accent_color};
                color: white;
                border-radius: 4px;
                padding: 4px 10px;
            }}
            QPushButton:hover {{
                background-color: {accent_color}CC;
            }}
            QLineEdit, QComboBox {{
                background-color: {table_bg};
                border: 1px solid #b0bec5;
                border-radius: 3px;
                padding: 2px 4px;
            }}
            """
        )

    # ---- Menu ----

    def _build_menu(self):
        bar = self.menuBar()
        file_menu = bar.addMenu("&File")

        new_act = file_menu.addAction("New File")
        new_act.triggered.connect(self.on_new_file)

        cont_act = file_menu.addAction("Continue File")
        cont_act.triggered.connect(self.on_continue_file)

        file_menu.addSeparator()
        export_act = file_menu.addAction("Export to CSV")
        export_act.triggered.connect(self.export_to_csv)
        import_act = file_menu.addAction("Import from CSV")
        import_act.triggered.connect(self.import_from_csv)

        maint_export_act = file_menu.addAction("Export maintenance to CSV")
        maint_export_act.triggered.connect(self.export_maintenance_to_csv)

        file_menu.addSeparator()
        backup_act = file_menu.addAction("Backup encrypted database")
        backup_act.triggered.connect(self.backup_encrypted_db)

        sp_snapshot_act = file_menu.addAction("Publish snapshot to SharePoint")
        sp_snapshot_act.triggered.connect(self.publish_snapshot_to_sharepoint)

        file_menu.addSeparator()
        pref_act = file_menu.addAction("Preferences")
        pref_act.triggered.connect(self.on_preferences)

        file_menu.addSeparator()
        quit_act = file_menu.addAction("Quit")
        quit_act.triggered.connect(self.close)

        if self.is_admin:
            admin_menu = bar.addMenu("&Admin")
            manage_act = admin_menu.addAction("Manage Users")
            manage_act.triggered.connect(self.on_manage_users)

    # ---- Window close ----

    def closeEvent(self, event):
        try:
            write_encrypted_copy(delete_plaintext=True)
        finally:
            super().closeEvent(event)


# ---------- main ----------

def main():
    init_db()

    app = QApplication(sys.argv)

    # If there are no users yet, run initial admin setup
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM users")
    has_users = cur.fetchone()["c"] > 0
    conn.close()

    if not has_users:
        setup_dlg = SetupAdminDialog()
        if setup_dlg.exec_() != QDialog.Accepted:
            sys.exit(0)

    # Login
    login_dlg = LoginDialog()
    if login_dlg.exec_() != QDialog.Accepted:
        sys.exit(0)

    current_user = login_dlg.user_record
    window = MainWindow(current_user)
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()


