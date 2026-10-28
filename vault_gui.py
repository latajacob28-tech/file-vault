import sys
import os
import base64
from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTabWidget, QProgressBar, QFileDialog,
    QCheckBox, QSpinBox, QGraphicsOpacityEffect, QFrame)
from PySide6.QtCore import Qt, QTimer, QPropertyAnimation
from PySide6.QtGui import QFont
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

try:
    import qdarktheme
except ImportError:
    qdarktheme = None

SALT_SIZE = 16
ITERATIONS = 480000


def _key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_file(path, password):
    with open(path, "rb") as f:
        data = f.read()
    salt = os.urandom(SALT_SIZE)
    token = Fernet(_key(password, salt)).encrypt(data)
    out = path + ".vault"
    with open(out, "wb") as f:
        f.write(salt + token)
    os.remove(path)
    return out


def decrypt_file(path, password):
    with open(path, "rb") as f:
        blob = f.read()
    salt, token = blob[:SALT_SIZE], blob[SALT_SIZE:]
    data = Fernet(_key(password, salt)).decrypt(token)
    out = path[:-6] if path.endswith(".vault") else path + ".out"
    with open(out, "wb") as f:
        f.write(data)
    return out


class Vault(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setFixedWidth(440)
        self._drag = None
        self.enc_path = None
        self.dec_path = None
        self._anim = None

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        barframe = QFrame()
        barframe.setObjectName("titlebar")
        bar = QHBoxLayout(barframe)
        bar.setContentsMargins(16, 10, 10, 10)
        title = QLabel("\U0001F512  File Vault")
        title.setFont(QFont("Segoe UI", 12, QFont.DemiBold))
        close = QPushButton("\u2715")
        close.setFixedSize(30, 30)
        close.clicked.connect(self.close)
        bar.addWidget(title)
        bar.addStretch()
        bar.addWidget(close)
        root.addWidget(barframe)

        tabs = QTabWidget()
        tabs.addTab(self._encrypt_tab(), "Encrypt")
        tabs.addTab(self._decrypt_tab(), "Decrypt")
        wrap = QVBoxLayout()
        wrap.setContentsMargins(18, 10, 18, 18)
        wrap.addWidget(tabs)
        root.addLayout(wrap)

    def _encrypt_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(12)
        self.enc_file_label = QLabel("No file selected")
        self.enc_file_label.setStyleSheet("color:#8a93a0")
        pick = QPushButton("Choose a file to lock")
        pick.clicked.connect(self._pick_enc)
        self.enc_pw = QLineEdit()
        self.enc_pw.setEchoMode(QLineEdit.Password)
        self.enc_pw.setPlaceholderText("Password")
        show = QCheckBox("Show password")
        show.toggled.connect(lambda on: self.enc_pw.setEchoMode(
            QLineEdit.Normal if on else QLineEdit.Password))
        self.enc_btn = QPushButton("\U0001F512  Encrypt")
        self.enc_btn.clicked.connect(self._do_encrypt)
        self.enc_bar = QProgressBar()
        self.enc_bar.setTextVisible(False)
        self.enc_bar.hide()
        self.enc_status = QLabel("")
        self.enc_status.setWordWrap(True)
        for x in (pick, self.enc_file_label, self.enc_pw, show,
                  self.enc_btn, self.enc_bar, self.enc_status):
            lay.addWidget(x)
        lay.addStretch()
        return w

    def _decrypt_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(12)
        self.dec_file_label = QLabel("No .vault file selected")
        self.dec_file_label.setStyleSheet("color:#8a93a0")
        pick = QPushButton("Choose a .vault file to open")
        pick.clicked.connect(self._pick_dec)
        self.dec_pw = QLineEdit()
        self.dec_pw.setEchoMode(QLineEdit.Password)
        self.dec_pw.setPlaceholderText("Password")
        show = QCheckBox("Show password")
        show.toggled.connect(lambda on: self.dec_pw.setEchoMode(
            QLineEdit.Normal if on else QLineEdit.Password))
        optrow = QHBoxLayout()
        self.auto_cb = QCheckBox("Auto re-lock after")
        self.auto_spin = QSpinBox()
        self.auto_spin.setRange(1, 120)
        self.auto_spin.setValue(10)
        self.auto_spin.setSuffix(" min")
        optrow.addWidget(self.auto_cb)
        optrow.addWidget(self.auto_spin)
        optrow.addStretch()
        self.dec_btn = QPushButton("\U0001F513  Decrypt")
        self.dec_btn.clicked.connect(self._do_decrypt)
        self.dec_bar = QProgressBar()
        self.dec_bar.setTextVisible(False)
        self.dec_bar.hide()
        self.dec_status = QLabel("")
        self.dec_status.setWordWrap(True)
        for x in (pick, self.dec_file_label, self.dec_pw, show):
            lay.addWidget(x)
        lay.addLayout(optrow)
        for x in (self.dec_btn, self.dec_bar, self.dec_status):
            lay.addWidget(x)
        lay.addStretch()
        return w

    def _pick_enc(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose a file")
        if path:
            self.enc_path = path
            self.enc_file_label.setText(os.path.basename(path))
            self.enc_file_label.setStyleSheet("color:#d7dce2")

    def _pick_dec(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose a .vault file", "",
                                              "Vault files (*.vault);;All files (*)")
        if path:
            self.dec_path = path
            self.dec_file_label.setText(os.path.basename(path))
            self.dec_file_label.setStyleSheet("color:#d7dce2")

    def _run_progress(self, bar, on_done):
        bar.setValue(0)
        bar.show()
        self._p = 0
        t = QTimer(self)

        def step():
            self._p += 2
            bar.setValue(self._p)
            if self._p >= 100:
                t.stop()
                on_done()
        t.timeout.connect(step)
        t.start(40)

    def _fade(self, label, text, color):
        label.setText(text)
        label.setStyleSheet(f"color:{color}; font-weight:600")
        eff = QGraphicsOpacityEffect(label)
        label.setGraphicsEffect(eff)
        anim = QPropertyAnimation(eff, b"opacity")
        anim.setDuration(500)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.start()
        self._anim = anim

    def _do_encrypt(self):
        if not self.enc_path or not os.path.isfile(self.enc_path):
            self._fade(self.enc_status, "Choose a file first.", "#e08a8a")
            return
        if not self.enc_pw.text():
            self._fade(self.enc_status, "Enter a password.", "#e08a8a")
            return
        self.enc_status.setText("")
        self.enc_btn.setEnabled(False)
        pw = self.enc_pw.text()
        self._run_progress(self.enc_bar, lambda: self._finish_encrypt(pw))

    def _finish_encrypt(self, pw):
        try:
            out = encrypt_file(self.enc_path, pw)
        except Exception as ex:
            self._fade(self.enc_status, f"Error: {ex}", "#e08a8a")
            self.enc_btn.setEnabled(True)
            return
        self.enc_bar.hide()
        self.enc_path = None
        self.enc_file_label.setText("No file selected")
        self.enc_file_label.setStyleSheet("color:#8a93a0")
        self.enc_pw.clear()
        self.enc_btn.setEnabled(True)
        self._fade(self.enc_status,
                   f"\u2713 Locked \u2192 {os.path.basename(out)}  (original deleted)",
                   "#6bd38a")

    def _do_decrypt(self):
        if not self.dec_path or not os.path.isfile(self.dec_path):
            self._fade(self.dec_status, "Choose a .vault file first.", "#e08a8a")
            return
        if not self.dec_pw.text():
            self._fade(self.dec_status, "Enter a password.", "#e08a8a")
            return
        self.dec_status.setText("")
        self.dec_btn.setEnabled(False)
        pw = self.dec_pw.text()
        self._run_progress(self.dec_bar, lambda: self._finish_decrypt(pw))

    def _finish_decrypt(self, pw):
        try:
            out = decrypt_file(self.dec_path, pw)
        except InvalidToken:
            self._fade(self.dec_status, "Wrong password or the file was tampered with.", "#e08a8a")
            self.dec_bar.hide()
            self.dec_btn.setEnabled(True)
            return
        except Exception as ex:
            self._fade(self.dec_status, f"Error: {ex}", "#e08a8a")
            self.dec_bar.hide()
            self.dec_btn.setEnabled(True)
            return
        self.dec_bar.hide()
        self.dec_btn.setEnabled(True)
        self.dec_pw.clear()
        if self.auto_cb.isChecked():
            mins = self.auto_spin.value()
            self._fade(self.dec_status,
                       f"\u2713 Unlocked \u2192 {os.path.basename(out)}. Auto-locks in {mins} min.",
                       "#6bd38a")
            QTimer.singleShot(mins * 60000, lambda p=out, k=pw: self._auto_lock(p, k))
        else:
            self._fade(self.dec_status,
                       f"\u2713 Unlocked \u2192 {os.path.basename(out)}. Staying unlocked.",
                       "#6bd38a")

    def _auto_lock(self, path, pw):
        if os.path.isfile(path):
            try:
                encrypt_file(path, pw)
            except Exception:
                pass

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            self._drag = e.globalPosition().toPoint() - self.frameGeometry().topLeft()
            e.accept()

    def mouseMoveEvent(self, e):
        if self._drag is not None and e.buttons() & Qt.LeftButton:
            self.move(e.globalPosition().toPoint() - self._drag)
            e.accept()

    def mouseReleaseEvent(self, e):
        self._drag = None


app = QApplication(sys.argv)
if qdarktheme:
    try:
        qdarktheme.setup_theme("dark")
    except Exception:
        pass
win = Vault()
win.setStyleSheet(win.styleSheet() + """
#titlebar { background: #11151b; }
QPushButton { padding: 9px 14px; border-radius: 7px; }
QLineEdit { padding: 9px; border-radius: 7px; }
QProgressBar { height: 10px; border-radius: 5px; }
QProgressBar::chunk { background: #4b8cف4; border-radius: 5px; }
""".replace("4b8cف4", "4b8cf4"))
win.show()
sys.exit(app.exec())