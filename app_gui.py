"""WeChat Decrypt GUI — One-click decrypt / export messages / convert audio"""
import os
import sys
import subprocess
import threading
import sqlite3
import hashlib
import glob as globmod
import tkinter as tk
from tkinter import ttk, scrolledtext

# Ensure working directory is the script's directory (also works when packaged)
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)
os.environ["WECHAT_DECRYPT_APP_DIR"] = BASE_DIR


# ── Subtask entry point (when called with --task argument, execute the corresponding script directly) ──────────────────────

# Explicit imports: let PyInstaller collect all dependencies needed by sub-scripts
# (these scripts are dynamically loaded via exec, PyInstaller cannot auto-detect them)
import importlib.util  # noqa: F401 - used for dynamic loading
if False:  # noqa: never executed, only for PyInstaller dependency detection
    import sqlite3, hashlib, csv, json, re, glob, tempfile  # noqa: F401
    import xml.etree.ElementTree  # noqa: F401
    import functools, platform, ctypes, ctypes.wintypes  # noqa: F401
    import zstandard  # noqa: F401
    import pilk  # noqa: F401
    import Crypto, Crypto.Cipher, Crypto.Cipher.AES, Crypto.Util.Padding  # noqa: F401
    import wxwork_crypto  # noqa: F401
    import export_wxwork_messages  # noqa: F401


def _run_subtask(task: str):
    """Called in a subprocess, directly executes the corresponding script logic"""
    # Force stdout/stderr to UTF-8
    if sys.platform == "win32":
        for s in (sys.stdout, sys.stderr):
            if hasattr(s, "reconfigure"):
                s.reconfigure(encoding="utf-8", errors="replace")

    # onefile: _MEIPASS temp dir; onedir: _internal/; development: BASE_DIR
    if getattr(sys, "frozen", False):
        script_dir = getattr(sys, "_MEIPASS", os.path.join(os.path.dirname(sys.executable), "_internal"))
    else:
        script_dir = BASE_DIR

    # Allow import to find modules in the same directory as the script
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    if BASE_DIR not in sys.path:
        sys.path.insert(0, BASE_DIR)

    mapping = {
        "decrypt": "main.py",
        "export": "export_messages.py",
        "voice": "voice_to_mp3.py",
        "find_image_key": "find_image_key.py",
        "decrypt_sns": "decrypt_sns.py",
        "export_sns": "export_sns.py",
        "find_wxwork_keys": "find_wxwork_keys.py",
        "decrypt_wxwork": "decrypt_wxwork_db.py",
        "export_wxwork": "export_wxwork_messages.py",
    }
    script = mapping.get(task)
    if not script:
        print(f"Unknown task: {task}", flush=True)
        sys.exit(1)

    script_path = os.path.join(script_dir, script)
    if not os.path.exists(script_path):
        # Fall back to BASE_DIR in development mode
        script_path = os.path.join(BASE_DIR, script)
    if not os.path.exists(script_path):
        print(f"Script not found: {script_path}", flush=True)
        sys.exit(1)

    # Pass the decrypt command to main.py
    if task == "decrypt":
        sys.argv = ["main.py", "decrypt"]
    elif task == "find_image_key":
        sys.argv = ["find_image_key.py"]
    elif task == "find_wxwork_keys":
        sys.argv = ["find_wxwork_keys.py"]
    elif task == "decrypt_wxwork":
        sys.argv = ["decrypt_wxwork_db.py"]
    elif task == "export_wxwork":
        sys.argv = ["export_wxwork_messages.py"]
    else:
        sys.argv = [script]

    # Set environment variable so config.py and other scripts know the real app directory
    os.environ["WECHAT_DECRYPT_APP_DIR"] = BASE_DIR
    os.chdir(BASE_DIR)

    # Load and execute the script
    spec = importlib.util.spec_from_file_location("__main__", script_path)
    mod = importlib.util.module_from_spec(spec)
    mod.__name__ = "__main__"
    spec.loader.exec_module(mod)


# ── Check if running in subtask mode ──────────────────────────────────────────────────────
if len(sys.argv) >= 3 and sys.argv[1] == "--task":
    _run_subtask(sys.argv[2])
    sys.exit(0)

# ── GUI mode: hide console window ────────────────────────────────────────────────
if sys.platform == "win32":
    try:
        import ctypes
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except Exception:
        pass


# ── Contact discovery ────────────────────────────────────────────────────────────────

def _load_contact_map(decrypted_dir):
    """Load contact map from contact.db: {username: {remark, nick_name, ...}}"""
    contact_map = {}
    db_path = os.path.join(decrypted_dir, "contact", "contact.db")
    if not os.path.exists(db_path):
        return contact_map
    try:
        conn = sqlite3.connect(db_path)
        for uname, alias, remark, nick_name in conn.execute(
            "SELECT username, alias, remark, nick_name FROM contact"
        ):
            contact_map[uname] = {
                "remark": remark or "",
                "nick_name": nick_name or "",
            }
        conn.close()
    except Exception:
        pass
    return contact_map


def _display_name(username, contact_map):
    info = contact_map.get(username, {})
    return info.get("remark") or info.get("nick_name") or username


def _discover_contacts():
    """Scan all contacts/conversations, return (contacts, has_voice)
    contacts: [(username, display_name), ...]
    has_voice: whether voice data exists
    """
    from config import load_config
    cfg = load_config()
    decrypted_dir = cfg["decrypted_dir"]

    if not os.path.isdir(decrypted_dir):
        raise FileNotFoundError(f"Decrypted directory not found: {decrypted_dir}\nPlease run 'Decrypt Database' first")

    contact_map = _load_contact_map(decrypted_dir)
    usernames = set()
    has_voice = False

    # Scan from message databases
    msg_dir = os.path.join(decrypted_dir, "message")
    if os.path.isdir(msg_dir):
        db_files = [
            f for f in globmod.glob(os.path.join(msg_dir, "message_*.db"))
            if not f.endswith(("_fts.db", "_resource.db"))
        ]
        print(f"Found {len(db_files)} message databases", flush=True)
        for db_path in db_files:
            try:
                conn = sqlite3.connect(db_path)
                hash_to_uname = {}
                for row in conn.execute("SELECT rowid, user_name FROM Name2Id"):
                    uname = row[1]
                    if uname:
                        h = hashlib.md5(uname.encode()).hexdigest()
                        hash_to_uname[h] = uname
                for (tbl,) in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
                ):
                    h = tbl[4:]
                    uname = hash_to_uname.get(h)
                    if uname:
                        usernames.add(uname)
                conn.close()
            except Exception as e:
                print(f"  Failed to read {os.path.basename(db_path)}: {e}", flush=True)
                continue
    else:
        print(f"Message directory not found: {msg_dir}", flush=True)

    # Scan from voice database
    voice_db = os.path.join(msg_dir, "media_0.db")
    if os.path.exists(voice_db):
        try:
            conn = sqlite3.connect(voice_db)
            name_map = {}
            for rowid, uname in conn.execute("SELECT rowid, user_name FROM Name2Id"):
                name_map[rowid] = uname
            for (cid,) in conn.execute("SELECT DISTINCT chat_name_id FROM VoiceInfo"):
                uname = name_map.get(cid)
                if uname:
                    usernames.add(uname)
                    has_voice = True
            conn.close()
        except Exception as e:
            print(f"  Failed to read voice database: {e}", flush=True)

    print(f"Found {len(usernames)} conversations in total", flush=True)
    result = [(u, _display_name(u, contact_map)) for u in usernames]
    result.sort(key=lambda x: x[1].lower())
    return result, has_voice


# ── Export options dialog ──────────────────────────────────────────────────────────

class ExportOptionsDialog(tk.Toplevel):
    def __init__(self, parent, contacts, has_voice=False):
        """contacts: [(username, display_name), ...]
        has_voice: whether voice data was detected
        """
        super().__init__(parent)
        self.title("Export Options")
        self.geometry("460x600")
        self.transient(parent)
        self.grab_set()
        self.result = None
        self.configure(bg="#f0f0f0")
        self._contacts = contacts
        self._vars = {}  # username -> BooleanVar

        # ── Export format ──
        fmt_frame = ttk.LabelFrame(self, text="Export Format", padding=6)
        fmt_frame.pack(fill="x", padx=12, pady=(10, 4))

        self._fmt_csv = tk.BooleanVar(value=True)
        self._fmt_html = tk.BooleanVar(value=False)
        self._fmt_json = tk.BooleanVar(value=False)

        ttk.Checkbutton(fmt_frame, text="CSV (Default)", variable=self._fmt_csv).pack(side="left", padx=10)
        ttk.Checkbutton(fmt_frame, text="HTML", variable=self._fmt_html).pack(side="left", padx=10)
        ttk.Checkbutton(fmt_frame, text="JSON", variable=self._fmt_json).pack(side="left", padx=10)

        # ── Other options ──
        opt_frame = ttk.LabelFrame(self, text="Other Options", padding=6)
        opt_frame.pack(fill="x", padx=12, pady=(0, 4))

        self._image_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_frame, text="Export & Decrypt Images",
                        variable=self._image_var).pack(anchor="w", padx=8)

        self._sns_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt_frame, text="Export Moments Feed (posts/comments)",
                        variable=self._sns_var).pack(anchor="w", padx=8)

        self._sns_media_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt_frame, text="  ↳ Try to download Moments media (may be slow)",
                        variable=self._sns_media_var).pack(anchor="w", padx=24)

        self._voice_var = tk.BooleanVar(value=False)
        if has_voice:
            ttk.Checkbutton(opt_frame, text="Also convert voice messages to MP3",
                            variable=self._voice_var).pack(anchor="w", padx=8)

        # ── 联系人选择 ──
        top = ttk.Frame(self)
        top.pack(fill="x", padx=12, pady=(4, 4))

        ttk.Label(top, text=f"Total: {len(contacts)} conversations",
                  font=("Microsoft YaHei UI", 10)).pack(side="left")

        self._all_selected = True
        self._toggle_btn = ttk.Button(top, text="Deselect All", command=self._toggle_all)
        self._toggle_btn.pack(side="right")

        # Search box
        search_frame = ttk.Frame(self)
        search_frame.pack(fill="x", padx=12, pady=(0, 4))
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._filter_list())
        ttk.Entry(search_frame, textvariable=self._search_var,
                  font=("Microsoft YaHei UI", 10)).pack(fill="x")

        # Scrollable area
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True, padx=12, pady=4)

        self._canvas = tk.Canvas(container, bg="#ffffff", highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self._canvas.yview)
        self._inner = ttk.Frame(self._canvas)

        self._inner.bind("<Configure>",
                         lambda e: self._canvas.configure(scrollregion=self._canvas.bbox("all")))
        self._canvas.create_window((0, 0), window=self._inner, anchor="nw")
        self._canvas.configure(yscrollcommand=scrollbar.set)

        self._canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Bind mouse wheel
        self._canvas.bind("<Enter>", lambda e: self._bind_mousewheel())
        self._canvas.bind("<Leave>", lambda e: self._unbind_mousewheel())

        # Create Checkbutton list
        self._cb_widgets = []
        for username, dname in contacts:
            var = tk.BooleanVar(value=True)
            self._vars[username] = var
            label = f"{dname}  ({username})" if dname != username else username
            cb = ttk.Checkbutton(self._inner, text=label, variable=var)
            cb.pack(anchor="w", padx=6, pady=1)
            self._cb_widgets.append((username, dname, cb))

        # Bottom buttons
        bottom = ttk.Frame(self)
        bottom.pack(fill="x", padx=12, pady=(4, 10))

        ttk.Button(bottom, text="OK", command=self._on_ok).pack(side="right", padx=4)
        ttk.Button(bottom, text="Cancel", command=self._on_cancel).pack(side="right", padx=4)

    def _bind_mousewheel(self):
        self._canvas.bind_all("<MouseWheel>",
                              lambda e: self._canvas.yview_scroll(-1 * (e.delta // 120), "units"))

    def _unbind_mousewheel(self):
        self._canvas.unbind_all("<MouseWheel>")

    def _toggle_all(self):
        self._all_selected = not self._all_selected
        for var in self._vars.values():
            var.set(self._all_selected)
        self._toggle_btn.configure(text="Deselect All" if self._all_selected else "Select All")

    def _filter_list(self):
        keyword = self._search_var.get().strip().lower()
        for username, dname, cb in self._cb_widgets:
            if not keyword or keyword in dname.lower() or keyword in username.lower():
                cb.pack(anchor="w", padx=6, pady=1)
            else:
                cb.pack_forget()

    def _on_ok(self):
        formats = []
        if self._fmt_csv.get():
            formats.append("csv")
        if self._fmt_html.get():
            formats.append("html")
        if self._fmt_json.get():
            formats.append("json")

        if not formats and not self._voice_var.get() and not self._sns_var.get():
            from tkinter import messagebox
            messagebox.showwarning("Notice", "Please select at least one export format, Moments export, or voice conversion", parent=self)
            return

        self.result = {
            "contacts": [u for u, var in self._vars.items() if var.get()],
            "formats": formats,
            "include_voice": self._voice_var.get(),
            "include_images": self._image_var.get(),
            "include_sns": self._sns_var.get(),
            "include_sns_media": self._sns_media_var.get(),
        }
        self.destroy()

    def _on_cancel(self):
        self.result = None
        self.destroy()


class WxworkExportOptionsDialog(tk.Toplevel):
    def __init__(self, parent, conversations):
        """conversations: [{conversation_id, display_name, kind, message_count, last_time}, ...]"""
        super().__init__(parent)
        self.title("Work WeChat Export Options")
        self.geometry("560x620")
        self.transient(parent)
        self.grab_set()
        self.result = None
        self.configure(bg="#f0f0f0")
        self._conversations = conversations
        self._vars = {}

        fmt_frame = ttk.LabelFrame(self, text="Export Format", padding=6)
        fmt_frame.pack(fill="x", padx=12, pady=(10, 4))

        self._fmt_csv = tk.BooleanVar(value=True)
        self._fmt_html = tk.BooleanVar(value=False)
        self._fmt_json = tk.BooleanVar(value=False)

        ttk.Checkbutton(fmt_frame, text="CSV (Default)", variable=self._fmt_csv).pack(side="left", padx=10)
        ttk.Checkbutton(fmt_frame, text="HTML", variable=self._fmt_html).pack(side="left", padx=10)
        ttk.Checkbutton(fmt_frame, text="JSON", variable=self._fmt_json).pack(side="left", padx=10)

        top = ttk.Frame(self)
        top.pack(fill="x", padx=12, pady=(4, 4))
        ttk.Label(top, text=f"Total: {len(conversations)} Work WeChat conversations",
                  font=("Microsoft YaHei UI", 10)).pack(side="left")

        self._all_selected = True
        self._toggle_btn = ttk.Button(top, text="Deselect All", command=self._toggle_all)
        self._toggle_btn.pack(side="right")

        search_frame = ttk.Frame(self)
        search_frame.pack(fill="x", padx=12, pady=(0, 4))
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._filter_list())
        ttk.Entry(search_frame, textvariable=self._search_var,
                  font=("Microsoft YaHei UI", 10)).pack(fill="x")

        container = ttk.Frame(self)
        container.pack(fill="both", expand=True, padx=12, pady=4)

        self._canvas = tk.Canvas(container, bg="#ffffff", highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self._canvas.yview)
        self._inner = ttk.Frame(self._canvas)
        self._inner.bind("<Configure>",
                         lambda e: self._canvas.configure(scrollregion=self._canvas.bbox("all")))
        self._canvas.create_window((0, 0), window=self._inner, anchor="nw")
        self._canvas.configure(yscrollcommand=scrollbar.set)
        self._canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self._canvas.bind("<Enter>", lambda e: self._bind_mousewheel())
        self._canvas.bind("<Leave>", lambda e: self._unbind_mousewheel())

        self._cb_widgets = []
        for conv in conversations:
            cid = conv["conversation_id"]
            var = tk.BooleanVar(value=True)
            self._vars[cid] = var
            last_time = self._format_time(conv.get("last_time"))
            suffix = f" · {last_time}" if last_time else ""
            label = (
                f"[{conv.get('kind', 'conversation')}] {conv.get('display_name') or cid}"
                f" · {conv.get('message_count', 0)} messages{suffix}"
            )
            cb = ttk.Checkbutton(self._inner, text=label, variable=var)
            cb.pack(anchor="w", padx=6, pady=1)
            self._cb_widgets.append((cid, label.lower(), cb))

        bottom = ttk.Frame(self)
        bottom.pack(fill="x", padx=12, pady=(4, 10))
        ttk.Button(bottom, text="OK", command=self._on_ok).pack(side="right", padx=4)
        ttk.Button(bottom, text="Cancel", command=self._on_cancel).pack(side="right", padx=4)

    def _format_time(self, value):
        if not value:
            return ""
        try:
            from datetime import datetime
            return datetime.fromtimestamp(int(value)).strftime("%Y-%m-%d")
        except Exception:
            return ""

    def _bind_mousewheel(self):
        self._canvas.bind_all("<MouseWheel>",
                              lambda e: self._canvas.yview_scroll(-1 * (e.delta // 120), "units"))

    def _unbind_mousewheel(self):
        self._canvas.unbind_all("<MouseWheel>")

    def _toggle_all(self):
        self._all_selected = not self._all_selected
        for var in self._vars.values():
            var.set(self._all_selected)
        self._toggle_btn.configure(text="Deselect All" if self._all_selected else "Select All")

    def _filter_list(self):
        keyword = self._search_var.get().strip().lower()
        for _cid, label, cb in self._cb_widgets:
            if not keyword or keyword in label:
                cb.pack(anchor="w", padx=6, pady=1)
            else:
                cb.pack_forget()

    def _on_ok(self):
        formats = []
        if self._fmt_csv.get():
            formats.append("csv")
        if self._fmt_html.get():
            formats.append("html")
        if self._fmt_json.get():
            formats.append("json")
        if not formats:
            from tkinter import messagebox
            messagebox.showwarning("Notice", "Please select at least one export format", parent=self)
            return
        self.result = {
            "conversations": [cid for cid, var in self._vars.items() if var.get()],
            "formats": formats,
        }
        self.destroy()

    def _on_cancel(self):
        self.result = None
        self.destroy()


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("WeChat Decrypt Toolbox")
        self.geometry("820x600")
        self.resizable(True, True)
        self.configure(bg="#f0f0f0")
        self._running = False
        self._auto_export = False
        self._selected_contacts = None
        self._export_formats = None
        self._include_voice = False
        self._include_images = True
        self._include_sns = False
        self._include_sns_media = False
        self._selected_wxwork_conversations = None
        self._wxwork_export_formats = None

        self._build_ui()

    # ── UI construction ────────────────────────────────────────────────────────────
    def _build_ui(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Big.TButton", font=("Microsoft YaHei UI", 11), padding=(16, 10))
        style.configure("TLabel", font=("Microsoft YaHei UI", 10), background="#f0f0f0")

        # Title
        title = ttk.Label(self, text="WeChat Decrypt Toolbox", font=("Microsoft YaHei UI", 16, "bold"))
        title.pack(pady=(14, 6))

        # Button area
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=20, pady=(4, 4))

        self.btn_decrypt = ttk.Button(
            btn_frame, text="① WeChat Decrypt", style="Big.TButton",
            command=lambda: self._run_task("decrypt")
        )
        self.btn_decrypt.pack(side="left", expand=True, fill="x", padx=4)

        self.btn_imgkey = ttk.Button(
            btn_frame, text="② Image Key", style="Big.TButton",
            command=lambda: self._run_task("find_image_key")
        )
        self.btn_imgkey.pack(side="left", expand=True, fill="x", padx=4)

        self.btn_export = ttk.Button(
            btn_frame, text="③ Export Data", style="Big.TButton",
            command=lambda: self._run_task("export")
        )
        self.btn_export.pack(side="left", expand=True, fill="x", padx=4)

        self.btn_sns = ttk.Button(
            btn_frame, text="④ Moments Images", style="Big.TButton",
            command=lambda: self._run_task("decrypt_sns")
        )
        self.btn_sns.pack(side="left", expand=True, fill="x", padx=4)

        wxwork_frame = ttk.Frame(self)
        wxwork_frame.pack(fill="x", padx=20, pady=(0, 6))

        self.btn_wxwork = ttk.Button(
            wxwork_frame, text="⑤ Work WeChat Decrypt", style="Big.TButton",
            command=lambda: self._run_task("wxwork_decrypt")
        )
        self.btn_wxwork.pack(side="left", expand=True, fill="x", padx=4)

        self.btn_wxwork_export = ttk.Button(
            wxwork_frame, text="⑥ Work WeChat Export", style="Big.TButton",
            command=lambda: self._run_task("wxwork_export")
        )
        self.btn_wxwork_export.pack(side="left", expand=True, fill="x", padx=4)

        # Tips section
        tips_frame = ttk.LabelFrame(self, text="Usage Tips", padding=6)
        tips_frame.pack(fill="x", padx=20, pady=(0, 4))
        tips_text = (
            "• WeChat Decrypt: WeChat must be running; keys will be extracted and decrypted automatically\n"
            "• Image Key: Open 2-3 images in WeChat first, then run immediately\n"
            "• Export Data: Select contacts and formats; can export messages/images/voice simultaneously\n"
            "• Moments Images: Decrypt cached Moments images (_t thumbnails are skipped automatically)\n"
            "• Work WeChat Decrypt: Work WeChat must be running; outputs to wxwork_decrypted/\n"
            "• Work WeChat Export: Select a person or group; outputs CSV / HTML / JSON to wxwork_export/"
        )
        ttk.Label(tips_frame, text=tips_text, font=("Microsoft YaHei UI", 9),
                  wraplength=760, justify="left").pack(anchor="w")

        # Progress bar
        self.progress = ttk.Progressbar(self, mode="indeterminate")
        self.progress.pack(fill="x", padx=20, pady=(0, 4))

        # Log area
        log_label = ttk.Label(self, text="Run Log:")
        log_label.pack(anchor="w", padx=20)

        self.log = scrolledtext.ScrolledText(
            self, wrap="word", height=18,
            font=("Consolas", 10), bg="#1e1e1e", fg="#d4d4d4",
            insertbackground="#fff", state="disabled"
        )
        self.log.pack(fill="both", expand=True, padx=20, pady=(2, 10))

        # Bottom status
        self.status_var = tk.StringVar(value="Ready")
        status = ttk.Label(self, textvariable=self.status_var, font=("Microsoft YaHei UI", 9))
        status.pack(anchor="w", padx=20, pady=(0, 8))

    # ── Log writing ───────────────────────────────────────────────────────────
    def _log(self, text: str):
        self.log.configure(state="normal")
        self.log.insert("end", text)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    # ── Button state ───────────────────────────────────────────────────────────
    def _set_buttons(self, enabled: bool):
        state = "normal" if enabled else "disabled"
        self.btn_decrypt.configure(state=state)
        self.btn_imgkey.configure(state=state)
        self.btn_export.configure(state=state)
        self.btn_sns.configure(state=state)
        self.btn_wxwork.configure(state=state)
        self.btn_wxwork_export.configure(state=state)

    # ── Task scheduling ───────────────────────────────────────────────────────────
    def _run_task(self, task: str):
        if self._running:
            return
        self._running = True
        self._selected_contacts = None
        self._export_formats = None
        self._include_voice = False
        self._include_sns = False
        self._include_sns_media = False
        self._selected_wxwork_conversations = None
        self._wxwork_export_formats = None
        self._clear_log()
        self._set_buttons(False)

        if task == "export":
            self.progress.start(15)
            self.status_var.set("Scanning contacts...")
            threading.Thread(
                target=self._discover_and_select, daemon=True
            ).start()
        elif task == "find_image_key":
            self.progress.start(15)
            self.status_var.set("Scanning WeChat process memory...")
            threading.Thread(target=self._exec_task, args=(task,), daemon=True).start()
        elif task == "decrypt_sns":
            self.progress.start(15)
            self.status_var.set("Decrypting Moments images...")
            threading.Thread(target=self._exec_task, args=(task,), daemon=True).start()
        elif task == "wxwork_decrypt":
            self.progress.start(15)
            self.status_var.set("Decrypting Work WeChat database...")
            threading.Thread(target=self._exec_wxwork_decrypt, daemon=True).start()
        elif task == "wxwork_export":
            self.progress.start(15)
            self.status_var.set("Scanning Work WeChat conversations...")
            threading.Thread(target=self._discover_wxwork_and_select, daemon=True).start()
        else:
            self.progress.start(15)
            labels = {"decrypt": "Decrypt Database"}
            self.status_var.set(f"Running {labels.get(task, task)}...")
            threading.Thread(target=self._exec_task, args=(task,), daemon=True).start()

    def _discover_and_select(self):
        """Scan contacts in background, then show selection dialog on main thread"""
        try:
            contacts, has_voice = _discover_contacts()
        except Exception as e:
            self.after(0, self._log, f"Failed to scan contacts: {e}\n")
            self.after(0, self._on_task_done)
            return

        if not contacts:
            self.after(0, self._log, "No contacts/conversations found\n")
            self.after(0, self._on_task_done)
            return

        self.after(0, self._show_contact_dialog, contacts, has_voice)

    def _show_contact_dialog(self, contacts, has_voice):
        self.progress.stop()
        self.status_var.set(f"Please select export options ({len(contacts)} conversations)")

        dlg = ExportOptionsDialog(self, contacts, has_voice=has_voice)
        self.wait_window(dlg)

        if dlg.result is None:
            self._on_task_done()
            return

        if not dlg.result["contacts"]:
            self._log("No contacts selected\n")
            self._on_task_done()
            return

        self._selected_contacts = dlg.result["contacts"]
        self._export_formats = dlg.result["formats"]
        self._include_voice = dlg.result["include_voice"]
        self._include_images = dlg.result["include_images"]
        self._include_sns = dlg.result["include_sns"]
        self._include_sns_media = dlg.result["include_sns_media"]

        self._clear_log()
        self.progress.start(15)
        n_sel = len(dlg.result["contacts"])
        parts = []
        if self._export_formats:
            parts.append(f"Export {'/'.join(f.upper() for f in self._export_formats)}")
        if self._include_sns:
            parts.append("Moments")
        if self._include_voice:
            parts.append("Convert Voice")
        action = " + ".join(parts) or "Processing"
        self.status_var.set(f"Running {action}... ({n_sel}/{len(contacts)} contacts)")
        threading.Thread(target=self._exec_combined, daemon=True).start()

    def _discover_wxwork_and_select(self):
        """Scan Work WeChat conversations in background, then show selection dialog on main thread"""
        try:
            from export_wxwork_messages import discover_conversations
            conversations = discover_conversations()
        except Exception as e:
            self.after(0, self._log, f"Failed to scan Work WeChat conversations: {e}\n")
            self.after(0, self._on_task_done)
            return

        if not conversations:
            self.after(0, self._log, "No Work WeChat conversations found. Please run 'Work WeChat Decrypt' first\n")
            self.after(0, self._on_task_done)
            return

        self.after(0, self._show_wxwork_dialog, conversations)

    def _show_wxwork_dialog(self, conversations):
        self.progress.stop()
        self.status_var.set(f"Please select Work WeChat export options ({len(conversations)} conversations)")

        dlg = WxworkExportOptionsDialog(self, conversations)
        self.wait_window(dlg)

        if dlg.result is None:
            self._on_task_done()
            return

        if not dlg.result["conversations"]:
            self._log("No Work WeChat conversations selected\n")
            self._on_task_done()
            return

        self._selected_wxwork_conversations = dlg.result["conversations"]
        self._wxwork_export_formats = dlg.result["formats"]

        self._clear_log()
        self.progress.start(15)
        n_sel = len(dlg.result["conversations"])
        self.status_var.set(
            f"Exporting Work WeChat {'/'.join(f.upper() for f in self._wxwork_export_formats)}..."
            f" ({n_sel}/{len(conversations)} conversations)"
        )
        threading.Thread(target=self._exec_wxwork_export, daemon=True).start()

    # ── Subprocess execution ─────────────────────────────────────────────────────────
    def _run_subprocess(self, task: str) -> int:
        """Run subprocess and return exit code.

        When packaged as exe (sys.frozen=True), sys.executable is the exe itself,
        --task is its subcommand, so use [exe, --task, ...] directly.
        In development mode (python app_gui.py), sys.executable is the Python interpreter,
        need to add current script path __file__, otherwise `python --task` would be
        misinterpreted by the interpreter (reports unknown option).
        """
        if getattr(sys, "frozen", False):
            cmd = [sys.executable, "--task", task]
        else:
            cmd = [sys.executable, os.path.abspath(__file__), "--task", task]
        self.after(0, self._log, f">>> {' '.join(cmd)}\n\n")

        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["WECHAT_DECRYPT_APP_DIR"] = BASE_DIR
        env["WECHAT_DECRYPT_GUI"] = "1"
        env["WECHAT_DECRYPT_NONINTERACTIVE"] = "1"

        if self._selected_contacts:
            env["WECHAT_EXPORT_CONTACTS"] = ",".join(self._selected_contacts)
        if self._export_formats:
            env["WECHAT_EXPORT_FORMATS"] = ",".join(self._export_formats)
        env["WECHAT_EXPORT_IMAGES"] = "1" if getattr(self, '_include_images', True) else "0"
        if getattr(self, '_include_sns_media', False):
            env["WECHAT_SNS_DOWNLOAD_MEDIA"] = "1"
        if self._selected_wxwork_conversations:
            env["WXWORK_EXPORT_CONVERSATIONS"] = ",".join(self._selected_wxwork_conversations)
        if self._wxwork_export_formats:
            env["WXWORK_EXPORT_FORMATS"] = ",".join(self._wxwork_export_formats)

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=BASE_DIR,
            env=env,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )

        for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace")
            self.after(0, self._log, line)

        proc.wait()
        return proc.returncode

    def _exec_combined(self):
        """Execute export (messages + optional voice)"""
        try:
            if self._export_formats:
                rc = self._run_subprocess("export")
                if rc != 0:
                    self.after(0, self._log, f"\n❌ Export failed (return code {rc})\n")
                    self.after(0, self.status_var.set, f"Failed (return code {rc})")
                    return

            if getattr(self, '_include_sns', False):
                if self._export_formats:
                    self.after(0, self._log, "\n\n━━━ Starting Moments export ━━━\n\n")
                rc = self._run_subprocess("export_sns")
                if rc != 0:
                    self.after(0, self._log, f"\n❌ Moments export failed (return code {rc})\n")
                    self.after(0, self.status_var.set, f"Moments export failed (return code {rc})")
                    return

            if self._include_voice:
                if self._export_formats or getattr(self, '_include_sns', False):
                    self.after(0, self._log, "\n\n━━━ Starting voice conversion ━━━\n\n")
                rc = self._run_subprocess("voice")
                if rc != 0:
                    self.after(0, self._log, f"\n❌ Voice conversion failed (return code {rc})\n")
                    self.after(0, self.status_var.set, f"Voice conversion failed (return code {rc})")
                    return

            self.after(0, self._log, "\n✅ All done!\n")
            self.after(0, self.status_var.set, "Done")
        except Exception as e:
            self.after(0, self._log, f"\n❌ Exception: {e}\n")
            self.after(0, self.status_var.set, "Error")
        finally:
            self._selected_contacts = None
            self._export_formats = None
            self._include_voice = False
            self._include_images = True
            self._include_sns = False
            self._include_sns_media = False
            self.after(0, self._on_task_done)

    def _exec_wxwork_decrypt(self):
        """Execute Work WeChat key extraction + database decryption."""
        try:
            self.after(0, self._log, "━━━ Starting Work WeChat key extraction ━━━\n\n")
            rc = self._run_subprocess("find_wxwork_keys")
            if rc != 0:
                self.after(0, self._log, f"\n❌ Work WeChat key extraction failed (return code {rc})\n")
                self.after(0, self.status_var.set, f"Work WeChat key extraction failed (return code {rc})")
                return

            self.after(0, self._log, "\n\n━━━ Starting Work WeChat database decryption ━━━\n\n")
            rc = self._run_subprocess("decrypt_wxwork")
            if rc != 0:
                self.after(0, self._log, f"\n❌ Work WeChat database decryption failed (return code {rc})\n")
                self.after(0, self.status_var.set, f"Work WeChat decryption failed (return code {rc})")
                return

            self.after(0, self._log, "\n✅ Work WeChat decryption complete! Output directory: wxwork_decrypted\n")
            self.after(0, self.status_var.set, "Work WeChat decryption complete")
        except Exception as e:
            self.after(0, self._log, f"\n❌ Exception: {e}\n")
            self.after(0, self.status_var.set, "Error")
        finally:
            self.after(0, self._on_task_done)

    def _exec_wxwork_export(self):
        """Execute Work WeChat message export."""
        try:
            rc = self._run_subprocess("export_wxwork")
            if rc != 0:
                self.after(0, self._log, f"\n❌ Work WeChat export failed (return code {rc})\n")
                self.after(0, self.status_var.set, f"Work WeChat export failed (return code {rc})")
                return
            self.after(0, self._log, "\n✅ Work WeChat export complete! Output directory: wxwork_export\n")
            self.after(0, self.status_var.set, "Work WeChat export complete")
        except Exception as e:
            self.after(0, self._log, f"\n❌ Exception: {e}\n")
            self.after(0, self.status_var.set, "Error")
        finally:
            self._selected_wxwork_conversations = None
            self._wxwork_export_formats = None
            self.after(0, self._on_task_done)

    def _exec_task(self, task: str):
        """Execute a single task (decrypt)"""
        try:
            rc = self._run_subprocess(task)
            if rc == 0:
                self.after(0, self._log, "\n✅ Done!\n")
                self.after(0, self.status_var.set, "Done")
                if task == "decrypt":
                    self._auto_export = True
            else:
                self.after(0, self._log, f"\n❌ Process exited with return code: {rc}\n")
                self.after(0, self.status_var.set, f"Failed (return code {rc})")
        except Exception as e:
            self.after(0, self._log, f"\n❌ Exception: {e}\n")
            self.after(0, self.status_var.set, "Error")
        finally:
            self.after(0, self._on_task_done)

    def _on_task_done(self):
        self._running = False
        self.progress.stop()
        self._set_buttons(True)
        if self._auto_export:
            self._auto_export = False
            self._log("\nDecryption complete, automatically starting export...\n\n")
            self.after(500, lambda: self._run_task("export"))


if __name__ == "__main__":
    app = App()
    app.mainloop()
