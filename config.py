"""
Configuration loader - reads path configuration from config.json
On first run, auto-detects the WeChat data directory; prompts for manual configuration if detection fails
"""
import glob
import json
import os
import platform
import sys

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

# After packaging, __file__ points to a temp directory; prefer the exe's directory specified via env var.
def _app_base_dir():
    d = os.environ.get("WECHAT_DECRYPT_APP_DIR")
    if d and os.path.isdir(d):
        return d
    return os.path.dirname(os.path.abspath(__file__))


def _config_file_path():
    if os.environ.get("WECHAT_DECRYPT_APP_DIR"):
        return os.path.join(_app_base_dir(), "config.json")
    p = os.path.join(_app_base_dir(), "config.json")
    if os.path.exists(p):
        return p
    return CONFIG_FILE


_SYSTEM = platform.system().lower()

if _SYSTEM == "linux":
    _DEFAULT_TEMPLATE_DIR = os.path.expanduser("~/Documents/xwechat_files/your_wxid/db_storage")
    _DEFAULT_PROCESS = "wechat"
elif _SYSTEM == "darwin":
    # macOS uses a standalone C scanner (find_all_keys_macos.c); this only provides config defaults
    _DEFAULT_TEMPLATE_DIR = os.path.expanduser(
        "~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/your_wxid/db_storage"
    )
    _DEFAULT_PROCESS = "WeChat"
else:
    _DEFAULT_TEMPLATE_DIR = r"D:\xwechat_files\your_wxid\db_storage"
    _DEFAULT_PROCESS = "Weixin.exe"

_DEFAULT = {
    "db_dir": _DEFAULT_TEMPLATE_DIR,
    "keys_file": "all_keys.json",
    "decrypted_dir": "decrypted",
    "decoded_image_dir": "decoded_images",
    "wechat_process": _DEFAULT_PROCESS,
    "wxwork_db_dir": "",
    "wxwork_keys_file": "wxwork_keys.json",
    "wxwork_decrypted_dir": "wxwork_decrypted",
    "wxwork_export_dir": "wxwork_export",
    "wxwork_process": "WXWork.exe",
    # Transcription backend: "local" (default, local Whisper) or "openai" (OpenAI API)
    # When set to "openai", audio will be uploaded to OpenAI servers; see README "Transcription Privacy" section
    "transcription_backend": "local",
    "local_whisper_model": "base",
    "openai_api_key": "",
}


def _choose_candidate(candidates):
    """Select one from multiple candidate directories."""
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        if (
            os.environ.get("WECHAT_DECRYPT_NONINTERACTIVE") == "1"
            or os.environ.get("WECHAT_DECRYPT_GUI") == "1"
            or not sys.stdin.isatty()
        ):
            return candidates[0]
        print("[!] Multiple WeChat data directories detected (please select the currently active account):")
        for i, c in enumerate(candidates, 1):
            print(f"    {i}. {c}")
        print("    0. Skip, configure manually later")
        try:
            while True:
                choice = input("Select [0-{}]: ".format(len(candidates))).strip()
                if choice == "0":
                    return None
                if choice.isdigit() and 1 <= int(choice) <= len(candidates):
                    return candidates[int(choice) - 1]
                print("    Invalid input, please select again")
        except (EOFError, KeyboardInterrupt):
            print()
            return None
    return None


def _auto_detect_db_dir_windows():
    """Auto-detect Windows db_storage path from WeChat local config.

    Reads %APPDATA%\\Tencent\\xwechat\\config\\*.ini,
    finds the data storage root, then matches xwechat_files\\*\\db_storage.
    """
    appdata = os.environ.get("APPDATA", "")
    config_dir = os.path.join(appdata, "Tencent", "xwechat", "config")
    if not os.path.isdir(config_dir):
        return None

    # Find valid directory paths from ini files
    data_roots = []
    for ini_file in glob.glob(os.path.join(config_dir, "*.ini")):
        try:
            # WeChat ini may be utf-8 or gbk encoded (for Chinese paths)
            content = None
            for enc in ("utf-8", "gbk"):
                try:
                    with open(ini_file, "r", encoding=enc) as f:
                        content = f.read(1024).strip()
                    break
                except UnicodeDecodeError:
                    continue
            if not content or any(c in content for c in "\n\r\x00"):
                continue
            if os.path.isdir(content):
                data_roots.append(content)
        except OSError:
            continue

    # Search for xwechat_files\*\db_storage under each root directory
    seen = set()
    candidates = []
    for root in data_roots:
        pattern = os.path.join(root, "xwechat_files", "*", "db_storage")
        for match in glob.glob(pattern):
            normalized = os.path.normcase(os.path.normpath(match))
            if os.path.isdir(match) and normalized not in seen:
                seen.add(normalized)
                candidates.append(match)

    return _choose_candidate(candidates)


def _auto_detect_db_dir_linux():
    """Auto-detect Linux WeChat db_storage path.

    Searches the current user's home directory first. When running with sudo,
    falls back to the real user's home via SUDO_USER to avoid only searching /root.
    """
    seen = set()
    candidates = []
    search_roots = [
        os.path.expanduser("~/Documents/xwechat_files"),
    ]
    # When running with sudo, ~ expands to /root; fall back to the real user's home
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        # Validate SUDO_USER is a legitimate system user to prevent path injection
        import pwd
        try:
            sudo_home = pwd.getpwnam(sudo_user).pw_dir
        except KeyError:
            sudo_home = None
        if sudo_home:
            fallback = os.path.join(sudo_home, "Documents", "xwechat_files")
            if fallback not in search_roots:
                search_roots.append(fallback)

    for root in search_roots:
        if not os.path.isdir(root):
            continue
        pattern = os.path.join(root, "*", "db_storage")
        for match in glob.glob(pattern):
            normalized = os.path.normcase(os.path.normpath(match))
            if os.path.isdir(match) and normalized not in seen:
                seen.add(normalized)
                candidates.append(match)

    # Data path used by early Linux WeChat versions (wine/container setups)
    old_path = os.path.expanduser("~/.local/share/weixin/data/db_storage")
    if os.path.isdir(old_path):
        normalized = os.path.normcase(os.path.normpath(old_path))
        if normalized not in seen:
            candidates.append(old_path)

    # Prioritize most recently active account: sort by message dir mtime descending (approximate, best-effort)
    def _mtime(path):
        msg_dir = os.path.join(path, "message")
        target = msg_dir if os.path.isdir(msg_dir) else path
        try:
            return os.path.getmtime(target)
        except OSError:
            return 0

    candidates.sort(key=_mtime, reverse=True)
    return _choose_candidate(candidates)


def _auto_detect_db_dir_macos():
    """Auto-detect macOS WeChat db_storage path.

    WeChat 4.x data directory is at ~/Library/Containers/com.tencent.xinWeChat/.../xwechat_files/<wxid>/db_storage;
    the path contains a random hash and must be located by searching.
    """
    base = os.path.expanduser(
        "~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files"
    )
    if not os.path.isdir(base):
        return None

    seen = set()
    candidates = []
    pattern = os.path.join(base, "*", "db_storage")
    for match in glob.glob(pattern):
        normalized = os.path.normcase(os.path.normpath(match))
        if os.path.isdir(match) and normalized not in seen:
            seen.add(normalized)
            candidates.append(match)

    # Prioritize most recently active account: sort by message dir mtime descending
    def _mtime(path):
        msg_dir = os.path.join(path, "message")
        target = msg_dir if os.path.isdir(msg_dir) else path
        try:
            return os.path.getmtime(target)
        except OSError:
            return 0

    candidates.sort(key=_mtime, reverse=True)
    return _choose_candidate(candidates)


def auto_detect_db_dir():
    if _SYSTEM == "windows":
        return _auto_detect_db_dir_windows()
    if _SYSTEM == "linux":
        return _auto_detect_db_dir_linux()
    if _SYSTEM == "darwin":
        return _auto_detect_db_dir_macos()
    return None


def load_config():
    cfg = {}
    config_file = _config_file_path()
    if os.path.exists(config_file):
        try:
            with open(config_file, encoding="utf-8") as f:
                cfg = json.load(f)
        except json.JSONDecodeError:
            print(f"[!] {config_file} is corrupted, using default configuration")
            cfg = {}
    # If db_dir is missing or still the template value, attempt auto-detection
    db_dir = cfg.get("db_dir", "")
    if not db_dir or db_dir == _DEFAULT_TEMPLATE_DIR or "your_wxid" in db_dir:
        detected = auto_detect_db_dir()
        if detected:
            print(f"[+] Auto-detected WeChat data directory: {detected}")
            cfg = {**_DEFAULT, **cfg, "db_dir": detected}
            with open(config_file, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=4, ensure_ascii=False)
            print(f"[+] Saved to: {config_file}")
        else:
            if not os.path.exists(config_file):
                with open(config_file, "w", encoding="utf-8") as f:
                    json.dump(_DEFAULT, f, indent=4, ensure_ascii=False)
            print(f"[!] Failed to auto-detect WeChat data directory")
            print(f"    Please manually edit the db_dir field in {config_file}")
            if _SYSTEM == "linux":
                print("    Linux default path is similar to: ~/Documents/xwechat_files/<wxid>/db_storage")
            elif _SYSTEM == "darwin":
                print("    macOS default path is similar to: ~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/<wxid>/db_storage")
            else:
                print(f"    Path can be found in WeChat Settings -> File Management")
            sys.exit(1)
    else:
        cfg = {**_DEFAULT, **cfg}

    # Convert relative paths to absolute paths
    base = _app_base_dir()
    for key in (
        "keys_file", "decrypted_dir", "decoded_image_dir",
        "wxwork_keys_file", "wxwork_decrypted_dir", "wxwork_export_dir",
    ):
        if key in cfg and cfg[key] and not os.path.isabs(cfg[key]):
            cfg[key] = os.path.join(base, cfg[key])
    # Path expansion: first expanduser (~ expansion) + expandvars ($HOME / %USERPROFILE% expansion),
    # then check isabs; if still relative, join with project root. This allows config to use
    # "all_keys.json" (relative to project root) or "~/Documents/wechat_decrypted" /
    # "$HOME/wechat" / "%USERPROFILE%\\wechat" (portable across users).
    # Empty strings / null no longer trigger TypeError (using cfg.get instead of in).
    base = _app_base_dir()
    if cfg.get("db_dir"):
        cfg["db_dir"] = os.path.expanduser(os.path.expandvars(cfg["db_dir"]))
    for key in ("keys_file", "decrypted_dir", "decoded_image_dir"):
        if cfg.get(key):
            cfg[key] = os.path.expanduser(os.path.expandvars(cfg[key]))
            if not os.path.isabs(cfg[key]):
                cfg[key] = os.path.join(base, cfg[key])

    # Auto-derive WeChat data root directory (parent of db_dir)
    # db_dir format: D:\xwechat_files\<wxid>\db_storage
    # base_dir format: D:\xwechat_files\<wxid>
    db_dir = cfg.get("db_dir", "")
    if db_dir and os.path.basename(db_dir) == "db_storage":
        cfg["wechat_base_dir"] = os.path.dirname(db_dir)
    else:
        cfg["wechat_base_dir"] = db_dir

    # Output directory: <app_dir>/wechat_files/<wxid>/
    wxid = os.path.basename(os.path.normpath(cfg["wechat_base_dir"]))
    cfg["output_base_dir"] = os.path.join(base, "wechat_files", wxid)

    # decoded_image_dir default value
    if "decoded_image_dir" not in cfg:
        cfg["decoded_image_dir"] = os.path.join(base, "decoded_images")

    # Auto-detect WeChat Files directory (FileStorage/MsgAttach, FileStorage/Sns/Cache)
    if not cfg.get("wechat_files_dir"):
        wechat_files_base = os.path.join(os.path.expanduser("~"), "Documents", "WeChat Files")
        if os.path.isdir(wechat_files_base):
            # wxid in xwechat_files may have a suffix like _1d4c, requires fuzzy matching
            wxid_prefix = wxid.rsplit("_", 1)[0] if "_" in wxid else wxid
            for d in os.listdir(wechat_files_base):
                if d == wxid or d == wxid_prefix or wxid.startswith(d):
                    candidate = os.path.join(wechat_files_base, d)
                    if os.path.isdir(os.path.join(candidate, "FileStorage")):
                        cfg["wechat_files_dir"] = candidate
                        break

    wf_dir = cfg.get("wechat_files_dir", "")
    cfg["msgattach_dir"] = os.path.join(wf_dir, "FileStorage", "MsgAttach") if wf_dir else ""
    cfg["sns_cache_dir"] = os.path.join(wf_dir, "FileStorage", "Sns", "Cache") if wf_dir else ""

    # xwechat_files image/cache paths
    wb = cfg["wechat_base_dir"]
    cfg["xwechat_attach_dir"] = os.path.join(wb, "msg", "attach") if wb else ""
    cfg["xwechat_cache_dir"] = os.path.join(wb, "cache") if wb else ""

    return cfg
