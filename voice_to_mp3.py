"""Extract all voice data from media_0.db, organized into directories by username, SILK_V3 converted to MP3"""
import sqlite3
import subprocess
import tempfile
import os
import sys
from datetime import datetime

if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

try:
    import pilk
except ImportError:
    print("[ERROR] Missing pilk library (required for SILK decoding)", file=sys.stderr)
    print("        Please run: pip install pilk", file=sys.stderr)
    print("        Then restart this task", file=sys.stderr)
    sys.exit(1)

import shutil as _shutil
if not _shutil.which("ffmpeg"):
    print("[ERROR] ffmpeg is not in PATH (required for MP3 encoding)", file=sys.stderr)
    print("        Windows: https://ffmpeg.org/download.html  download and add to PATH", file=sys.stderr)
    print("        macOS:   brew install ffmpeg", file=sys.stderr)
    print("        Linux:   apt install ffmpeg / yum install ffmpeg", file=sys.stderr)
    sys.exit(1)

from config import load_config

_cfg = load_config()
DB_PATH = os.path.join(_cfg["decrypted_dir"], "message", "media_0.db")
CONTACT_DB_PATH = os.path.join(_cfg["decrypted_dir"], "contact", "contact.db")
OUTPUT_DIR = _cfg["output_base_dir"]

_CONTACT_FILTER = None
_filter_raw = os.environ.get("WECHAT_EXPORT_CONTACTS", "").strip()
if _filter_raw:
    _CONTACT_FILTER = set(_filter_raw.split(","))
    print(f"Contact filter: {len(_CONTACT_FILTER)} entries")

def silk_to_mp3(voice_data, output_path):
    """Convert WeChat SILK voice data to MP3"""
    # Strip the WeChat-format 0x02 prefix
    if voice_data[0:1] == b'\x02':
        silk_data = voice_data[1:]
    else:
        silk_data = voice_data

    if not silk_data.startswith(b'#!SILK_V3'):
        print(f"  Warning: data does not start with #!SILK_V3, skipping")
        return False

    # Append end-of-stream marker
    if not silk_data.endswith(b'\xff\xff'):
        silk_data += b'\xff\xff'

    silk_file = tempfile.mktemp(suffix=".silk")
    pcm_file = tempfile.mktemp(suffix=".pcm")
    try:
        with open(silk_file, "wb") as f:
            f.write(silk_data)

        pilk.decode(silk_file, pcm_file)

        result = subprocess.run([
            "ffmpeg", "-y", "-f", "s16le", "-ar", "24000", "-ac", "1",
            "-i", pcm_file, output_path
        ], capture_output=True, encoding="utf-8", errors="replace")
        return result.returncode == 0
    finally:
        if os.path.exists(silk_file):
            os.remove(silk_file)
        if os.path.exists(pcm_file):
            os.remove(pcm_file)

# 1. Read Name2Id mapping (rowid -> user_name)
conn = sqlite3.connect(DB_PATH)
name_map = {}
for rowid, user_name in conn.execute("SELECT rowid, user_name FROM Name2Id"):
    name_map[rowid] = user_name
print(f"Total {len(name_map)} users")

# 2. Read contact info (user_name -> {remark, nick_name, alias, ...})
contact_map = {}
try:
    cconn = sqlite3.connect(CONTACT_DB_PATH)
    for row in cconn.execute("SELECT username, alias, remark, nick_name FROM contact"):
        uname, alias, remark, nick_name = row
        contact_map[uname] = {"username": uname, "alias": alias or "", "remark": remark or "", "nick_name": nick_name or ""}
    cconn.close()
    print(f"Contact database loaded: {len(contact_map)} records")
except Exception as e:
    print(f"Failed to read contact database: {e}")

def display_name(user_name):
    """Priority: remark > nick_name > user_name"""
    info = contact_map.get(user_name, {})
    return info.get("remark") or info.get("nick_name") or user_name

def safe_dirname(name):
    """Replace illegal characters in directory names"""
    for ch in r'\/:*?"<>|':
        name = name.replace(ch, "_")
    return name.strip() or "unknown"

# 2. Query all voice records, join user_name via chat_name_id
rows = conn.execute("SELECT chat_name_id, create_time, local_id, voice_data FROM VoiceInfo ORDER BY chat_name_id, create_time").fetchall()
conn.close()
print(f"Total {len(rows)} voice records")

# 3. Iterate and convert
success = 0
fail = 0
for chat_name_id, create_time, local_id, voice_data in rows:
    user_name = name_map.get(chat_name_id, f"unknown_{chat_name_id}")
    if _CONTACT_FILTER and user_name not in _CONTACT_FILTER:
        continue
    dname = safe_dirname(display_name(user_name))
    dt = datetime.fromtimestamp(create_time)
    filename = dt.strftime("%Y%m%d_%H%M%S") + f"_{local_id}.mp3"

    user_dir = os.path.join(OUTPUT_DIR, dname, "voice")
    os.makedirs(user_dir, exist_ok=True)

    # Write .info file (written once, placed in the contact root directory)
    info_path = os.path.join(OUTPUT_DIR, dname, ".info")
    if not os.path.exists(info_path):
        info = contact_map.get(user_name, {"username": user_name, "alias": "", "remark": "", "nick_name": ""})
        with open(info_path, "w", encoding="utf-8") as f:
            f.write(f"username:  {info['username']}\n")
            f.write(f"alias:     {info['alias']}\n")
            f.write(f"nick_name: {info['nick_name']}\n")
            f.write(f"remark:    {info['remark']}\n")

    output_path = os.path.join(user_dir, filename)
    if os.path.exists(output_path):
        success += 1
        continue

    ok = silk_to_mp3(voice_data, output_path)
    if ok:
        success += 1
        print(f"  [{success}/{len(rows)}] {dname}/{filename}")
    else:
        fail += 1
        print(f"  Failed: {dname}/{filename}")

print(f"\nDone: {success} succeeded, {fail} failed")
