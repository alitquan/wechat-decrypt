"""Export WeChat message records to CSV / HTML / JSON
Directory structure: <output_base_dir>/<display_name>/messages.csv|html|json
Image export: <output_base_dir>/<display_name>/image/<md5>.<ext>
"""
import base64
import sqlite3
import glob
import hashlib
import os
import json
import csv
import re
import struct
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

import zstandard as zstd

# Set Windows PowerShell console to UTF-8
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from config import load_config

_cfg = load_config()
MSG_DB_DIR = os.path.join(_cfg["decrypted_dir"], "message")
CONTACT_DB_PATH = os.path.join(_cfg["decrypted_dir"], "contact", "contact.db")
OUTPUT_DIR = _cfg["output_base_dir"]

# Image-related configuration
WECHAT_BASE_DIR = _cfg.get("wechat_base_dir", "")
ATTACH_DIR = os.path.join(WECHAT_BASE_DIR, "msg", "attach") if WECHAT_BASE_DIR else ""
MSGATTACH_DIR = _cfg.get("msgattach_dir", "")  # WeChat Files/FileStorage/MsgAttach
IMAGE_AES_KEY = _cfg.get("image_aes_key")
IMAGE_XOR_KEY = _cfg.get("image_xor_key", 0x88)
MSG_RESOURCE_DB = os.path.join(_cfg["decrypted_dir"], "message", "message_resource.db")

_CONTACT_FILTER = None
_filter_raw = os.environ.get("WECHAT_EXPORT_CONTACTS", "").strip()
if _filter_raw:
    _CONTACT_FILTER = set(_filter_raw.split(","))
    print(f"Contact filter: {len(_CONTACT_FILTER)} contacts")

_EXPORT_FORMATS = None
_formats_raw = os.environ.get("WECHAT_EXPORT_FORMATS", "").strip()
if _formats_raw:
    _EXPORT_FORMATS = set(_formats_raw.lower().split(","))
    print(f"Export formats: {', '.join(sorted(_EXPORT_FORMATS))}")

_EXPORT_IMAGES = os.environ.get("WECHAT_EXPORT_IMAGES", "1").strip() == "1"


# ─── Image decryption helpers ──────────────────────────────────────────────────

def _extract_md5_from_packed_info(blob):
    """Extract file MD5 from packed_info in message_resource.db"""
    if not blob or not isinstance(blob, bytes):
        return None
    marker = b'\x12\x22\x0a\x20'
    idx = blob.find(marker)
    if idx >= 0 and idx + len(marker) + 32 <= len(blob):
        md5_bytes = blob[idx + len(marker): idx + len(marker) + 32]
        try:
            md5_str = md5_bytes.decode('ascii')
            int(md5_str, 16)
            return md5_str
        except (UnicodeDecodeError, ValueError):
            pass
    hex_chars = set(b'0123456789abcdef')
    i = 0
    while i <= len(blob) - 32:
        if blob[i] in hex_chars:
            candidate = blob[i:i+32]
            if all(b in hex_chars for b in candidate):
                try:
                    return candidate.decode('ascii')
                except UnicodeDecodeError:
                    pass
            i += 32
        else:
            i += 1
    return None


def _load_resource_md5_map():
    """Load (chat_username, local_id) -> file_md5 mapping from message_resource.db"""
    md5_map = {}
    if not os.path.exists(MSG_RESOURCE_DB):
        return md5_map
    try:
        conn = sqlite3.connect(MSG_RESOURCE_DB)
        # chat_id -> username mapping
        chat_id_map = {}
        for row in conn.execute("SELECT rowid, user_name FROM ChatName2Id"):
            chat_id_map[row[0]] = row[1]
        for row in conn.execute(
            "SELECT chat_id, message_local_id, packed_info FROM MessageResourceInfo"
        ):
            cid, lid, blob = row
            md5 = _extract_md5_from_packed_info(blob)
            if md5:
                uname = chat_id_map.get(cid, "")
                if uname:
                    md5_map[(uname, lid)] = md5
        conn.close()
        print(f"Image resource map: {len(md5_map)} entries")
    except Exception as e:
        print(f"Failed to read message_resource.db: {e}")
    return md5_map


def _find_dat_file(username_hash, file_md5):
    """Search for .dat files in the attach / MsgAttach directory, preferring high-resolution versions"""
    search_patterns = []
    # xwechat_files msg/attach directory: <hash>/<YYYY-MM>/Img/<md5>*.dat
    if ATTACH_DIR and os.path.isdir(ATTACH_DIR):
        search_base = os.path.join(ATTACH_DIR, username_hash)
        if os.path.isdir(search_base):
            search_patterns.append(os.path.join(search_base, "*", "Img", f"{file_md5}*.dat"))
    # WeChat Files MsgAttach directory: <hash>/Image/<YYYY-MM>/<md5>*.dat
    if MSGATTACH_DIR and os.path.isdir(MSGATTACH_DIR):
        search_base = os.path.join(MSGATTACH_DIR, username_hash)
        if os.path.isdir(search_base):
            search_patterns.append(os.path.join(search_base, "Image", "*", f"{file_md5}*.dat"))

    files = []
    for pat in search_patterns:
        files.extend(glob.glob(pat))
    if not files:
        return None
    # Priority: no suffix (original) > _W (original) > _h (high-res) > _t/_t_W (thumbnail)
    # Filter out thumbnails first
    non_thumb = [f for f in files if '_t.' not in os.path.basename(f) and '_t_' not in os.path.basename(f)]
    candidates = non_thumb if non_thumb else files
    selected = candidates[0]
    for f in candidates:
        fname = os.path.basename(f)
        # Exact match for original image (no suffix)
        if fname == f"{file_md5}.dat":
            return f
    for f in candidates:
        fname = os.path.basename(f)
        if fname == f"{file_md5}_W.dat":
            return f
    for f in candidates:
        if '_h.' in os.path.basename(f) or '_h_' in os.path.basename(f):
            return f
    return selected


def _detect_image_format(header):
    """Detect image format from the decrypted file header"""
    if header[:3] == bytes([0xFF, 0xD8, 0xFF]):
        return 'jpg'
    if header[:4] == bytes([0x89, 0x50, 0x4E, 0x47]):
        return 'png'
    if header[:3] == b'GIF':
        return 'gif'
    if header[:4] == b'RIFF' and len(header) >= 12 and header[8:12] == b'WEBP':
        return 'webp'
    if header[:4] == b'wxgf':
        return 'hevc'
    return 'bin'


# V2 format constants
_V2_MAGIC_FULL = b'\x07\x08V2\x08\x07'
_V1_MAGIC_FULL = b'\x07\x08V1\x08\x07'
_IMAGE_MAGICS = {
    'jpg': [0xFF, 0xD8, 0xFF],
    'png': [0x89, 0x50, 0x4E, 0x47],
    'gif': [0x47, 0x49, 0x46, 0x38],
    'webp': [0x52, 0x49, 0x46, 0x46],
}


def _decrypt_dat_to_bytes(dat_path):
    """Decrypt a .dat file, returning (bytes, format) or (None, None)"""
    with open(dat_path, 'rb') as f:
        data = f.read()
    if len(data) < 15:
        return None, None
    head6 = data[:6]

    # V2 / V1 format
    if head6 in (_V2_MAGIC_FULL, _V1_MAGIC_FULL):
        aes_key = None
        if head6 == _V1_MAGIC_FULL:
            aes_key = b'cfcd208495d565ef'
        elif IMAGE_AES_KEY:
            aes_key = IMAGE_AES_KEY.encode('ascii')[:16] if isinstance(IMAGE_AES_KEY, str) else IMAGE_AES_KEY[:16]
        if not aes_key or len(aes_key) < 16:
            return None, None
        try:
            from Crypto.Cipher import AES as _AES
            from Crypto.Util import Padding
            aes_size, xor_size = struct.unpack_from('<LL', data, 6)
            aligned = aes_size - ~(~aes_size % 16)
            offset = 15
            if offset + aligned > len(data):
                return None, None
            cipher = _AES.new(aes_key[:16], _AES.MODE_ECB)
            dec_aes = Padding.unpad(cipher.decrypt(data[offset:offset+aligned]), _AES.block_size)
            offset += aligned
            raw_end = len(data) - xor_size
            raw_data = data[offset:raw_end] if offset < raw_end else b''
            xor_data = data[raw_end:]
            xor_key = IMAGE_XOR_KEY if isinstance(IMAGE_XOR_KEY, int) else 0x88
            dec_xor = bytes(b ^ xor_key for b in xor_data)
            result = dec_aes + raw_data + dec_xor
            fmt = _detect_image_format(result[:16])
            return result, fmt
        except Exception:
            return None, None

    # Legacy XOR format
    for fmt_name, magic in _IMAGE_MAGICS.items():
        key = data[0] ^ magic[0]
        match = all(i < len(data) and (data[i] ^ key) == magic[i] for i in range(len(magic)))
        if match:
            result = bytes(b ^ key for b in data)
            fmt = _detect_image_format(result[:16])
            return result, fmt

    return None, None


_resource_md5_map = _load_resource_md5_map() if _EXPORT_IMAGES else {}


def decode_chat_images(chat_username, _messages_unused, out_dir):
    """Directly scan all images for the contact in the attach directory and decrypt them.
    Output to out_dir/image/<YYYY-MM>/ organized by month.
    Skip _t thumbnails, prefer _h high-resolution versions.
    Returns {file_md5: relative_path} for HTML embedding.
    """
    image_map = {}
    username_hash = hashlib.md5(chat_username.encode()).hexdigest()

    # Collect all source directories: [(base_path, sub_structure), ...]
    # xwechat: attach/<hash>/<YYYY-MM>/Img/<md5>*.dat
    # WeChat Files: MsgAttach/<hash>/Image/<YYYY-MM>/<md5>*.dat
    source_dirs = []
    if ATTACH_DIR:
        p = os.path.join(ATTACH_DIR, username_hash)
        if os.path.isdir(p):
            source_dirs.append(("xwechat", p))
    if MSGATTACH_DIR:
        p = os.path.join(MSGATTACH_DIR, username_hash)
        if os.path.isdir(p):
            source_dirs.append(("wechat", p))

    if not source_dirs:
        return image_map

    # Collect all dat files: {base_md5: (best_path, month)}
    # Priority: _h > no suffix > _W > other (skip _t)
    file_candidates = {}  # base_md5 -> (priority, dat_path, month)

    def _priority(fname):
        """Return a priority number; lower is better"""
        base = fname.rsplit('.', 1)[0]
        if base.endswith('_h'):
            return 0  # high-resolution
        if '_' not in base[-3:]:
            return 1  # original (no suffix)
        if base.endswith('_W'):
            return 2
        return 9  # other

    for src_type, base_path in source_dirs:
        # xwechat: <hash>/<YYYY-MM>/Img/  — list base_path directly to get months
        # wechat:  <hash>/Image/<YYYY-MM>/ — list base_path/Image to get months
        if src_type == "xwechat":
            scan_base = base_path
        else:
            scan_base = os.path.join(base_path, "Image")
        try:
            months = sorted(os.listdir(scan_base))
        except OSError:
            continue
        for month in months:
            if src_type == "xwechat":
                img_dir = os.path.join(base_path, month, "Img")
            else:
                img_dir = os.path.join(scan_base, month)
            if not os.path.isdir(img_dir):
                continue
            try:
                files = os.listdir(img_dir)
            except OSError:
                continue
            for fname in files:
                if not fname.endswith('.dat'):
                    continue
                # Skip thumbnails _t.dat and _t_W.dat
                base_no_ext = fname.rsplit('.', 1)[0]
                if '_t' in base_no_ext.split('_'):
                    continue
                if base_no_ext.endswith('_t') or '_t_' in base_no_ext:
                    continue
                # Extract base md5
                base_md5 = base_no_ext.split('_')[0]
                pri = _priority(fname)
                existing = file_candidates.get(base_md5)
                if not existing or pri < existing[0]:
                    file_candidates[base_md5] = (pri, os.path.join(img_dir, fname), month)

    if not file_candidates:
        return image_map

    decoded_count = 0
    for base_md5, (pri, dat_path, month) in file_candidates.items():
        month_dir = os.path.join(out_dir, "image", month)
        # Check if already decrypted
        existing = glob.glob(os.path.join(month_dir, f"{base_md5}.*"))
        if existing:
            rel = os.path.relpath(existing[0], out_dir).replace("\\", "/")
            image_map[base_md5] = rel
            continue
        img_bytes, fmt = _decrypt_dat_to_bytes(dat_path)
        if not img_bytes or fmt == 'bin':
            continue
        os.makedirs(month_dir, exist_ok=True)
        out_path = os.path.join(month_dir, f"{base_md5}.{fmt}")
        with open(out_path, 'wb') as f:
            f.write(img_bytes)
        image_map[base_md5] = f"image/{month}/{base_md5}.{fmt}"
        decoded_count += 1

    return image_map

MSG_TYPES = {
    1: "Text",
    3: "Image",
    34: "Voice",
    42: "Business Card",
    43: "Video",
    47: "Emoji/Sticker",
    48: "Location",
    49: "Share/File/Mini App",
    10000: "System Message",
    10002: "System Notification",
}

_zstd_ctx = zstd.ZstdDecompressor()

def decompress_zstd(data: bytes) -> str:
    try:
        return _zstd_ctx.decompress(data).decode("utf-8", errors="replace")
    except Exception:
        return ""

def get_content(raw, ct_flag) -> str:
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        if ct_flag == 4:
            return decompress_zstd(raw)
        return raw.decode("utf-8", errors="replace")
    return str(raw)

def safe_dirname(name: str) -> str:
    for ch in r'\/:*?"<>|':
        name = name.replace(ch, "_")
    return name.strip() or "unknown"

def xml_extract(content: str, *tags) -> str:
    """Extract the text of the first matching tag from XML"""
    try:
        root = ET.fromstring(content)
        for tag in tags:
            el = root.find(".//" + tag)
            if el is not None and el.text:
                return el.text
    except Exception:
        pass
    for tag in tags:
        m = re.search(rf"<{tag}>(.*?)</{tag}>", content, re.DOTALL)
        if m:
            return m.group(1).strip()
    return content[:200]

def friendly_content(msg_type: int, content: str) -> str:
    """Return a display-friendly content summary"""
    if msg_type == 1:
        return content
    if msg_type == 3:
        return "[Image]"
    if msg_type == 34:
        return "[Voice]"
    if msg_type == 42:
        title = xml_extract(content, "nickname")
        return f"[Business Card: {title}]"
    if msg_type == 43:
        return "[Video]"
    if msg_type == 47:
        return "[Emoji/Sticker]"
    if msg_type == 48:
        loc = xml_extract(content, "label")
        return f"[Location: {loc}]"
    if msg_type == 49:
        title = xml_extract(content, "title")
        return f"[Share: {title}]" if title else "[File/Link]"
    if msg_type in (10000, 10002):
        return f"[System: {content[:100]}]"
    return content[:200]

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#ededed;font-family:"Helvetica Neue",Arial,sans-serif;font-size:14px}}
.header{{background:#44A848;color:#fff;padding:12px 16px;font-size:17px;font-weight:bold;position:sticky;top:0;z-index:10;box-shadow:0 1px 3px rgba(0,0,0,.3)}}
.chat{{padding:10px 0;max-width:800px;margin:0 auto}}
.date-sep{{text-align:center;margin:12px 0;color:#999;font-size:12px}}
.date-sep span{{background:#ddd;border-radius:10px;padding:2px 10px}}
.msg{{display:flex;align-items:flex-start;margin:6px 12px;max-width:100%}}
.msg.sent{{flex-direction:row-reverse}}
.msg.system{{justify-content:center;margin:4px 12px}}
.msg.system .bubble{{background:transparent;color:#999;font-size:12px;box-shadow:none;border-radius:0;padding:2px 8px}}
.avatar{{width:40px;height:40px;border-radius:6px;background:#7CC;color:#fff;display:flex;align-items:center;justify-content:center;font-size:16px;font-weight:bold;flex-shrink:0}}
.msg.sent .avatar{{background:#4CAF50}}
.msg-body{{max-width:70%;margin:0 8px}}
.sender-name{{font-size:12px;color:#888;margin-bottom:3px}}
.msg.sent .sender-name{{text-align:right}}
.bubble{{display:inline-block;padding:8px 12px;border-radius:6px;word-break:break-word;line-height:1.5;box-shadow:0 1px 2px rgba(0,0,0,.1);white-space:pre-wrap}}
.received .bubble{{background:#fff;border-radius:0 6px 6px 6px}}
.sent .bubble{{background:#95EC69;border-radius:6px 0 6px 6px}}
.bubble img{{max-width:100%;border-radius:4px;display:block;margin:2px 0}}
.type-tag{{font-size:11px;color:#aaa;margin-top:2px}}
</style>
</head>
<body>
<div class="header">{title}</div>
<div class="chat">
{body}
</div>
</body>
</html>
"""

def _html_escape(s: str) -> str:
    return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"','&quot;')

def _write_html(path: str, title: str, is_group: bool, messages: list, image_map: dict = None, out_dir: str = None):
    parts = []
    last_date = None
    for m in messages:
        dt = datetime.fromtimestamp(m["create_time"])
        day = dt.strftime("%B %d, %Y")
        if day != last_date:
            parts.append(f'<div class="date-sep"><span>{day}</span></div>')
            last_date = day

        if m["is_system"]:
            parts.append(
                f'<div class="msg system"><div class="bubble">'
                f'{_html_escape(m["display_content"])}</div></div>'
            )
            continue

        side = "received" if m["is_received"] else "sent"
        initial = (m["sender"] or "?")[0].upper()
        sender_label = ""
        if is_group or m["is_received"]:
            sender_label = f'<div class="sender-name">{_html_escape(m["sender"])}</div>'

        type_tag = ""
        if m["type"] != 1:
            type_tag = f'<div class="type-tag">{m["type_name"]}</div>'

        # Embed image message
        bubble_content = _html_escape(m["display_content"])
        if m["type"] == 3 and image_map and m["local_id"] in image_map:
            rel_path = image_map[m["local_id"]]
            if out_dir:
                abs_img = os.path.join(out_dir, rel_path)
                if os.path.exists(abs_img):
                    ext = os.path.splitext(abs_img)[1].lstrip('.').lower()
                    mime = {'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'png': 'image/png',
                            'gif': 'image/gif', 'webp': 'image/webp'}.get(ext, 'image/jpeg')
                    try:
                        with open(abs_img, 'rb') as imgf:
                            b64 = base64.b64encode(imgf.read()).decode('ascii')
                        bubble_content = f'<img src=\"data:{mime};base64,{b64}\" alt=\"Image\">'
                    except Exception:
                        bubble_content = f'<img src=\"{_html_escape(rel_path)}\" alt=\"Image\">'
                else:
                    bubble_content = f'<img src=\"{_html_escape(rel_path)}\" alt=\"Image\">'
            else:
                bubble_content = f'<img src=\"{_html_escape(rel_path)}\" alt=\"Image\">'

        parts.append(
            f'<div class="msg {side}">'
            f'<div class="avatar">{initial}</div>'
            f'<div class="msg-body">'
            f'{sender_label}'
            f'<div class="bubble">{bubble_content}</div>'
            f'{type_tag}'
            f'<div class="type-tag">{m["time_str"]}</div>'
            f'</div></div>'
        )

    body = "\n".join(parts)
    with open(path, "w", encoding="utf-8") as f:
        f.write(HTML_TEMPLATE.format(title=_html_escape(title), body=body))


# ─── Load contact information ──────────────────────────────────────────────────
contact_map: dict[str, dict] = {}
try:
    cconn = sqlite3.connect(CONTACT_DB_PATH)
    for uname, alias, remark, nick_name in cconn.execute(
        "SELECT username, alias, remark, nick_name FROM contact"
    ):
        contact_map[uname] = {
            "username": uname,
            "alias": alias or "",
            "remark": remark or "",
            "nick_name": nick_name or "",
        }
    cconn.close()
    print(f"Contact database: {len(contact_map)} entries")
except Exception as e:
    print(f"Failed to read contact database: {e}")

def display_name(username: str) -> str:
    info = contact_map.get(username, {})
    return info.get("remark") or info.get("nick_name") or username

# ─── Iterate over all message_*.db files ───────────────────────────────────────
db_files = sorted(
    f for f in glob.glob(os.path.join(MSG_DB_DIR, "message_*.db"))
    if not f.endswith(("_fts.db", "_resource.db"))
)
print(f"Found {len(db_files)} message database(s)")

total_chats = 0
total_msgs = 0

# ── Phase 1: Collect messages for all contacts ───────────────────────────────
# chat_data[chat_username] -> { dname, is_group, db_messages: [(db_name, messages)] }
chat_data: dict[str, dict] = {}

for db_path in sorted(db_files):
    db_name = os.path.basename(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    # rowid -> username mapping
    sender_map: dict[int, str] = {}
    for row in conn.execute("SELECT rowid, user_name FROM Name2Id"):
        sender_map[row[0]] = row[1]

    # Compute username -> hash mapping
    hash_to_username: dict[str, str] = {}
    for username in sender_map.values():
        if username:
            h = hashlib.md5(username.encode()).hexdigest()
            hash_to_username[h] = username

    # Find all Msg_<hash> tables
    all_tables = [
        r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
        )
    ]

    for table_name in all_tables:
        h = table_name[4:]  # strip "Msg_"
        chat_username = hash_to_username.get(h, f"unknown_{h[:8]}")
        if _CONTACT_FILTER and chat_username not in _CONTACT_FILTER:
            continue
        dname = safe_dirname(display_name(chat_username))
        is_group = chat_username.endswith("@chatroom") or chat_username.endswith("@openim")

        # Read all messages from this table
        try:
            rows = conn.execute(
                f"SELECT local_id, server_id, local_type, sort_seq, real_sender_id,"
                f" create_time, status, message_content, WCDB_CT_message_content"
                f" FROM {table_name} ORDER BY sort_seq"
            ).fetchall()
        except Exception as e:
            print(f"  Failed to read {table_name}: {e}")
            continue

        if not rows:
            continue

        messages = []
        for r in rows:
            (local_id, server_id, local_type, sort_seq, real_sender_id,
             create_time, status, raw_content, ct_flag) = tuple(r)

            content = get_content(raw_content, ct_flag or 0)
            sender_uname = sender_map.get(real_sender_id, "")
            sender_dn = display_name(sender_uname) if sender_uname else "Me"
            msg_type_name = MSG_TYPES.get(local_type, f"Unknown({local_type})")
            display_content = friendly_content(local_type, content)
            is_system = local_type in (10000, 10002)

            messages.append({
                "local_id": local_id,
                "server_id": server_id,
                "type": local_type,
                "type_name": msg_type_name,
                "sort_seq": sort_seq,
                "sender_username": sender_uname,
                "sender": sender_dn,
                "create_time": create_time,
                "time_str": datetime.fromtimestamp(create_time).strftime("%Y-%m-%d %H:%M:%S"),
                "status": status,
                "content": content,
                "display_content": display_content,
                "is_system": is_system,
                "is_received": (sender_uname == chat_username) if not is_group else True,
            })

        if chat_username not in chat_data:
            chat_data[chat_username] = {
                "dname": dname, "is_group": is_group, "db_messages": []
            }
        chat_data[chat_username]["db_messages"].append((db_name, messages))

    conn.close()

# ── Phase 2: Decrypt images once per contact, then write output files ────────
total_chats = 0
total_msgs = 0

for chat_username, cdata in chat_data.items():
    dname = cdata["dname"]
    is_group = cdata["is_group"]
    out_dir = os.path.join(OUTPUT_DIR, dname)
    os.makedirs(out_dir, exist_ok=True)

    # ── .info file ───────────────────────────────────────────────────────
    info_path = os.path.join(out_dir, ".info")
    if not os.path.exists(info_path):
        info = contact_map.get(chat_username, {
            "username": chat_username, "alias": "", "remark": "", "nick_name": ""
        })
        with open(info_path, "w", encoding="utf-8") as f:
            f.write(f"username:  {info['username']}\n")
            f.write(f"alias:     {info['alias']}\n")
            f.write(f"nick_name: {info['nick_name']}\n")
            f.write(f"remark:    {info['remark']}\n")
            f.write(f"is_group:  {is_group}\n")

    # ── Decrypt images (executed once per contact) ───────────────────────
    image_md5_map = {}
    if _EXPORT_IMAGES:
        image_md5_map = decode_chat_images(chat_username, None, out_dir)
        if image_md5_map:
            print(f"  Images decrypted: {len(image_md5_map)} ({dname})")

    # ── Write message files per DB ───────────────────────────────────────
    for db_name, messages in cdata["db_messages"]:
        # Build local_id -> rel_path mapping
        image_map = {}
        if image_md5_map:
            for m in messages:
                if m["type"] != 3:
                    continue
                lid = m["local_id"]
                file_md5 = _resource_md5_map.get((chat_username, lid))
                if file_md5 and file_md5 in image_md5_map:
                    image_map[lid] = image_md5_map[file_md5]

        # ── CSV ───────────────────────────────────────────────────────────
        if not _EXPORT_FORMATS or "csv" in _EXPORT_FORMATS:
            csv_path = os.path.join(out_dir, f"{db_name}.csv")
            with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(["Time", "Sender", "Message Type", "Content", "Image Path", "server_id"])
                for m in messages:
                    img_path = image_map.get(m["local_id"], "") if m["type"] == 3 else ""
                    w.writerow([
                        m["time_str"], m["sender"], m["type_name"],
                        m["display_content"], img_path, m["server_id"]
                    ])

        # ── JSON ──────────────────────────────────────────────────────────
        if not _EXPORT_FORMATS or "json" in _EXPORT_FORMATS:
            json_path = os.path.join(out_dir, f"{db_name}.json")
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump({
                    "chat_username": chat_username,
                    "display_name": dname,
                    "is_group": is_group,
                    "message_count": len(messages),
                    "messages": messages,
                }, f, ensure_ascii=False, indent=2)

        # ── HTML ──────────────────────────────────────────────────────────
        if not _EXPORT_FORMATS or "html" in _EXPORT_FORMATS:
            html_path = os.path.join(out_dir, f"{db_name}.html")
            _write_html(html_path, dname, is_group, messages, image_map=image_map, out_dir=out_dir)

        total_chats += 1
        total_msgs += len(messages)
        print(f"  [{db_name}] {dname}: {len(messages)} messages")

print(f"\nDone: {total_chats} conversation(s), {total_msgs} total messages")
print(f"Output directory: {os.path.abspath(OUTPUT_DIR)}")
