"""Export WeChat Moments posts (SnsTimeLine table)

Output dir:   <output_base_dir>/<display_name>/SNS/<yyyyMMddHHmmss000>.json
Media files:  <output_base_dir>/<display_name>/SNS/<yyyyMMddHHmmss000>_<n>.<ext>
Summary file: <output_base_dir>/<display_name>/SNS/timeline.json
Timeline:     <output_base_dir>/<display_name>/SNS/timeline.html
"""
import base64
import binascii
import bisect
import html
import os
import sys
import json
import sqlite3
import struct
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError

import zstandard as zstd

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from config import load_config
from decode_image import aligned_aes_block_size

# Moments XML comes from untrusted input (other users' post content) — XXE must be blocked.
# Uses the same filter pattern as mcp_server._XML_UNSAFE_RE; max_len is more lenient than
# mcp_server (Moments timeline XML includes media lists + comments, can reach tens of KB in
# practice; 200K headroom given).
_SNS_XML_UNSAFE_RE = re.compile(r'<!DOCTYPE|<!ENTITY', re.IGNORECASE)
_SNS_XML_MAX_LEN = 200_000

# SnsTimeLine.content can appear in 4 encoding forms (different WeChat versions/eras):
#   1. bytes (zstd compressed, magic 28 B5 2F FD) or raw UTF-8 bytes
#   2. already a plain XML string
#   3. hex string (all 0-9a-f, even length)
#   4. base64 string (A-Za-z0-9+/=)
# When fed directly to ET.fromstring, the last three fail silently with ParseError,
# causing the entire row to be lost.
_SNS_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_SNS_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_SNS_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]+$")

# 2013-2017 legacy Moments XML contains characters ElementTree cannot accept:
#   - bare & (in URL query strings, should be &amp;)
#   - bare < > in text fields (user-typed angle brackets in contentDesc etc.)
#   - control characters (\x00-\x08 etc., forbidden in XML 1.0)
# & < > inside CDATA blocks are valid and must not be touched — CDATA blocks must be
# identified first before sanitizing the surrounding text.
_SNS_INVALID_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_SNS_CDATA_BLOCK_RE = re.compile(r"<!\[CDATA\[.*?\]\]>", re.DOTALL)
_SNS_BARE_AMP_RE = re.compile(
    r"&(?!(amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)"
)
_SNS_TEXT_ONLY_NODES = (
    "content", "title", "description", "nickname", "contentDesc",
    "appname", "sourceName", "sourcename", "poiName", "displayName",
    "feeddesc",
)
_SNS_TEXT_NODE_RE = re.compile(
    r"(<(" + "|".join(_SNS_TEXT_ONLY_NODES) + r")\b[^>]*>)(.*?)(</\2>)",
    re.DOTALL,
)


def _decode_sns_content_blob(value):
    """Convert a SnsTimeLine.content column value (any encoding form) to a UTF-8 XML string.

    For bytes, zstd decompression is tried first; strings are detected in order:
    plain XML / hex / base64.
    If unrecognized, returns the string form of the original value so the caller's
    ET.fromstring raises a natural ParseError.
    None / empty value -> empty string.
    """
    if value is None:
        return ""

    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if raw.startswith(_SNS_ZSTD_MAGIC):
            try:
                raw = zstd.ZstdDecompressor().decompress(raw)
            except Exception:
                pass
        return html.unescape(raw.decode("utf-8", errors="ignore").strip())

    text = str(value).strip()
    if not text:
        return ""
    if text.lstrip().startswith("<"):
        return html.unescape(text)

    compact = "".join(text.split())
    if len(compact) >= 16 and len(compact) % 2 == 0 and _SNS_HEX_RE.match(compact):
        try:
            return _decode_sns_content_blob(bytes.fromhex(compact))
        except ValueError:
            pass
    if len(compact) >= 24 and len(compact) % 4 == 0 and _SNS_BASE64_RE.match(compact):
        try:
            return _decode_sns_content_blob(base64.b64decode(compact, validate=True))
        except (ValueError, binascii.Error):
            pass
    return html.unescape(text)


def _sanitize_sns_pseudo_xml(xml_text):
    """Fix illegal characters in WeChat legacy Moments XML so ElementTree can parse it.

    CDATA blocks are left untouched; bare & outside them is converted to &amp;.
    Bare < > inside text-only nodes (content/title/description/...) are escaped.
    Control characters are stripped outright.
    """
    s = _SNS_INVALID_CTRL_RE.sub("", xml_text)
    parts = []
    last = 0
    for m in _SNS_CDATA_BLOCK_RE.finditer(s):
        head = s[last:m.start()]
        parts.append(_SNS_BARE_AMP_RE.sub("&amp;", head))
        parts.append(m.group(0))
        last = m.end()
    parts.append(_SNS_BARE_AMP_RE.sub("&amp;", s[last:]))
    out = "".join(parts)

    def _esc(m):
        open_tag, _, text, close_tag = (
            m.group(1), m.group(2), m.group(3), m.group(4)
        )
        return (
            open_tag
            + text.replace("<", "&lt;").replace(">", "&gt;")
            + close_tag
        )

    return _SNS_TEXT_NODE_RE.sub(_esc, out)

_cfg = load_config()
DECRYPTED_DIR = _cfg["decrypted_dir"]
SNS_DB_PATH = os.path.join(DECRYPTED_DIR, "sns", "sns.db")
CONTACT_DB_PATH = os.path.join(DECRYPTED_DIR, "contact", "contact.db")
OUTPUT_DIR = _cfg["output_base_dir"]

# Image cache / decryption configuration
IMAGE_AES_KEY = _cfg.get("image_aes_key")
IMAGE_XOR_KEY = _cfg.get("image_xor_key", 0x88)
XWECHAT_CACHE_DIR = _cfg.get("xwechat_cache_dir", "")
SNS_CACHE_DIR = _cfg.get("sns_cache_dir", "")

# Contact filter (consistent with export_messages.py)
_CONTACT_FILTER = None
_filter_raw = os.environ.get("WECHAT_EXPORT_CONTACTS", "").strip()
if _filter_raw:
    _CONTACT_FILTER = set(_filter_raw.split(","))
    print(f"Moments contact filter: {len(_CONTACT_FILTER)} contacts")

# ── Media download ───────────────────────────────────────────────────────────

_DOWNLOAD_TIMEOUT = 10  # seconds

# ── Local cache image decryption & matching ──────────────────────────────────

_V2_MAGIC = b'\x07\x08V2\x08\x07'
_V1_MAGIC = b'\x07\x08V1\x08\x07'
_IMAGE_MAGICS = {
    'jpg': [0xFF, 0xD8, 0xFF],
    'png': [0x89, 0x50, 0x4E, 0x47],
    'gif': [0x47, 0x49, 0x46, 0x38],
    'webp': [0x52, 0x49, 0x46, 0x46],
}
_TIME_WINDOW = 72 * 3600  # 72 hours


def _decrypt_sns_dat(dat_path):
    """Decrypt an SNS cache .dat file; returns bytes or None."""
    try:
        with open(dat_path, 'rb') as f:
            data = f.read()
    except OSError:
        return None
    if len(data) < 15:
        return None

    head6 = data[:6]

    # V2 / V1 format (xwechat cache)
    if head6 in (_V2_MAGIC, _V1_MAGIC):
        aes_key = None
        if head6 == _V1_MAGIC:
            aes_key = b'cfcd208495d565ef'
        elif IMAGE_AES_KEY:
            aes_key = IMAGE_AES_KEY.encode('ascii')[:16] if isinstance(IMAGE_AES_KEY, str) else IMAGE_AES_KEY[:16]
        if not aes_key or len(aes_key) < 16:
            return None
        try:
            from Crypto.Cipher import AES
            from Crypto.Util import Padding
            aes_size, xor_size = struct.unpack_from('<LL', data, 6)
            aligned = aligned_aes_block_size(aes_size)
            offset = 15
            if offset + aligned > len(data):
                return None
            cipher = AES.new(aes_key[:16], AES.MODE_ECB)
            dec_aes = Padding.unpad(cipher.decrypt(data[offset:offset + aligned]), AES.block_size)
            offset += aligned
            raw_end = len(data) - xor_size
            raw_data = data[offset:raw_end] if offset < raw_end else b''
            xor_data = data[raw_end:]
            xor_key = IMAGE_XOR_KEY if isinstance(IMAGE_XOR_KEY, int) else 0x88
            dec_xor = bytes(b ^ xor_key for b in xor_data)
            return dec_aes + raw_data + dec_xor
        except Exception:
            return None

    # Legacy XOR format (FileStorage Sns Cache)
    for magic in _IMAGE_MAGICS.values():
        key = data[0] ^ magic[0]
        if all(i < len(data) and (data[i] ^ key) == magic[i] for i in range(len(magic))):
            return bytes(b ^ key for b in data)

    return None


def _detect_format(header):
    """Detect the image format of decrypted data; returns the file extension."""
    if header[:3] == b'\xff\xd8\xff':
        return 'jpg'
    if header[:4] == b'\x89PNG':
        return 'png'
    if header[:3] == b'GIF':
        return 'gif'
    if header[:4] == b'RIFF' and len(header) >= 12 and header[8:12] == b'WEBP':
        return 'webp'
    return 'bin'


def _image_size_from_bytes(data):
    """Extract (width, height) from decrypted image data; returns (0, 0) on failure."""
    if not data or len(data) < 24:
        return 0, 0

    # PNG: IHDR is at bytes 16-24
    if data[:4] == b'\x89PNG':
        w = struct.unpack('>I', data[16:20])[0]
        h = struct.unpack('>I', data[20:24])[0]
        return w, h

    # JPEG: find SOF marker
    if data[:2] == b'\xff\xd8':
        i = 2
        while i < len(data) - 9:
            if data[i] != 0xFF:
                break
            marker = data[i + 1]
            if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
                h = struct.unpack('>H', data[i + 5:i + 7])[0]
                w = struct.unpack('>H', data[i + 7:i + 9])[0]
                return w, h
            if i + 3 >= len(data):
                break
            seg_len = struct.unpack('>H', data[i + 2:i + 4])[0]
            i += 2 + seg_len
        return 0, 0

    # WEBP VP8 format
    if data[:4] == b'RIFF' and len(data) >= 30 and data[8:12] == b'WEBP':
        if data[12:16] == b'VP8 ':
            w = struct.unpack('<H', data[26:28])[0] & 0x3FFF
            h = struct.unpack('<H', data[28:30])[0] & 0x3FFF
            return w, h

    return 0, 0


def _build_sns_cache_index():
    """Scan the SNS cache directory, pre-decrypt file headers to extract metadata.

    Returns an index sorted by mtime:
    [(mtime, path, est_dec_size, fmt, width, height), ...]
    """
    raw_paths = []  # collect all paths first

    # 1. xwechat cache: <cache_dir>/YYYY-MM/Sns/Img/<2hex>/<30hex>
    if XWECHAT_CACHE_DIR and os.path.isdir(XWECHAT_CACHE_DIR):
        for month_dir in os.listdir(XWECHAT_CACHE_DIR):
            sns_img = os.path.join(XWECHAT_CACHE_DIR, month_dir, "Sns", "Img")
            if not os.path.isdir(sns_img):
                continue
            for sub in os.listdir(sns_img):
                sub_path = os.path.join(sns_img, sub)
                if not os.path.isdir(sub_path):
                    continue
                for fname in os.listdir(sub_path):
                    fp = os.path.join(sub_path, fname)
                    if os.path.isfile(fp):
                        raw_paths.append(fp)

    # 2. FileStorage Sns Cache: <sns_cache_dir>/YYYY-MM/<hash>
    if SNS_CACHE_DIR and os.path.isdir(SNS_CACHE_DIR):
        for month_dir in os.listdir(SNS_CACHE_DIR):
            month_path = os.path.join(SNS_CACHE_DIR, month_dir)
            if not os.path.isdir(month_path):
                continue
            for fname in os.listdir(month_path):
                if fname.endswith('_t'):  # skip thumbnails
                    continue
                fp = os.path.join(month_path, fname)
                if os.path.isfile(fp):
                    raw_paths.append(fp)

    if not raw_paths:
        return []

    print(f"  Pre-reading metadata for {len(raw_paths)} cache files...")

    # Prepare AES key (avoid reconstructing it on every loop iteration)
    aes_key = None
    if IMAGE_AES_KEY:
        aes_key = IMAGE_AES_KEY.encode('ascii')[:16] if isinstance(IMAGE_AES_KEY, str) else IMAGE_AES_KEY[:16]

    entries = []
    for path in raw_paths:
        try:
            fsize = os.path.getsize(path)
            mtime = os.path.getmtime(path)
            if fsize < 15:
                continue

            with open(path, 'rb') as f:
                data = f.read(min(fsize, 4096))

            head6 = data[:6]
            dec_header = None
            est_dec_size = fsize

            if head6 in (_V2_MAGIC, _V1_MAGIC):
                # V2/V1: decrypt the AES portion to obtain the file header
                k = b'cfcd208495d565ef' if head6 == _V1_MAGIC else aes_key
                if not k or len(k) < 16:
                    continue
                try:
                    from Crypto.Cipher import AES as _AES
                    aes_size, xor_size = struct.unpack_from('<LL', data, 6)
                    aligned = aligned_aes_block_size(aes_size)
                    est_dec_size = fsize - 15 - (aligned - aes_size)
                    available = min(aligned, len(data) - 15)
                    # align to 16-byte blocks (ECB can decrypt block by block)
                    usable = (available // 16) * 16
                    if usable < 16:
                        continue
                    cipher = _AES.new(k[:16], _AES.MODE_ECB)
                    dec_header = cipher.decrypt(data[15:15 + usable])
                except Exception:
                    continue
            else:
                # XOR format
                for magic in _IMAGE_MAGICS.values():
                    key = data[0] ^ magic[0]
                    if all(i < len(data) and (data[i] ^ key) == magic[i] for i in range(len(magic))):
                        dec_header = bytes(b ^ key for b in data[:4096])
                        est_dec_size = fsize
                        break

            if dec_header is None:
                continue

            fmt = _detect_format(dec_header[:16])
            if fmt == 'bin':
                continue

            w, h = _image_size_from_bytes(dec_header)
            entries.append((mtime, path, est_dec_size, fmt, w, h))
        except OSError:
            continue

    entries.sort(key=lambda x: x[0])
    return entries


def _match_cache_images(create_time, media_list, index, index_mtimes):
    """Match local cache images for all media items in a post (metadata index only, no decryption).

    Returns: [(matched_path, fmt), ...] same length as media_list; unmatched entries are (None, None).
    """
    results = []
    if not index or not media_list:
        return [(None, None)] * len(media_list)

    t_low = create_time - _TIME_WINDOW
    t_high = create_time + _TIME_WINDOW
    lo = bisect.bisect_left(index_mtimes, t_low)
    hi = bisect.bisect_right(index_mtimes, t_high)

    # If the time window is empty (abnormal xwechat cache mtime), expand to all entries
    if lo >= hi:
        lo, hi = 0, len(index)

    used_paths = set()

    for media in media_list:
        mtype = media.get("type", "")
        if mtype not in ("2", ""):
            results.append((None, None))
            continue

        want_w = int(media.get("width") or 0)
        want_h = int(media.get("height") or 0)
        want_size = int(media.get("total_size") or 0)

        candidates = []  # (score, path, fmt)

        for i in range(lo, hi):
            mtime_i, path_i, dec_size_i, fmt_i, w_i, h_i = index[i]
            if path_i in used_paths:
                continue

            # dimensions match
            if want_w > 0 and want_h > 0 and w_i > 0 and h_i > 0:
                if w_i != want_w or h_i != want_h:
                    continue

            # file size match
            if want_size > 0:
                if dec_size_i > want_size * 3 or dec_size_i < want_size * 0.3:
                    continue

            size_diff = abs(dec_size_i - want_size) if want_size > 0 else 0
            time_diff = abs(mtime_i - create_time)
            candidates.append((size_diff, time_diff, path_i, fmt_i))

        if candidates:
            candidates.sort(key=lambda x: (x[0], x[1]))
            best = candidates[0]
            used_paths.add(best[2])
            results.append((best[2], best[3]))
        else:
            results.append((None, None))

    return results

# ContentObject type meanings (known values)
_CONTENT_TYPES = {
    1: "Image+Text",
    2: "Text only",
    3: "Link",
    5: "Video link",
    7: "Location",
    15: "Video",
    28: "Short video",
    30: "Music",
    34: "Note",
    42: "Mini program",
    54: "Live stream",
}


def _try_download_media(url, save_path):
    """Attempt to download a media file; returns True/False.

    WeChat Moments images from shmmsns.qpic.cn require a Referer and User-Agent header.
    Note: the data returned by the URL may be encrypted (enc_idx=1 case);
    the decryption algorithm is not publicly known, so downloaded files may not be
    directly viewable. Returns False on failure; replace with more complex download
    logic if needed.
    """
    if not url or not url.startswith("http"):
        return False
    try:
        req = Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.0.0 Safari/537.36",
            "Referer": "https://weixin.qq.com/",
        })
        with urlopen(req, timeout=_DOWNLOAD_TIMEOUT) as resp:
            if resp.status != 200:
                return False
            data = resp.read()
            if len(data) < 100:
                return False
            # detect format
            if data[:3] == b'\xff\xd8\xff':
                ext = '.jpg'
            elif data[:4] == b'\x89PNG':
                ext = '.png'
            elif data[:4] == b'GIF8':
                ext = '.gif'
            elif data[:4] == b'RIFF' and data[8:12] == b'WEBP':
                ext = '.webp'
            else:
                ext = '.bin'
            if not os.path.splitext(save_path)[1]:
                save_path += ext
            with open(save_path, 'wb') as f:
                f.write(data)
            return True
    except (URLError, OSError, Exception):
        return False


def _parse_media_list(timeline_obj):
    """Parse the mediaList inside a TimelineObject; returns a list of media info dicts."""
    medias = []
    for media_el in timeline_obj.findall('.//media'):
        media_type = media_el.findtext('type', '')
        sub_type = media_el.findtext('sub_type', '')
        vid_duration = media_el.findtext('videoDuration', '0')

        thumb_el = media_el.find('thumb')
        url_el = media_el.find('url')
        size_el = media_el.find('size')

        info = {
            "type": media_type,
            "sub_type": sub_type,
            "video_duration": vid_duration,
        }

        if thumb_el is not None:
            info["thumb_url"] = thumb_el.text or ""
            info["thumb_key"] = thumb_el.get("key", "")
            info["thumb_token"] = thumb_el.get("token", "")

        if url_el is not None:
            info["url"] = url_el.text or ""
            info["url_md5"] = url_el.get("md5", "")
            info["url_key"] = url_el.get("key", "")
            info["url_token"] = url_el.get("token", "")

        if size_el is not None:
            info["width"] = size_el.get("width", "")
            info["height"] = size_el.get("height", "")
            info["total_size"] = size_el.get("totalSize", "")

        medias.append(info)
    return medias


def _parse_timeline_xml(content_xml):
    """Parse the Content XML of a SnsTimeLine row; returns structured data.

    content_xml may be bytes / zstd bytes / hex string / base64 string / plain XML.
    It is decoded first, then legacy XML dirt (bare & < > and control characters) is
    sanitized before being passed to ET.
    """
    if not content_xml:
        return None
    decoded = _decode_sns_content_blob(content_xml)
    if not decoded:
        return None
    if len(decoded) > _SNS_XML_MAX_LEN:
        return None
    if _SNS_XML_UNSAFE_RE.search(decoded):
        # XXE protection: reject DOCTYPE/ENTITY to prevent malicious Moments XML from
        # performing SSRF or reading local files via entity expansion or external entity refs.
        return None
    try:
        root = ET.fromstring(_sanitize_sns_pseudo_xml(decoded))
    except ET.ParseError:
        return None

    tl = root.find('.//TimelineObject')
    if tl is None:
        return None

    create_time_str = tl.findtext('createTime', '0')
    try:
        create_time = int(create_time_str)
    except ValueError:
        create_time = 0

    content_type = tl.findtext('.//ContentObject/type', '0')
    try:
        content_type_int = int(content_type)
    except ValueError:
        content_type_int = 0

    # parse location
    loc_el = tl.find('.//location')
    location = None
    if loc_el is not None:
        lat = loc_el.get('latitude', '0')
        lon = loc_el.get('longitude', '0')
        if lat != '0' or lon != '0':
            location = {
                "latitude": lat,
                "longitude": lon,
                "poi_name": loc_el.get("poiName", ""),
            }

    return {
        "id": tl.findtext('id', ''),
        "username": tl.findtext('username', ''),
        "create_time": create_time,
        "create_time_str": datetime.fromtimestamp(create_time).strftime("%Y-%m-%d %H:%M:%S") if create_time else "",
        "content_desc": tl.findtext('contentDesc', ''),
        "content_type": content_type_int,
        "content_type_name": _CONTENT_TYPES.get(content_type_int, f"Unknown({content_type_int})"),
        "nickname": root.findtext('.//LocalExtraInfo/nickname', ''),
        "is_private": tl.findtext('private', '0') == '1',
        "location": location,
        "media": _parse_media_list(tl),
    }


def _load_comments(conn):
    """Load comments/likes from SnsMessage_tmp3, grouped by feed_id.

    `del_status != 0` means the other party retracted the interaction — WeChat does not
    actually delete it locally, only sets a deletion flag. Not filtering these would
    export already-retracted likes/comments. COALESCE treats NULL as 0 for older schemas
    that lack the column.
    """
    comments = {}
    try:
        rows = conn.execute(
            "SELECT feed_id, create_time, type, from_username, from_nickname,"
            " to_username, to_nickname, content"
            " FROM SnsMessage_tmp3 WHERE COALESCE(del_status, 0) = 0"
            " ORDER BY create_time"
        ).fetchall()
        for feed_id, ctime, ctype, from_u, from_n, to_u, to_n, content in rows:
            if feed_id not in comments:
                comments[feed_id] = []
            comments[feed_id].append({
                "create_time": ctime,
                "create_time_str": datetime.fromtimestamp(ctime).strftime("%Y-%m-%d %H:%M:%S") if ctime else "",
                "type": ctype,  # 1=like, 2=comment
                "type_name": "Like" if ctype == 1 else "Comment" if ctype == 2 else f"Unknown({ctype})",
                "from_username": from_u or "",
                "from_nickname": from_n or "",
                "to_username": to_u or "",
                "to_nickname": to_n or "",
                "content": content or "",
            })
    except Exception as e:
        print(f"Failed to read comment data: {e}")
    return comments


def _safe_dirname(name: str) -> str:
    """Strip illegal characters from a directory name."""
    for ch in r'\/:*?"<>|':
        name = name.replace(ch, "_")
    return name.strip() or "unknown"


def _load_contact_map():
    """Load {username: display_name} from contact.db."""
    cmap = {}
    if not os.path.exists(CONTACT_DB_PATH):
        return cmap
    try:
        conn = sqlite3.connect(CONTACT_DB_PATH)
        for uname, remark, nick_name in conn.execute(
            "SELECT username, remark, nick_name FROM contact"
        ):
            dname = remark or nick_name or uname
            cmap[uname] = _safe_dirname(dname)
        conn.close()
    except Exception as e:
        print(f"Failed to read contact database: {e}")
    return cmap


def _timestamp_filename(unix_ts):
    """Unix timestamp -> yyyyMMddHHmmss000 filename (millisecond part is 000)."""
    if not unix_ts:
        return "00000000000000000"
    dt = datetime.fromtimestamp(unix_ts)
    return dt.strftime("%Y%m%d%H%M%S") + "000"


def _html_escape(text):
    """Simple HTML escaping."""
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _generate_timeline_html(display_name, posts, sns_dir, image_files):
    """Generate a Moments timeline HTML file.

    Args:
        display_name: contact display name
        posts: list of posts in reverse-chronological order
        sns_dir: SNS output directory
        image_files: {final_name: [(rel_path, ext), ...]} image file list per post
    """
    html_path = os.path.join(sns_dir, "timeline.html")
    parts = [f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_html_escape(display_name)} - Moments</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; background: #f5f5f5; color: #333; }}
h1 {{ text-align: center; color: #07c160; border-bottom: 2px solid #07c160; padding-bottom: 10px; }}
.stats {{ text-align: center; color: #888; margin-bottom: 30px; font-size: 14px; }}
.post {{ background: #fff; border-radius: 10px; padding: 16px 20px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
.post-time {{ font-size: 12px; color: #999; margin-bottom: 8px; }}
.post-type {{ display: inline-block; font-size: 11px; background: #e8f5e9; color: #2e7d32; padding: 1px 6px; border-radius: 3px; margin-left: 8px; }}
.post-text {{ margin: 8px 0; white-space: pre-wrap; word-break: break-word; line-height: 1.6; }}
.post-images {{ display: flex; flex-wrap: wrap; gap: 6px; margin: 10px 0; }}
.post-images img {{ max-width: 240px; max-height: 240px; border-radius: 6px; object-fit: cover; cursor: pointer; }}
.post-images img:hover {{ opacity: 0.85; }}
.post-location {{ font-size: 12px; color: #1a73e8; margin: 4px 0; }}
.comments {{ margin-top: 10px; padding-top: 8px; border-top: 1px solid #f0f0f0; }}
.comment {{ font-size: 13px; color: #555; margin: 4px 0; line-height: 1.5; }}
.comment-name {{ color: #576b95; font-weight: 500; }}
.comment-like {{ color: #e64a19; }}
.private-tag {{ font-size: 11px; background: #fff3e0; color: #e65100; padding: 1px 6px; border-radius: 3px; margin-left: 6px; }}
</style>
</head>
<body>
<h1>{_html_escape(display_name)}'s Moments</h1>
<div class="stats">{len(posts)} posts total</div>
"""]

    for post in posts:
        final_name = post.get("_final_name", "")
        time_str = _html_escape(post.get("create_time_str", ""))
        type_name = _html_escape(post.get("content_type_name", ""))
        text = _html_escape(post.get("content_desc", ""))
        is_private = post.get("is_private", False)

        parts.append('<div class="post">')
        parts.append(f'<div class="post-time">{time_str}<span class="post-type">{type_name}</span>')
        if is_private:
            parts.append('<span class="private-tag">Visible to self only</span>')
        parts.append('</div>')

        if text:
            parts.append(f'<div class="post-text">{text}</div>')

        # images
        imgs = image_files.get(final_name, [])
        if imgs:
            parts.append('<div class="post-images">')
            for rel_path, _ in imgs:
                parts.append(f'<img src="{_html_escape(rel_path)}" loading="lazy" onclick="window.open(this.src)">')
            parts.append('</div>')

        # location
        loc = post.get("location")
        if loc and loc.get("poi_name"):
            parts.append(f'<div class="post-location">📍 {_html_escape(loc["poi_name"])}</div>')

        # comments
        comments = post.get("comments", [])
        if comments:
            parts.append('<div class="comments">')
            for c in comments:
                if c.get("type") == 1:
                    parts.append(f'<div class="comment comment-like">❤️ <span class="comment-name">{_html_escape(c["from_nickname"])}</span></div>')
                else:
                    to_part = ""
                    if c.get("to_nickname"):
                        to_part = f' replied to <span class="comment-name">{_html_escape(c["to_nickname"])}</span>'
                    parts.append(f'<div class="comment"><span class="comment-name">{_html_escape(c["from_nickname"])}</span>{to_part}: {_html_escape(c.get("content", ""))}</div>')
            parts.append('</div>')

        parts.append('</div>')

    parts.append('</body></html>')

    with open(html_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(parts))
    return html_path


def export_sns_timeline():
    """Main function for exporting Moments posts."""
    if not os.path.exists(SNS_DB_PATH):
        print(f"Moments database not found: {SNS_DB_PATH}")
        print("Please run 'Decrypt Database' first.")
        return

    # load contacts
    contact_map = _load_contact_map()
    print(f"Contacts: {len(contact_map)}")

    conn = sqlite3.connect(SNS_DB_PATH)

    # load comments
    print("Loading comment data...")
    comments_map = _load_comments(conn)
    print(f"Comments/likes: {sum(len(v) for v in comments_map.values())}")

    # read all posts
    print("Reading Moments posts...")
    rows = conn.execute(
        "SELECT tid, user_name, content FROM SnsTimeLine WHERE content IS NOT NULL"
    ).fetchall()
    conn.close()

    print(f"Total: {len(rows)} posts")
    if not rows:
        return

    # whether to attempt media download
    try_download = os.environ.get("WECHAT_SNS_DOWNLOAD_MEDIA", "0").strip() == "1"

    # ── Build cache index ─────────────────────────────────────────────────────
    print("Scanning SNS image cache...")
    cache_index = _build_sns_cache_index()
    index_mtimes = [e[0] for e in cache_index]
    print(f"Cache index: {len(cache_index)} valid image files")

    # ── Group by user_name ────────────────────────────────────────────────────
    user_posts: dict[str, list] = {}  # user_name -> [post, ...]
    user_nicknames: dict[str, str] = {}  # user_name -> nickname (extracted from XML)
    skipped = 0

    for tid, user_name, content_xml in rows:
        if not content_xml:
            continue
        if _CONTACT_FILTER and user_name not in _CONTACT_FILTER:
            skipped += 1
            continue

        post = _parse_timeline_xml(content_xml)
        if not post:
            continue

        post["tid"] = tid
        post["db_user_name"] = user_name or ""
        post["comments"] = comments_map.get(tid, [])

        key = user_name or "unknown"
        if key not in user_posts:
            user_posts[key] = []
        user_posts[key].append(post)

        # 记录 nickname（取第一个非空的）
        nick = post.get("nickname", "")
        if nick and key not in user_nicknames:
            user_nicknames[key] = nick

    if skipped:
        print(f"Filtered out: {skipped} posts")

    # ── Output per contact ────────────────────────────────────────────────────
    total_posts = 0
    cache_match_ok = 0
    cache_match_fail = 0
    media_download_ok = 0
    media_download_fail = 0

    for user_name, posts in user_posts.items():
        dname = contact_map.get(user_name) or _safe_dirname(
            user_nicknames.get(user_name) or user_name
        )
        sns_dir = os.path.join(OUTPUT_DIR, dname, "SNS")
        os.makedirs(sns_dir, exist_ok=True)

        # use a set to handle filename collisions when multiple posts share the same second
        used_names = set()
        # image_files: {final_name: [(rel_path, ext), ...]} used for HTML generation
        image_files: dict[str, list] = {}

        posts.sort(key=lambda p: p.get("create_time", 0))

        for post in posts:
            ts_name = _timestamp_filename(post.get("create_time"))
            # 处理冲突: 递增末尾毫秒
            final_name = ts_name
            counter = 1
            while final_name in used_names:
                final_name = ts_name[:-3] + f"{counter:03d}"
                counter += 1
            used_names.add(final_name)
            post["_final_name"] = final_name

            # ── Cache image matching ──────────────────────────────────
            media_list = post.get("media", [])
            if media_list and cache_index:
                matches = _match_cache_images(
                    post.get("create_time", 0), media_list,
                    cache_index, index_mtimes,
                )
                for i, (matched_path, fmt) in enumerate(matches):
                    if matched_path is not None:
                        dec_bytes = _decrypt_sns_dat(matched_path)
                        if dec_bytes:
                            ext = _detect_format(dec_bytes[:16])
                            img_name = f"{final_name}_{i}.{ext}"
                            img_path = os.path.join(sns_dir, img_name)
                            with open(img_path, 'wb') as f:
                                f.write(dec_bytes)
                            if final_name not in image_files:
                                image_files[final_name] = []
                            image_files[final_name].append((img_name, ext))
                            cache_match_ok += 1
                            continue
                        cache_match_fail += 1
                    else:
                        cache_match_fail += 1

            # ── Network download (only for media not matched from cache) ──────
            if try_download and media_list:
                existing_imgs = image_files.get(final_name, [])
                existing_indices = {int(p.rsplit('_', 1)[1].split('.')[0]) for p, _ in existing_imgs} if existing_imgs else set()
                for i, media in enumerate(media_list):
                    if i in existing_indices:
                        continue
                    media_url = media.get("url", "") or media.get("thumb_url", "")
                    if not media_url:
                        continue
                    save_name = os.path.join(sns_dir, f"{final_name}_{i}")
                    if _try_download_media(media_url, save_name):
                        # update image_files after successful download
                        for cand_ext in ('.jpg', '.png', '.gif', '.webp', '.bin'):
                            if os.path.exists(save_name + cand_ext):
                                if final_name not in image_files:
                                    image_files[final_name] = []
                                image_files[final_name].append((f"{final_name}_{i}{cand_ext}", cand_ext[1:]))
                                break
                        media_download_ok += 1
                    else:
                        media_download_fail += 1

            # save JSON (strip internal fields)
            post_out = {k: v for k, v in post.items() if not k.startswith("_")}
            post_file = os.path.join(sns_dir, f"{final_name}.json")
            with open(post_file, 'w', encoding='utf-8') as f:
                json.dump(post_out, f, ensure_ascii=False, indent=2)

            total_posts += 1

        # per-contact summary JSON
        posts.sort(key=lambda p: p.get("create_time", 0), reverse=True)
        summary_posts = [{k: v for k, v in p.items() if not k.startswith("_")} for p in posts]
        summary_path = os.path.join(sns_dir, "timeline.json")
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump({
                "user_name": user_name,
                "display_name": dname,
                "export_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_posts": len(posts),
                "posts": summary_posts,
            }, f, ensure_ascii=False, indent=2)

        # generate HTML timeline
        _generate_timeline_html(dname, posts, sns_dir, image_files)

        print(f"  {dname}: {len(posts)} posts")

    print(f"\nDone: {len(user_posts)} contacts, {total_posts} posts total")
    if cache_index:
        print(f"Cache matches: {cache_match_ok} succeeded, {cache_match_fail} failed")
    if try_download:
        print(f"Media downloads: {media_download_ok} succeeded, {media_download_fail} failed")
    print(f"Output directory: {os.path.abspath(OUTPUT_DIR)}")


if __name__ == "__main__":
    export_sns_timeline()
