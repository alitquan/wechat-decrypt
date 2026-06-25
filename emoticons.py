"""
Emoticon common module — builds MD5→CDN mapping from emoticon.db + download

Shared by monitor_web.py and export_emoticons.py.
"""
import os
import re
import sqlite3
import struct
import tempfile
import urllib.request

from Crypto.Cipher import AES

from key_utils import get_key_info
from decrypt_db import decrypt_page

PAGE_SZ = 4096
WAL_HEADER_SZ = 32
WAL_FRAME_HEADER_SZ = 24


def _full_decrypt(db_path, out_path, enc_key):
    """Fully decrypt the database (skips HMAC verification, suitable for runtime use)."""
    file_size = os.path.getsize(db_path)
    total_pages = file_size // PAGE_SZ
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(db_path, "rb") as fin, open(out_path, "wb") as fout:
        for pgno in range(1, total_pages + 1):
            page = fin.read(PAGE_SZ)
            if len(page) < PAGE_SZ:
                if len(page) > 0:
                    page = page + b"\x00" * (PAGE_SZ - len(page))
                else:
                    break
            fout.write(decrypt_page(enc_key, page, pgno))


def _decrypt_wal(wal_path, out_path, enc_key):
    """Decrypt valid WAL frames and patch them into the decrypted DB copy."""
    if not os.path.exists(wal_path):
        return
    wal_size = os.path.getsize(wal_path)
    if wal_size <= WAL_HEADER_SZ:
        return
    frame_size = WAL_FRAME_HEADER_SZ + PAGE_SZ
    with open(wal_path, "rb") as wf, open(out_path, "r+b") as df:
        wal_hdr = wf.read(WAL_HEADER_SZ)
        wal_salt1 = struct.unpack(">I", wal_hdr[16:20])[0]
        wal_salt2 = struct.unpack(">I", wal_hdr[20:24])[0]
        while wf.tell() + frame_size <= wal_size:
            fh = wf.read(WAL_FRAME_HEADER_SZ)
            if len(fh) < WAL_FRAME_HEADER_SZ:
                break
            pgno = struct.unpack(">I", fh[0:4])[0]
            frame_salt1 = struct.unpack(">I", fh[8:12])[0]
            frame_salt2 = struct.unpack(">I", fh[12:16])[0]
            ep = wf.read(PAGE_SZ)
            if len(ep) < PAGE_SZ:
                break
            if pgno == 0 or pgno > 1000000:
                continue
            if frame_salt1 != wal_salt1 or frame_salt2 != wal_salt2:
                continue
            dec = decrypt_page(enc_key, ep, pgno)
            df.seek((pgno - 1) * PAGE_SZ)
            df.write(dec)


def build_emoji_lookup(keys_dict, db_dir):
    """Build an emoji md5 → URL mapping from emoticon.db.

    Returns: {md5: {cdn_url, aes_key, encrypt_url, caption, product_id}}
    """
    key_info = get_key_info(keys_dict, os.path.join("emoticon", "emoticon.db"))
    if not key_info:
        return {}

    src = os.path.join(db_dir, "emoticon", "emoticon.db")
    if not os.path.exists(src):
        return {}

    dst = os.path.join(tempfile.gettempdir(), "wechat_emoticon_dec.db")
    enc_key = bytes.fromhex(key_info["enc_key"])

    try:
        _full_decrypt(src, dst, enc_key)
        wal = src + "-wal"
        if os.path.exists(wal):
            _decrypt_wal(wal, dst, enc_key)
    except Exception as e:
        print(f"[emoticons] emoticon.db decryption failed: {e}", flush=True)
        return {}

    try:
        conn = sqlite3.connect(f"file:{dst}?mode=ro", uri=True)
        lookup = {}

        # 1. NonStore emoticons (with individual cdn_url)
        rows = conn.execute(
            "SELECT md5, aes_key, cdn_url, encrypt_url, product_id FROM kNonStoreEmoticonTable"
        ).fetchall()
        pkg_cdn_template = {}
        for md5, aes_key, cdn_url, encrypt_url, product_id in rows:
            if md5:
                lookup[md5] = {
                    "cdn_url": cdn_url or "",
                    "aes_key": aes_key or "",
                    "encrypt_url": encrypt_url or "",
                    "product_id": product_id or "",
                }
            if product_id and cdn_url:
                pkg_cdn_template[product_id] = cdn_url

        non_store_count = len(lookup)

        # 2. Store emoticons (attempt to construct cdn_url)
        store_rows = conn.execute(
            "SELECT package_id_, md5_ FROM kStoreEmoticonFilesTable"
        ).fetchall()
        store_added = 0
        for pkg_id, md5 in store_rows:
            if md5 and md5 not in lookup:
                template = pkg_cdn_template.get(pkg_id, "")
                if template and "&" in template:
                    constructed = re.sub(r"m=[0-9a-f]+", f"m={md5}", template)
                    lookup[md5] = {
                        "cdn_url": constructed,
                        "aes_key": "",
                        "encrypt_url": "",
                        "product_id": pkg_id or "",
                    }
                    store_added += 1

        # 3. Collect captions (emoticon descriptions)
        try:
            captions = conn.execute(
                "SELECT md5_, caption_ FROM kStoreEmoticonCaptionsTable WHERE language_='default'"
            ).fetchall()
            for md5, caption in captions:
                if md5 in lookup:
                    lookup[md5]["caption"] = caption or ""
        except Exception:
            pass

        conn.close()
        print(
            f"[emoticons] Loaded {non_store_count} NonStore + {store_added} Store = {len(lookup)} emoticon mappings",
            flush=True,
        )
        return lookup
    except Exception as e:
        print(f"[emoticons] Failed to build mapping: {e}", flush=True)
        return {}
    finally:
        try:
            os.unlink(dst)
        except OSError:
            pass


def convert_hevc_to_jpeg(hevc_path, jpeg_path):
    """Convert a wxgf/HEVC file to JPEG.

    wxgf is WeChat's proprietary format: wxgf header + ICC profile + HEVC NAL units.
    Locates the Annex B stream by scanning for the HEVC VPS start code (00 00 00 01 40 01),
    then decodes the first frame to JPEG using PyAV (ffmpeg).
    """
    try:
        import av

        with open(hevc_path, 'rb') as f:
            data = f.read()

        # Scan for HEVC Annex B VPS start code: 00 00 00 01 40 01
        vps_sig = b'\x00\x00\x00\x01\x40\x01'
        hevc_start = data.find(vps_sig)
        if hevc_start < 0:
            # fallback: look for SPS (00 00 00 01 42 01)
            hevc_start = data.find(b'\x00\x00\x00\x01\x42\x01')
        if hevc_start < 0:
            return None

        # Extract HEVC Annex B stream and decode with PyAV
        h265_path = hevc_path + '.h265'
        with open(h265_path, 'wb') as f:
            f.write(data[hevc_start:])

        try:
            container = av.open(h265_path, format='hevc')
            for frame in container.decode(video=0):
                img = frame.to_image()
                img.save(jpeg_path, "JPEG", quality=90)
                container.close()
                return jpeg_path
            container.close()
        finally:
            if os.path.exists(h265_path):
                os.unlink(h265_path)

    except ImportError:
        pass
    except Exception:
        pass
    return None


def download_emoji(md5, lookup, out_dir):
    """Download a single emoticon from CDN to out_dir; returns filename or None.

    lookup: dict returned by build_emoji_lookup()
    """
    info = lookup.get(md5)
    if not info:
        return None

    # Check if already cached
    for ext in (".gif", ".png", ".jpg", ".webp"):
        cached = os.path.join(out_dir, f"{md5}{ext}")
        if os.path.exists(cached):
            return f"{md5}{ext}"

    cdn_url = info.get("cdn_url", "")
    aes_key = info.get("aes_key", "")
    encrypt_url = info.get("encrypt_url", "")

    data = None
    # Method 1: download directly from cdn_url (unencrypted)
    if cdn_url:
        try:
            req = urllib.request.Request(cdn_url, headers={"User-Agent": "Mozilla/5.0"})
            resp = urllib.request.urlopen(req, timeout=15)
            data = resp.read()
        except Exception:
            pass

    # Method 2: download from encrypt_url + AES-CBC decrypt
    if not data and encrypt_url and aes_key:
        try:
            req = urllib.request.Request(encrypt_url, headers={"User-Agent": "Mozilla/5.0"})
            resp = urllib.request.urlopen(req, timeout=15)
            enc_data = resp.read()
            key_bytes = bytes.fromhex(aes_key)
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv=key_bytes)
            data = cipher.decrypt(enc_data)
            if data:
                pad = data[-1]
                if 1 <= pad <= 16 and data[-pad:] == bytes([pad]) * pad:
                    data = data[:-pad]
        except Exception:
            pass

    if not data or len(data) < 4:
        return None

    # Detect format
    if data[:3] == b"\xff\xd8\xff":
        ext = ".jpg"
    elif data[:4] == b"\x89PNG":
        ext = ".png"
    elif data[:3] == b"GIF":
        ext = ".gif"
    elif data[:4] == b"RIFF":
        ext = ".webp"
    elif data[:4] == b"WXGF" or b"\x00\x00\x00\x01\x40\x01" in data[:256]:
        # wxgf/wxam (HEVC): save to temp file first, then convert to JPEG
        os.makedirs(out_dir, exist_ok=True)
        tmp_path = os.path.join(out_dir, f"{md5}.wxgf")
        with open(tmp_path, "wb") as f:
            f.write(data)
        jpg_path = os.path.join(out_dir, f"{md5}.jpg")
        if convert_hevc_to_jpeg(tmp_path, jpg_path):
            os.unlink(tmp_path)
            return f"{md5}.jpg"
        # Conversion failed, keep as .bin
        os.replace(tmp_path, os.path.join(out_dir, f"{md5}.bin"))
        return f"{md5}.bin"
    else:
        ext = ".bin"

    os.makedirs(out_dir, exist_ok=True)
    out_name = f"{md5}{ext}"
    out_path = os.path.join(out_dir, out_name)
    with open(out_path, "wb") as f:
        f.write(data)
    return out_name
