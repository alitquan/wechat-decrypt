"""Decrypt WeChat Moments (SNS) image cache
Source 1: WeChat Files/FileStorage/Sns/Cache/<YYYY-MM>/<hash>[_t|_d]
Source 2: xwechat_files/cache/<YYYY-MM>/Sns/Img/<hex>/<hash>
Output directory: <output_base_dir>/Moments Images/<YYYY-MM>/
_t suffix = thumbnail (skipped)
"""
import os
import sys
import glob
import struct

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from config import load_config
from decode_image import aligned_aes_block_size

_cfg = load_config()
SNS_CACHE_DIR = _cfg.get("sns_cache_dir", "")
XWECHAT_CACHE_DIR = _cfg.get("xwechat_cache_dir", "")
OUTPUT_DIR = os.path.join(_cfg["output_base_dir"], "Moments Images")
IMAGE_AES_KEY = _cfg.get("image_aes_key")
IMAGE_XOR_KEY = _cfg.get("image_xor_key", 0x88)

# ── V2/V1 magic ──────────────────────────────────────────────────────────────
_V2_MAGIC_FULL = b'\x07\x08V2\x08\x07'
_V1_MAGIC_FULL = b'\x07\x08V1\x08\x07'

_IMAGE_MAGICS = {
    'jpg': [0xFF, 0xD8, 0xFF],
    'png': [0x89, 0x50, 0x4E, 0x47],
    'gif': [0x47, 0x49, 0x46, 0x38],
    'webp': [0x52, 0x49, 0x46, 0x46],
    'bmp': [0x42, 0x4D],
    'tif': [0x49, 0x49, 0x2A, 0x00],
}


def _detect_format(header):
    if header[:3] == bytes([0xFF, 0xD8, 0xFF]):
        return 'jpg'
    if header[:4] == bytes([0x89, 0x50, 0x4E, 0x47]):
        return 'png'
    if header[:3] == b'GIF':
        return 'gif'
    if header[:2] == b'BM':
        return 'bmp'
    if header[:4] == b'RIFF' and len(header) >= 12 and header[8:12] == b'WEBP':
        return 'webp'
    if header[:4] == bytes([0x49, 0x49, 0x2A, 0x00]):
        return 'tif'
    if header[:4] == b'wxgf':
        return 'hevc'
    return 'bin'


def decrypt_dat(dat_path):
    """Decrypt a single .dat file, returns (bytes, format) or (None, None)"""
    with open(dat_path, 'rb') as f:
        data = f.read()
    if len(data) < 6:
        return None, None

    head6 = data[:6]

    # V2 / V1 format
    if head6 in (_V2_MAGIC_FULL, _V1_MAGIC_FULL):
        if head6 == _V1_MAGIC_FULL:
            aes_key = b'cfcd208495d565ef'
        elif IMAGE_AES_KEY:
            aes_key = IMAGE_AES_KEY.encode('ascii')[:16] if isinstance(IMAGE_AES_KEY, str) else IMAGE_AES_KEY[:16]
        else:
            return None, None
        if not aes_key or len(aes_key) < 16:
            return None, None
        try:
            from Crypto.Cipher import AES
            from Crypto.Util import Padding
            if len(data) < 15:
                return None, None
            aes_size, xor_size = struct.unpack_from('<LL', data, 6)
            aligned = aligned_aes_block_size(aes_size)
            offset = 15
            if offset + aligned > len(data):
                return None, None
            cipher = AES.new(aes_key[:16], AES.MODE_ECB)
            dec_aes = Padding.unpad(cipher.decrypt(data[offset:offset+aligned]), AES.block_size)
            offset += aligned
            raw_end = len(data) - xor_size
            raw_data = data[offset:raw_end] if offset < raw_end else b''
            xor_data = data[raw_end:]
            xor_key = IMAGE_XOR_KEY if isinstance(IMAGE_XOR_KEY, int) else 0x88
            dec_xor = bytes(b ^ xor_key for b in xor_data)
            result = dec_aes + raw_data + dec_xor
            fmt = _detect_format(result[:16])
            return result, fmt
        except Exception as e:
            print(f"  AES decryption failed: {e}")
            return None, None

    # Legacy XOR format
    for fmt_name, magic in _IMAGE_MAGICS.items():
        key = data[0] ^ magic[0]
        match = all(i < len(data) and (data[i] ^ key) == magic[i] for i in range(len(magic)))
        if match:
            result = bytes(b ^ key for b in data)
            fmt = _detect_format(result[:16])
            return result, fmt

    return None, None


def _collect_xwechat_sns_files():
    """Collect all files under xwechat cache/<YYYY-MM>/Sns/Img/<hex>/
    Returns {month: [(file_path, basename), ...], ...}
    """
    result = {}
    if not XWECHAT_CACHE_DIR or not os.path.isdir(XWECHAT_CACHE_DIR):
        return result
    try:
        months = sorted(os.listdir(XWECHAT_CACHE_DIR))
    except OSError:
        return result
    for month in months:
        sns_img = os.path.join(XWECHAT_CACHE_DIR, month, "Sns", "Img")
        if not os.path.isdir(sns_img):
            continue
        files = []
        try:
            hex_dirs = os.listdir(sns_img)
        except OSError:
            continue
        for hd in hex_dirs:
            hd_path = os.path.join(sns_img, hd)
            if not os.path.isdir(hd_path):
                continue
            try:
                for fname in os.listdir(hd_path):
                    fp = os.path.join(hd_path, fname)
                    if os.path.isfile(fp):
                        files.append((fp, fname))
            except OSError:
                continue
        if files:
            result[month] = files
    return result


def main():
    has_wechat = SNS_CACHE_DIR and os.path.isdir(SNS_CACHE_DIR)
    has_xwechat = XWECHAT_CACHE_DIR and os.path.isdir(XWECHAT_CACHE_DIR)

    if not has_wechat and not has_xwechat:
        print(f"Moments cache directory not found:")
        print(f"  WeChat Files: {SNS_CACHE_DIR}")
        print(f"  xwechat:      {XWECHAT_CACHE_DIR}")
        print("Please verify the path configuration in config.json")
        return

    print(f"Output directory: {OUTPUT_DIR}")

    total = 0
    success = 0
    skipped_thumb = 0
    skipped_exist = 0
    failed = 0

    # ── Source 1: WeChat Files/FileStorage/Sns/Cache/<YYYY-MM>/ ──
    if has_wechat:
        print(f"\n[Source 1] WeChat Files: {SNS_CACHE_DIR}")
        months = sorted(d for d in os.listdir(SNS_CACHE_DIR)
                        if os.path.isdir(os.path.join(SNS_CACHE_DIR, d)))
        has_month_dirs = any(len(m) == 7 and m[4] == '-' for m in months)

        if has_month_dirs:
            print(f"  Month directories: {len(months)}")
            for month in months:
                month_src = os.path.join(SNS_CACHE_DIR, month)
                month_out = os.path.join(OUTPUT_DIR, month)
                stats = _process_dir_stats(month_src, month_out, month)
                total += stats[0]; success += stats[1]; skipped_thumb += stats[2]
                skipped_exist += stats[3]; failed += stats[4]
        else:
            stats = _process_dir_stats(SNS_CACHE_DIR, OUTPUT_DIR, "")
            total, success, skipped_thumb, skipped_exist, failed = stats

    # ── Source 2: xwechat cache/<YYYY-MM>/Sns/Img/<hex>/ ──
    if has_xwechat:
        print(f"\n[Source 2] xwechat: {XWECHAT_CACHE_DIR}")
        xw_files = _collect_xwechat_sns_files()
        if not xw_files:
            print("  No Sns/Img files found")
        else:
            print(f"  Month directories: {len(xw_files)}")
            for month, file_list in sorted(xw_files.items()):
                month_out = os.path.join(OUTPUT_DIR, month)
                stats = _process_file_list(file_list, month_out, month)
                total += stats[0]; success += stats[1]; skipped_thumb += stats[2]
                skipped_exist += stats[3]; failed += stats[4]

    print(f"\nDone: {total} files total")
    print(f"  Successfully decrypted: {success}")
    print(f"  Skipped thumbnails (_t): {skipped_thumb}")
    print(f"  Skipped (already exist): {skipped_exist}")
    print(f"  Decryption failed: {failed}")
    print(f"Output: {os.path.abspath(OUTPUT_DIR)}")


def _process_dir_stats(src_dir, out_dir, label):
    """Process all files in a directory, returns (total, success, skipped_thumb, skipped_exist, failed)"""
    try:
        all_files = sorted(os.listdir(src_dir))
    except OSError:
        return (0, 0, 0, 0, 0)

    dat_files = [(os.path.join(src_dir, f), f) for f in all_files
                 if os.path.isfile(os.path.join(src_dir, f))]
    return _process_file_list(dat_files, out_dir, label)


def _process_file_list(file_list, out_dir, label):
    """Process a file list [(file_path, basename), ...], returns (total, success, skipped_thumb, skipped_exist, failed)"""
    total = 0
    success = 0
    skipped_thumb = 0
    skipped_exist = 0
    failed = 0

    if not file_list:
        return (0, 0, 0, 0, 0)

    if label:
        print(f"  [{label}] {len(file_list)} files")

    month_ok = 0
    for file_path, fname in file_list:
        total += 1
        # Skip thumbnails
        if fname.endswith('_t'):
            skipped_thumb += 1
            continue

        # Strip _d suffix to get base name
        base_name = fname
        if base_name.endswith('_d'):
            base_name = base_name[:-2]

        # Check if output already exists
        existing = glob.glob(os.path.join(out_dir, f"{base_name}.*"))
        if existing:
            skipped_exist += 1
            continue

        img_bytes, fmt = decrypt_dat(file_path)
        if not img_bytes or fmt in ('bin', 'hevc'):
            failed += 1
            continue

        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, f"{base_name}.{fmt}")
        with open(out_path, 'wb') as f:
            f.write(img_bytes)
        success += 1
        month_ok += 1

    if month_ok > 0 and label:
        print(f"    Successfully decrypted: {month_ok} images")

    return (total, success, skipped_thumb, skipped_exist, failed)


if __name__ == "__main__":
    main()
