"""
WeChat 4.0 Database Decryptor

Decrypts SQLCipher 4 encrypted databases using per-DB enc_key extracted from process memory.
Parameters: SQLCipher 4, AES-256-CBC, HMAC-SHA512, reserve=80, page_size=4096
Key source: all_keys.json (extracted from memory by find_all_keys.py)
"""
import hashlib, struct, os, sys, json
import hmac as hmac_mod
from Crypto.Cipher import AES

import argparse
import functools
print = functools.partial(print, flush=True)

PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16
IV_SZ = 16
HMAC_SZ = 64
RESERVE_SZ = 80  # IV(16) + HMAC(64)
SQLITE_HDR = b'SQLite format 3\x00'

from config import load_config
from key_utils import get_key_info, strip_key_metadata
_cfg = load_config()
DB_DIR = _cfg["db_dir"]
OUT_DIR = _cfg["decrypted_dir"]
KEYS_FILE = _cfg["keys_file"]


def derive_mac_key(enc_key, salt):
    """Derive HMAC key from enc_key"""
    mac_salt = bytes(b ^ 0x3a for b in salt)
    return hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SZ)


def decrypt_page(enc_key, page_data, pgno):
    """Decrypt a single page, output a standard 4096-byte SQLite page"""
    iv = page_data[PAGE_SZ - RESERVE_SZ : PAGE_SZ - RESERVE_SZ + IV_SZ]

    if pgno == 1:
        encrypted = page_data[SALT_SZ : PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        page = bytearray(SQLITE_HDR + decrypted + b'\x00' * RESERVE_SZ)
        # Preserve reserve=80, B-tree is built based on usable_size=4016
        return bytes(page)
    else:
        encrypted = page_data[:PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return decrypted + b'\x00' * RESERVE_SZ


def decrypt_database(db_path, out_path, enc_key):
    """Decrypt the entire database file"""
    file_size = os.path.getsize(db_path)
    total_pages = file_size // PAGE_SZ

    if file_size % PAGE_SZ != 0:
        print(f"  [WARN] File size {file_size} is not a multiple of {PAGE_SZ}")
        total_pages += 1

    with open(db_path, 'rb') as fin:
        page1 = fin.read(PAGE_SZ)

    if len(page1) < PAGE_SZ:
        print(f"  [ERROR] File too small")
        return False

    # Extract salt and derive mac_key, verify page 1
    salt = page1[:SALT_SZ]
    mac_key = derive_mac_key(enc_key, salt)
    p1_hmac_data = page1[SALT_SZ : PAGE_SZ - RESERVE_SZ + IV_SZ]
    p1_stored_hmac = page1[PAGE_SZ - HMAC_SZ : PAGE_SZ]
    hm = hmac_mod.new(mac_key, p1_hmac_data, hashlib.sha512)
    hm.update(struct.pack('<I', 1))
    if hm.digest() != p1_stored_hmac:
        print(f"  [ERROR] Page 1 HMAC verification failed! salt: {salt.hex()}")
        return False

    print(f"  HMAC OK, {total_pages} pages")

    # Decrypt all pages
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(db_path, 'rb') as fin, open(out_path, 'wb') as fout:
        for pgno in range(1, total_pages + 1):
            page = fin.read(PAGE_SZ)
            if len(page) < PAGE_SZ:
                if len(page) > 0:
                    page = page + b'\x00' * (PAGE_SZ - len(page))
                else:
                    break

            decrypted = decrypt_page(enc_key, page, pgno)
            fout.write(decrypted)

            if pgno == 1:
                if decrypted[:16] != SQLITE_HDR:
                    print(f"  [WARN] Header mismatch after decryption!")

            if pgno % 10000 == 0:
                print(f"  Progress: {pgno}/{total_pages} ({100*pgno/total_pages:.1f}%)")

    return True


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="WeChat 4.0 Database Decryptor"
    )
    parser.add_argument(
        "-i", "--incremental",
        action="store_true",
        help="Incremental mode: only re-decrypt when the source .db is newer than the decrypted file",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Dry-run mode: show the list of databases that would be decrypted",
    )
    args = parser.parse_args(argv)

    print("=" * 60)
    print("  WeChat 4.0 Database Decryptor")
    print("=" * 60)

    # Load keys
    if not os.path.exists(KEYS_FILE):
        print(f"[ERROR] Keys file not found: {KEYS_FILE}")
        print("Please run python main.py decrypt first to extract keys and decrypt")
        sys.exit(1)


    with open(KEYS_FILE, encoding="utf-8") as f:
        keys = json.load(f)

    keys = strip_key_metadata(keys)
    print(f"\nLoaded {len(keys)} database keys")
    print(f"Output directory: {OUT_DIR}")
    if args.incremental:
        print(f"Mode: incremental (skipping unchanged databases)")
    os.makedirs(OUT_DIR, exist_ok=True)

    # Collect all DB files
    db_files = []
    for root, dirs, files in os.walk(DB_DIR):
        for f in files:
            if f.endswith('.db') and not f.endswith('-wal') and not f.endswith('-shm'):
                path = os.path.join(root, f)
                rel = os.path.relpath(path, DB_DIR)
                sz = os.path.getsize(path)
                db_files.append((rel, path, sz))

    db_files.sort(key=lambda x: x[2])  # ascending by size

    print(f"Found {len(db_files)} database files\n")

    success = 0
    failed = 0
    skipped = 0
    skipped_unmodified = 0
    total_bytes = 0

    for rel, path, sz in db_files:
        key_info = get_key_info(keys, rel)
        if not key_info:
            print(f"SKIP: {rel} (no key; if WeChat patch is installed you may need to re-run key extraction)")
            skipped += 1
            continue

        out_path = os.path.join(OUT_DIR, rel)

        # Incremental mode: check mtime
        if args.incremental and os.path.exists(out_path):
            src_mtime = os.path.getmtime(path)
            dst_mtime = os.path.getmtime(out_path)
            if src_mtime <= dst_mtime:
                skipped_unmodified += 1
                if args.dry_run:
                    print(f"SKIP: {rel} (unmodified)")
                continue
            elif args.dry_run:
                print(f"NEW: {rel} (source is newer)")
            elif not args.dry_run:
                print(f"UPDATE: {rel} ({sz/1024/1024:.1f}MB) ...", end=" ")
        elif args.dry_run:
            print(f"NEW: {rel} ({sz/1024/1024:.1f}MB)")
        else:
            print(f"DECRYPT: {rel} ({sz/1024/1024:.1f}MB) ...", end=" ")

        if args.dry_run:
            skipped_unmodified += 1
            continue

        enc_key = bytes.fromhex(key_info["enc_key"])
        ok = decrypt_database(path, out_path, enc_key)
        if ok:
            # SQLite validation
            try:
                import sqlite3
                conn = sqlite3.connect(out_path)
                tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                conn.close()
                table_names = [t[0] for t in tables]
                print(f"  OK! 表: {', '.join(table_names[:5])}", end="")
                if len(table_names) > 5:
                    print(f" ...{len(table_names)} total", end="")
                print()
                success += 1
                total_bytes += sz
            except Exception as e:
                print(f"  [WARN] SQLite validation failed: {e}")
                failed += 1
        else:
            failed += 1

        # Clean up empty -shm/-wal files left by sqlite3.connect() validation
        # Prevents subsequent tools from reading a stale WAL and getting "database disk image is malformed"
        for suffix in ("-shm", "-wal"):
            residual = out_path + suffix
            if os.path.exists(residual):
                try:
                    os.remove(residual)
                except OSError:
                    pass

    if args.dry_run:
        print(f"\n{'='*60}")
        print(f"Dry-run: {skipped_unmodified} databases would be decrypted")
        return

    print(f"\n{'='*60}")
    inc_note = f" (skipped {skipped_unmodified} unchanged)" if skipped_unmodified else ""
    print(f"Result: {success} succeeded, {failed} failed, {skipped} skipped (no key){inc_note}, {len(db_files)} total")
    print(f"Total decrypted: {total_bytes/1024/1024/1024:.1f}GB")
    print(f"Decrypted files in: {OUT_DIR}")


if __name__ == '__main__':
    main()
