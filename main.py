"""
WeChat Decrypt One-Click Launcher

python main.py               # Extract keys + launch Web UI
python main.py decrypt       # Extract keys + decrypt all databases
python main.py export        # Extract keys + decrypt + bulk export chat logs
python main.py all           # End-to-end: keys → decrypt → export
python main.py status        # Show current data status
"""

import functools
import glob
import json
import os
import platform
import subprocess
import sys

print = functools.partial(print, flush=True)

from key_utils import strip_key_metadata


def check_wechat_running():
    """Check whether WeChat is running; returns True/False."""
    if platform.system().lower() == "darwin":
        return subprocess.run(["pgrep", "-x", "WeChat"], capture_output=True).returncode == 0
    from find_all_keys import get_pids
    try:
        get_pids()
        return True
    except RuntimeError:
        return False


def _run_decode_images(cfg, argv):
    """`decode-images` subcommand: bulk-decrypt .dat images into a plaintext image tree.

    Unlike decrypt, decode-images does **not** require WeChat to be running or a DB key
    (it only reads existing .dat files; V2 files use image_aes_key from config.json).
    """
    import argparse
    from decode_image import decode_all_dats

    parser = argparse.ArgumentParser(
        prog="main.py decode-images",
        description=(
            "Bulk-decrypt WeChat local .dat images into a plaintext image tree. "
            "Unlike the single-file decode_image.py CLI, this subcommand scans all "
            ".dat files under attach_dir and mirrors the directory structure, "
            "producing plaintext output (jpg / png / gif / webp / hevc)."
        ),
    )
    default_base = cfg.get("wechat_base_dir") or os.path.dirname(cfg["db_dir"])
    default_attach = os.path.join(default_base, "msg", "attach")
    default_out = cfg.get("decoded_image_dir", "decoded_images")
    parser.add_argument(
        "--attach-dir", default=None,
        help=f"WeChat msg/attach root directory, overrides default inference (default: {default_attach})",
    )
    parser.add_argument(
        "--decoded-dir", default=None,
        help=f"Plaintext image output root directory, overrides decoded_image_dir in config.json (default: {default_out})",
    )
    parser.add_argument(
        "--aes-key", default=None,
        help="V2 AES key (16-byte ASCII string), overrides image_aes_key in config.json",
    )
    parser.add_argument(
        "--xor-key", default=None,
        help="V2 XOR key (decimal or 0x hex), overrides image_xor_key in config.json (default: 0x88)",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Re-decrypt even if output already exists (default: skip by basename)",
    )
    args = parser.parse_args(argv)

    attach_dir = args.attach_dir or default_attach
    out_dir = args.decoded_dir or default_out
    aes_key = args.aes_key if args.aes_key is not None else cfg.get("image_aes_key")
    xor_key_raw = args.xor_key if args.xor_key is not None else cfg.get("image_xor_key", 0x88)
    if isinstance(xor_key_raw, str):
        xor_key = int(xor_key_raw, 0)
    else:
        xor_key = xor_key_raw

    if not os.path.isdir(attach_dir):
        print(f"[ERROR] attach directory does not exist: {attach_dir}", file=sys.stderr)
        sys.exit(1)

    if aes_key is None:
        print(
            "[NOTE] image_aes_key not configured; V2 encrypted images will be skipped (counted as skipped_no_key). "
            "V1 / legacy XOR images are unaffected. See the image decryption section in the README for how to extract the V2 key.",
            file=sys.stderr,
        )

    print(f"  attach_dir = {attach_dir}")
    print(f"  out_dir    = {out_dir}")
    print(f"  aes_key    = {'configured' if aes_key else 'not configured'}")
    print(f"  xor_key    = 0x{xor_key:02x}")
    print(f"  force      = {args.force}")
    print()

    stats = decode_all_dats(
        attach_dir=attach_dir,
        out_dir=out_dir,
        aes_key=aes_key,
        xor_key=xor_key,
        force=args.force,
    )

    print()
    print("=" * 60)
    print(f"Scanned {stats['total']} .dat files")
    print(f"  Decoded: {stats['decoded']}  Skipped (already exists): {stats['skipped']}  "
          f"Skipped (no key): {stats['skipped_no_key']}  Failed: {stats['failed']}")
    if stats["formats"]:
        fmt_summary = ", ".join(f"{ext}={n}" for ext, n in sorted(stats["formats"].items()))
        print(f"  By format: {fmt_summary}")
    print(f"Output at: {out_dir}")

    if stats["failed"] > 0:
        sys.exit(2)


def ensure_keys(keys_file, db_dir):
    """Ensure the keys file exists and matches the current db_dir; re-extract if not."""
    if os.path.exists(keys_file):
        try:
            with open(keys_file, encoding="utf-8") as f:
                keys = json.load(f)
        except (json.JSONDecodeError, ValueError):
            keys = {}
        saved_dir = keys.pop("_db_dir", None)
        if saved_dir and os.path.normcase(os.path.normpath(saved_dir)) != os.path.normcase(os.path.normpath(db_dir)):
            print(f"[!] The directory associated with the keys file has changed; re-extraction required")
            print(f"    Old: {saved_dir}")
            print(f"    New: {db_dir}")
            keys = {}
        keys = strip_key_metadata(keys)
        if keys:
            print(f"[+] {len(keys)} database keys already present")
            return

    print("[*] Keys file not found; extracting from WeChat process...")
    print()
    from find_all_keys import main as extract_keys
    try:
        extract_keys()
    except RuntimeError as e:
        print(f"\n[!] Key extraction failed: {e}")
        sys.exit(1)
    print()

    if not os.path.exists(keys_file):
        print("[!] Key extraction failed")
        sys.exit(1)
    try:
        with open(keys_file, encoding="utf-8") as f:
            keys = json.load(f)
    except (json.JSONDecodeError, ValueError):
        keys = {}
    if not strip_key_metadata(keys):
        print("[!] No keys could be extracted")
        print("    Possible causes: wrong WeChat data directory selected, or WeChat needs a restart")
        print("    Please verify that db_dir in config.json matches the currently logged-in WeChat account")
        sys.exit(1)


def show_status():
    """Show current data status."""
    cfg = {}
    # Use config._config_file_path() instead of hard-coding "config.json"
    # so that when packaged as an exe (cwd may be arbitrary) the correct config is still found
    from config import _config_file_path
    config_file = _config_file_path()
    if os.path.exists(config_file):
        with open(config_file, encoding="utf-8") as f:
            cfg = json.load(f)
        print(f"[config] {config_file}")
        print(f"         db_dir = {cfg.get('db_dir', '?')}")
    else:
        print(f"[config] {config_file} not found")

    keys_files = sorted(glob.glob("all_keys*.json"))
    print(f"[keys]   {len(keys_files)} keys file(s)")
    for kf in keys_files:
        sz = os.path.getsize(kf) / 1024
        print(f"         {kf} ({sz:.0f} KB)")

    decrypted_dir = cfg.get("decrypted_dir", "decrypted")
    if os.path.exists(decrypted_dir):
        dbs = glob.glob(os.path.join(decrypted_dir, "**/*.db"), recursive=True)
        total_mb = sum(os.path.getsize(f) for f in dbs) / 1024 / 1024
        print(f"[decrypt] {len(dbs)} database(s) ({total_mb:.0f} MB)")
        # Check whether message databases are present (rough indicator of whether export has been done)
        for db in dbs:
            if "message" in os.path.basename(db):
                sz = os.path.getsize(db) / 1024 / 1024
                print(f"          Message DB(s): {len([d for d in dbs if 'message' in d])} ({sz:.0f} MB)")
                break
    else:
        print("[decrypt] Not decrypted (run: python main.py decrypt)")

    exported_dir = "exported_chats"
    if os.path.exists(exported_dir):
        jsons = [f for f in glob.glob(os.path.join(exported_dir, "*.json"))
                 if not f.endswith("_transcribed.json")]
        tx_jsons = glob.glob(os.path.join(exported_dir, "*_transcribed.json"))
        total_sz = sum(os.path.getsize(f) for f in jsons) / 1024 / 1024
        print(f"[export]  {len(jsons)} JSON file(s) ({total_sz:.0f} MB)")
    else:
        print("[export]  Not exported (run: python main.py export)")

    if os.path.exists(exported_dir):
        total_voice = 0
        total_tx = 0
        for jp in glob.glob(os.path.join(exported_dir, "*_transcribed.json")):
            try:
                with open(jp, encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                continue
            if isinstance(data, dict) and "chats" in data:
                for chat in data["chats"]:
                    for m in chat.get("messages", []):
                        if m.get("type") == "voice":
                            total_voice += 1
                            if m.get("transcription"):
                                total_tx += 1
            elif isinstance(data, dict):
                for m in data.get("messages", []):
                    if m.get("type") == "voice":
                        total_voice += 1
                        if m.get("transcription"):
                            total_tx += 1
        if total_voice > 0:
            pct = total_tx * 100 // max(total_voice, 1)
            print(f"[transcribe] {total_tx}/{total_voice} ({pct}%) voice messages transcribed")

    # Suggested next steps
    print()
    steps = []
    if not os.path.exists(decrypted_dir):
        steps.append("python main.py decrypt  — decrypt databases")
    elif not os.path.exists(exported_dir):
        steps.append("main.py export — export chat logs")
    if steps:
        print("Suggested next steps:")
        for s in steps:
            print(f"  {s}")
    else:
        print("All steps complete.")


def print_usage():
    print("Usage:")
    print("  python main.py                Start live message monitoring (Web UI)")
    print("  python main.py decrypt        Decrypt all databases to decrypted/")
    print("  python main.py decode-images  Bulk-decrypt .dat images to decoded_image_dir/")
    print("  python main.py decode-images --help  Show all decode-images options")
    print("  python main.py export         Decrypt + bulk export chat logs")
    print("  python main.py all            End-to-end: keys → decrypt → export")
    print("  python main.py emoticons      Export saved emoticons/stickers")
    print("  python main.py status         Show current status and disk usage")


def _call_with_argv(func, argv):
    """Temporarily isolate sys.argv when calling a subcommand's main(), so argparse does not see outer arguments."""
    old_argv = sys.argv[:]
    try:
        sys.argv = argv
        return func()
    finally:
        sys.argv = old_argv


def main():
    print("=" * 60)
    print("  WeChat Decrypt")
    print("=" * 60)
    print()

    cmd = sys.argv[1] if len(sys.argv) > 1 else "web"

    # help / status do not require keys or a running WeChat process
    if cmd in ("help", "-h", "--help"):
        print_usage()
        return
    if cmd in ("status", "-s"):
        show_status()
        return

    # The following commands require config + a running WeChat process
    from config import load_config
    cfg = load_config()

    # Early route: decode-images does not require WeChat to be running or a DB key
    if len(sys.argv) > 1 and sys.argv[1] == "decode-images":
        print("[*] Bulk-decrypting images...")
        print()
        _run_decode_images(cfg, sys.argv[2:])
        return

    # 2. Check for WeChat process
    if not check_wechat_running():
        print(f"[!] WeChat process not detected ({cfg.get('wechat_process', 'WeChat')})")
        print("    Please start WeChat and log in, then run again")
        sys.exit(1)
    print("[+] WeChat process is running")

    ensure_keys(cfg["keys_file"], cfg["db_dir"])

    if cmd == "decrypt":
        print("[*] Starting decryption of all databases...")
        print()
        from decrypt_db import main as decrypt_all
        decrypt_all(sys.argv[2:])

    elif cmd in ("export", "all"):
        print("[*] Starting decryption of all databases...")
        print()
        from decrypt_db import main as decrypt_all
        decrypt_all([])
        print()
        print("[*] Starting bulk export of chat logs...")
        print()
        from export_all_chats import main as export_all
        try:
            export_args = sys.argv[2:] if cmd == "export" else []
            export_all(export_args)
        except SystemExit:
            pass

        if cmd == "all" and os.path.exists("exported_chats"):
            print()
            print("[*] Checking voice transcription configuration...")
            from config import load_config
            cfg2 = load_config()
            from mcp_server import _resolve_active_backend
            backend = _resolve_active_backend()
            if backend and backend != "local":
                print(f"    Detected backend = {backend}")
                print("    To transcribe voice messages, run: python export_all_chats.py --with-transcriptions")
            else:
                print("    No voice transcription backend configured (set in config.json)")
                print("    After configuring, run: python export_all_chats.py --with-transcriptions")

    elif cmd == "emoticons":
        from export_emoticons import main as export_emojis
        export_emojis()

    elif cmd == "web":
        print("[*] Starting Web UI...")
        print()
        from monitor_web import main as start_web
        start_web()

    else:
        print(f"[!] Unknown command: {cmd}")
        print()
        print_usage()
        sys.exit(1)


if __name__ == "__main__":
    main()
