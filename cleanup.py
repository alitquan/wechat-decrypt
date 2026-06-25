#!/usr/bin/env python3
"""
WeChat Decrypt — Data Cleanup Tool

Safely view and free up disk space used by decrypted/exported data, interactively.

Usage:
    python3 cleanup.py           # interactive cleanup
    python3 cleanup.py status    # show disk usage only
    python3 cleanup.py --dry-run # preview what would be deleted without actually doing it
"""

import argparse
import glob
import json
import os
import shutil
import sys


def format_size(size_bytes):
    """Format file size as a human-readable string"""
    if size_bytes > 1024 * 1024 * 1024:
        return f"{size_bytes / 1024 / 1024 / 1024:.1f} GB"
    elif size_bytes > 1024 * 1024:
        return f"{size_bytes / 1024 / 1024:.0f} MB"
    elif size_bytes > 1024:
        return f"{size_bytes / 1024:.0f} KB"
    else:
        return f"{size_bytes} B"


class CleanupItem:
    def __init__(self, name, path, is_dir=True, pattern=None, description=""):
        self.name = name
        self.path = path
        self.is_dir = is_dir
        self.pattern = pattern
        self.description = description

    def size(self):
        if not self.exists():
            return 0
        if self.is_dir:
            if self.pattern:
                files = glob.glob(os.path.join(self.path, self.pattern), recursive=True)
                files = [f for f in files if os.path.isfile(f)]
            else:
                files = []
                for root, dirs, fnames in os.walk(self.path):
                    for fname in fnames:
                        files.append(os.path.join(root, fname))
            return sum(os.path.getsize(f) for f in files)
        else:
            return os.path.getsize(self.path) if os.path.isfile(self.path) else 0

    def exists(self):
        if self.is_dir:
            return os.path.isdir(self.path)
        return os.path.isfile(self.path)

    def delete(self):
        if not self.exists():
            return
        if self.is_dir:
            shutil.rmtree(self.path)
        else:
            os.unlink(self.path)


def get_items():
    """Return a list of all cleanable items"""
    items = []

    # Decrypted databases
    cfg = {}
    if os.path.exists("config.json"):
        with open("config.json") as f:
            cfg = json.load(f)
    decrypted_dir = cfg.get("decrypted_dir", "decrypted")
    items.append(CleanupItem(
        "Decrypted databases", decrypted_dir,
        description="Decrypted SQLite database files (can be re-decrypted to restore)"
    ))

    # WAV decode cache
    items.append(CleanupItem(
        "Voice WAV cache", "decoded_voices",
        description="Temporary WAV files decoded from SILK (can be re-decoded)"
    ))

    # Image decode cache
    items.append(CleanupItem(
        "Image decode cache", "decoded_images",
        description="Decrypted image cache"
    ))

    # Exported JSON
    items.append(CleanupItem(
        "Exported chat logs", "exported_chats",
        description="JSON files exported by export_all_chats.py (can be re-exported)"
    ))

    # Legacy format exports
    items.append(CleanupItem(
        "Legacy format exports", "exports",
        description="Data exported by older versions"
    ))

    # Key files
    for kf in sorted(glob.glob("all_keys*.json")):
        items.append(CleanupItem(
            os.path.basename(kf), kf, is_dir=False,
            description="Key cache file (can be re-extracted)"
        ))

    return items


def show_status(items):
    """Display disk usage for each item"""
    total = 0
    rows = []
    for item in items:
        sz = item.size()
        if sz > 0:
            total += sz
            rows.append((item.name, sz, item.description))

    if not rows:
        print("No data to clean up.")
        return 0

    # Find the longest name
    name_width = max(len(r[0]) for r in rows) + 2
    print(f"{'Item':<{name_width}}{'Size':>10}  Description")
    print("-" * (name_width + 45))
    for name, sz, desc in rows:
        print(f"{name:<{name_width}}{format_size(sz):>10}  {desc}")
    print("-" * (name_width + 45))
    print(f"{'Total':<{name_width}}{format_size(total):>10}")
    return total


def cleanup(dry_run=False):
    """Interactive cleanup"""
    items = get_items()

    print("=" * 60)
    print("  Disk Usage Analysis")
    print("=" * 60)
    print()
    total = show_status(items)
    if total == 0:
        print()
        print("No data to clean up.")
        return

    print()
    print("Select items to delete (comma-separated, e.g.: 1,3,5):")
    print("  Enter a to select all")
    print("  Enter n to cancel")
    choice = input("> ").strip().lower()

    if choice in ("", "n"):
        print("Cancelled.")
        return

    # Parse selection
    indices = []
    if choice == "a":
        indices = list(range(len(items)))
    else:
        for part in choice.split(","):
            part = part.strip()
            try:
                idx = int(part) - 1
                if 0 <= idx < len(items):
                    indices.append(idx)
            except ValueError:
                pass

    if not indices:
        print("No items selected.")
        return

    # Confirm
    total_saved = 0
    print()
    for idx in indices:
        item = items[idx]
        if item.exists():
            sz = item.size()
            total_saved += sz
            print(f"  [{idx+1}] {item.name} ({format_size(sz)})")

    print(f"\nWill free {format_size(total_saved)} of disk space")
    if dry_run:
        print("(dry-run mode, nothing actually deleted)")
        return

    confirm = input("Confirm deletion? (y/N): ").strip().lower()
    if confirm != "y":
        print("Cancelled.")
        return

    # Perform deletion
    for idx in indices:
        item = items[idx]
        if item.exists():
            sz = item.size()
            item.delete()
            print(f"  Deleted: {item.name} ({format_size(sz)})")

    print()
    # Show remaining
    remaining = sum(item.size() for item in get_items())
    print(f"Remaining: {format_size(remaining)}")
    print("Cleanup complete.")


def main():
    parser = argparse.ArgumentParser(
        description="WeChat Decrypt — Data Cleanup Tool",
    )
    parser.add_argument("mode", nargs="?", default="interactive",
                        choices=["interactive", "status"],
                        help="interactive (default) or status (display only)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview mode, nothing is actually deleted")
    args = parser.parse_args()

    if args.mode == "status":
        show_status(get_items())
    else:
        cleanup(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
