#!/usr/bin/env python3
"""
Win32 Client Win32 Pre-Launch Resource Validator (tools/validate_resources.py)

Audits an extracted Win32 Client `Resources/` directory before launching the native
Win32 Cocos2d-x 2.2.6 C++ client:
  - `.lua`: plaintext vs. LuaJIT (`\x1bLJ`) vs. Lua 5.1+ (`\x1bLua`) bytecode
    vs. `0xFEFEFEFE` `bt_decrypt`-encrypted headers.
  - `.plistb`, `.xmlb`, `.pb`: counts, empty-file checks, and `0xFEFEFEFE` check.
  - `.pvr.ccz`: counts, `CCZ!` magic vs. `0xFEFEFEFE` encrypted headers.
  - `.png` / `.jpg` (`.jpeg`): plaintext magic vs. `0xFEFEFEFE` encrypted
    headers and `bt_decrypt` key index (0..15) distribution.
  - `.db`: SQLite 3 magic header verification (`SQLite format 3\x00`) and
    last-column hex-encoded `0xFEFEFEFE` (`doDecrypt`) presence audit.

Uses only the Python 3 standard library and opens SQLite databases in strictly
read-only immutable URI mode so `Resources/` is never modified.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

BT_ENCRYPT_MAGIC = b"\xfe\xfe\xfe\xfe"
LUAJIT_MAGIC = b"\x1bLJ"
LUA_BYTECODE_MAGIC = b"\x1bLua"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
JPG_MAGIC = b"\xff\xd8\xff"
CCZ_MAGIC = b"CCZ!"
SQLITE3_MAGIC = b"SQLite format 3\x00"
VALID_BT_KEY_COUNT = 16  # 16-key bt_decrypt XOR table (indices 0..15)


@dataclass
class LuaStats:
    total: int = 0
    plaintext: int = 0
    luajit_bytecode: int = 0
    lua51_bytecode: int = 0
    lua_other_bytecode: int = 0
    bt_encrypted: int = 0
    empty_or_unknown: int = 0
    bt_key_indices: Dict[int, int] = field(default_factory=dict)
    bytecode_samples: List[str] = field(default_factory=list)


@dataclass
class BinaryAssetStats:
    total: int = 0
    plain_or_raw: int = 0
    bt_encrypted: int = 0
    empty: int = 0
    bt_key_indices: Dict[int, int] = field(default_factory=dict)


@dataclass
class PvrCczStats:
    total: int = 0
    valid_ccz: int = 0
    bt_encrypted: int = 0
    unexpected_header: int = 0
    bt_key_indices: Dict[int, int] = field(default_factory=dict)


@dataclass
class ImageStats:
    total: int = 0
    plaintext_valid: int = 0
    bt_encrypted: int = 0
    invalid_or_mismatched: int = 0
    bt_key_indices: Dict[int, int] = field(default_factory=dict)


@dataclass
class DbStats:
    total: int = 0
    valid_sqlite3: int = 0
    invalid_magic: int = 0
    bt_encrypted_file: int = 0
    open_or_query_errors: int = 0
    tables_inspected: int = 0
    dbs_with_hex_fefefefe_last_col: int = 0
    dbs_plaintext_last_col_only: int = 0
    dbs_empty_tables: int = 0
    last_col_bt_key_indices: Dict[int, int] = field(default_factory=dict)
    error_samples: List[str] = field(default_factory=list)


@dataclass
class AuditReport:
    resources_dir: str
    total_files_scanned: int = 0
    lua: LuaStats = field(default_factory=LuaStats)
    plistb: BinaryAssetStats = field(default_factory=BinaryAssetStats)
    xmlb: BinaryAssetStats = field(default_factory=BinaryAssetStats)
    pb: BinaryAssetStats = field(default_factory=BinaryAssetStats)
    pvr_ccz: PvrCczStats = field(default_factory=PvrCczStats)
    png: ImageStats = field(default_factory=ImageStats)
    jpg: ImageStats = field(default_factory=ImageStats)
    db: DbStats = field(default_factory=DbStats)
    mobile_compressed_textures: Dict[str, int] = field(default_factory=dict)
    out_of_range_key_indices: List[str] = field(default_factory=list)
    blockers: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    verdict: str = "READY"


def read_header(path: Path, n: int = 64) -> bytes:
    with path.open("rb") as f:
        return f.read(n)


def parse_bt_key_index(header: bytes) -> Optional[int]:
    """Extract the 1-byte bt_decrypt key index following 0xFEFEFEFE."""
    if len(header) >= 5 and header[:4] == BT_ENCRYPT_MAGIC:
        return header[4]
    return None


def looks_like_plaintext_lua(header: bytes) -> bool:
    if not header:
        return False
    sample = header[3:] if header.startswith(b"\xef\xbb\xbf") else header
    if not sample:
        return True
    if b"\x00" in sample:
        return False
    # Allow printable ASCII, whitespace, and valid UTF-8 sequences.
    try:
        sample.decode("utf-8", errors="strict")
        return True
    except UnicodeDecodeError:
        # Fallback: partial multi-byte UTF-8 cut at the 64-byte boundary.
        try:
            sample[:-3].decode("utf-8", errors="strict")
            return True
        except UnicodeDecodeError:
            return False


def try_decode_hex_fefefefe(value: object) -> Tuple[bool, Optional[int]]:
    """
    Match CConfigManager.cpp's last-column contract:
    hex-decode the blob/text and check for the 0xFEFEFEFE bt_decrypt header.
    Returns (is_hex_fefefefe, key_index).
    """
    if value is None:
        return False, None
    if isinstance(value, bytes):
        try:
            text = value.decode("ascii")
        except UnicodeDecodeError:
            return False, None
    elif isinstance(value, str):
        text = value
    else:
        return False, None

    text = text.strip()
    if len(text) < 10 or (len(text) % 2) != 0:
        return False, None
    if not text[:8].lower() == "fefefefe":
        return False, None

    try:
        # Validate full hex string (or prefix + valid hex) cleanly.
        decoded_prefix = bytes.fromhex(text[:16] if len(text) >= 16 else text)
        # Ensure remaining characters are valid hex digits too.
        int(text, 16)
    except ValueError:
        return False, None

    key_idx = parse_bt_key_index(decoded_prefix)
    return True, key_idx


def audit_db_file(
    db_path: Path,
    rel_path: str,
    sample_rows: int,
    stats: DbStats,
    db_key_counter: Counter,
    out_of_range_keys: List[str],
) -> None:
    stats.total += 1
    try:
        header = read_header(db_path, 16)
    except OSError as exc:
        stats.open_or_query_errors += 1
        if len(stats.error_samples) < 10:
            stats.error_samples.append(f"{rel_path}: read error ({exc})")
        return

    if header.startswith(BT_ENCRYPT_MAGIC):
        stats.bt_encrypted_file += 1
        stats.invalid_magic += 1
        if len(stats.error_samples) < 10:
            stats.error_samples.append(f"{rel_path}: encrypted with 0xFEFEFEFE (expected plaintext SQLite 3)")
        return

    if header != SQLITE3_MAGIC:
        stats.invalid_magic += 1
        if len(stats.error_samples) < 10:
            stats.error_samples.append(f"{rel_path}: invalid SQLite 3 magic ({header[:8].hex()})")
        return

    stats.valid_sqlite3 += 1

    # Open strictly read-only & immutable so SQLite never creates -wal/-shm files.
    uri = f"file:{quote(str(db_path.resolve()))}?mode=ro&immutable=1"
    conn: Optional[sqlite3.Connection] = None
    try:
        conn = sqlite3.connect(uri, uri=True)
        conn.text_factory = bytes
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        tables = [row[0].decode("utf-8", errors="replace") for row in cur.fetchall()]
        if not tables:
            stats.dbs_empty_tables += 1
            return

        found_encrypted_last_col = False
        saw_any_row = False

        for table in tables:
            stats.tables_inspected += 1
            safe_table = table.replace('"', '""')
            sql = f'SELECT * FROM "{safe_table}"'
            if sample_rows > 0:
                sql += f" LIMIT {sample_rows}"
            cur.execute(sql)
            rows = cur.fetchall()
            if not rows:
                continue
            saw_any_row = True
            for row in rows:
                if not row:
                    continue
                last_val = row[-1]
                is_enc, key_idx = try_decode_hex_fefefefe(last_val)
                if is_enc:
                    found_encrypted_last_col = True
                    if key_idx is not None:
                        db_key_counter[key_idx] += 1
                        if key_idx >= VALID_BT_KEY_COUNT and len(out_of_range_keys) < 10:
                            out_of_range_keys.append(f"{rel_path} (table {table}): key_idx={key_idx}")

        if not saw_any_row:
            stats.dbs_empty_tables += 1
        elif found_encrypted_last_col:
            stats.dbs_with_hex_fefefefe_last_col += 1
        else:
            stats.dbs_plaintext_last_col_only += 1
    except sqlite3.Error as exc:
        stats.open_or_query_errors += 1
        if len(stats.error_samples) < 10:
            stats.error_samples.append(f"{rel_path}: SQLite error ({exc})")
    finally:
        if conn is not None:
            conn.close()


def audit_resources(resources_dir: Path, db_sample_rows: int = 5) -> AuditReport:
    report = AuditReport(resources_dir=str(resources_dir))

    lua_keys: Counter = Counter()
    plistb_keys: Counter = Counter()
    xmlb_keys: Counter = Counter()
    pb_keys: Counter = Counter()
    ccz_keys: Counter = Counter()
    png_keys: Counter = Counter()
    jpg_keys: Counter = Counter()
    db_keys: Counter = Counter()
    mobile_tex_counter: Counter = Counter()

    def record_key(counter: Counter, key_idx: Optional[int], rel: str) -> None:
        if key_idx is None:
            return
        counter[key_idx] += 1
        if key_idx >= VALID_BT_KEY_COUNT and len(report.out_of_range_key_indices) < 10:
            report.out_of_range_key_indices.append(f"{rel}: key_idx={key_idx}")

    for root, _, filenames in os.walk(resources_dir):
        root_path = Path(root)
        for fname in filenames:
            report.total_files_scanned += 1
            fpath = root_path / fname
            rel = str(fpath.relative_to(resources_dir)).replace("\\", "/")
            lower = fname.lower()

            if lower.endswith(".pvr.ccz"):
                report.pvr_ccz.total += 1
                header = read_header(fpath, 16)
                if header.startswith(BT_ENCRYPT_MAGIC):
                    report.pvr_ccz.bt_encrypted += 1
                    record_key(ccz_keys, parse_bt_key_index(header), rel)
                elif header.startswith(CCZ_MAGIC):
                    report.pvr_ccz.valid_ccz += 1
                else:
                    report.pvr_ccz.unexpected_header += 1
                continue

            ext = os.path.splitext(lower)[1]

            if ext == ".lua":
                report.lua.total += 1
                header = read_header(fpath, 64)
                if not header:
                    report.lua.empty_or_unknown += 1
                elif header.startswith(BT_ENCRYPT_MAGIC):
                    report.lua.bt_encrypted += 1
                    record_key(lua_keys, parse_bt_key_index(header), rel)
                elif header.startswith(LUAJIT_MAGIC):
                    report.lua.luajit_bytecode += 1
                    if len(report.lua.bytecode_samples) < 10:
                        report.lua.bytecode_samples.append(f"{rel} (LuaJIT)")
                elif header.startswith(LUA_BYTECODE_MAGIC):
                    ver = header[4] if len(header) > 4 else 0
                    if ver == 0x51:
                        report.lua.lua51_bytecode += 1
                    else:
                        report.lua.lua_other_bytecode += 1
                    if len(report.lua.bytecode_samples) < 10:
                        report.lua.bytecode_samples.append(f"{rel} (Lua 0x{ver:02x})")
                elif looks_like_plaintext_lua(header):
                    report.lua.plaintext += 1
                else:
                    report.lua.empty_or_unknown += 1

            elif ext in (".plistb", ".xmlb", ".pb"):
                target, key_counter = {
                    ".plistb": (report.plistb, plistb_keys),
                    ".xmlb": (report.xmlb, xmlb_keys),
                    ".pb": (report.pb, pb_keys),
                }[ext]
                target.total += 1
                header = read_header(fpath, 16)
                if not header:
                    target.empty += 1
                elif header.startswith(BT_ENCRYPT_MAGIC):
                    target.bt_encrypted += 1
                    record_key(key_counter, parse_bt_key_index(header), rel)
                else:
                    target.plain_or_raw += 1

            elif ext == ".png":
                report.png.total += 1
                header = read_header(fpath, 16)
                if header.startswith(BT_ENCRYPT_MAGIC):
                    report.png.bt_encrypted += 1
                    record_key(png_keys, parse_bt_key_index(header), rel)
                elif header.startswith(PNG_MAGIC):
                    report.png.plaintext_valid += 1
                else:
                    report.png.invalid_or_mismatched += 1

            elif ext in (".jpg", ".jpeg"):
                report.jpg.total += 1
                header = read_header(fpath, 16)
                if header.startswith(BT_ENCRYPT_MAGIC):
                    report.jpg.bt_encrypted += 1
                    record_key(jpg_keys, parse_bt_key_index(header), rel)
                elif header.startswith(JPG_MAGIC):
                    report.jpg.plaintext_valid += 1
                else:
                    report.jpg.invalid_or_mismatched += 1

            elif ext == ".db":
                audit_db_file(
                    fpath, rel, db_sample_rows, report.db, db_keys, report.out_of_range_key_indices
                )

            elif ext in (".pkm", ".ktx", ".etc", ".pvr"):
                mobile_tex_counter[ext] += 1

    report.lua.bt_key_indices = dict(sorted(lua_keys.items()))
    report.plistb.bt_key_indices = dict(sorted(plistb_keys.items()))
    report.xmlb.bt_key_indices = dict(sorted(xmlb_keys.items()))
    report.pb.bt_key_indices = dict(sorted(pb_keys.items()))
    report.pvr_ccz.bt_key_indices = dict(sorted(ccz_keys.items()))
    report.png.bt_key_indices = dict(sorted(png_keys.items()))
    report.jpg.bt_key_indices = dict(sorted(jpg_keys.items()))
    report.db.last_col_bt_key_indices = dict(sorted(db_keys.items()))
    report.mobile_compressed_textures = dict(sorted(mobile_tex_counter.items()))

    # Evaluate Win32 launch readiness blockers & warnings.
    if report.total_files_scanned == 0:
        report.blockers.append("Resources directory is empty (0 files scanned).")
    if report.lua.total == 0:
        report.blockers.append("No .lua scripts found in Resources/.")
    if report.lua.luajit_bytecode > 0:
        report.blockers.append(
            f"{report.lua.luajit_bytecode} LuaJIT bytecode file(s) detected; "
            "stock Cocos2d-x 2.2.6 Lua 5.1 VM cannot execute LuaJIT bytecode without LuaJIT."
        )
    if report.lua.lua_other_bytecode > 0:
        report.blockers.append(
            f"{report.lua.lua_other_bytecode} non-5.1 Lua bytecode file(s) detected."
        )
    if report.lua.lua51_bytecode > 0:
        report.warnings.append(
            f"{report.lua.lua51_bytecode} Lua 5.1 bytecode file(s) detected; "
            "verify 32-bit ARM vs. Win32 x86 pointer/size_t header compatibility."
        )
    if report.db.invalid_magic > 0 or report.db.open_or_query_errors > 0:
        report.blockers.append(
            f"{report.db.invalid_magic} .db file(s) failed SQLite 3 magic check and "
            f"{report.db.open_or_query_errors} failed to open/query."
        )
    if report.out_of_range_key_indices:
        report.blockers.append(
            f"Found bt_decrypt key index >= {VALID_BT_KEY_COUNT} outside the 16-key table "
            f"(e.g., {report.out_of_range_key_indices[0]})."
        )
    if report.png.invalid_or_mismatched > 0 or report.jpg.invalid_or_mismatched > 0:
        report.warnings.append(
            f"Unexpected image headers: {report.png.invalid_or_mismatched} .png, "
            f"{report.jpg.invalid_or_mismatched} .jpg/.jpeg."
        )
    if report.pvr_ccz.unexpected_header > 0:
        report.warnings.append(
            f"{report.pvr_ccz.unexpected_header} .pvr.ccz file(s) lack CCZ! or 0xFEFEFEFE magic."
        )
    if report.mobile_compressed_textures:
        summary = ", ".join(f"{k}:{v}" for k, v in report.mobile_compressed_textures.items())
        report.warnings.append(
            f"Mobile-compressed textures detected ({summary}); Win32 OpenGL 2.1 will "
            "fall back to RGBA8888 software decode (4x-8x RAM/VRAM overhead)."
        )

    if report.blockers:
        report.verdict = "NOT READY (BLOCKED)"
    elif report.warnings:
        report.verdict = "READY WITH WARNINGS"
    else:
        report.verdict = "READY"

    return report


def format_key_histogram(hist: Dict[int, int]) -> str:
    if not hist:
        return "-"
    return ", ".join(f"k{k}:{v}" for k, v in sorted(hist.items()))


def print_concise_report(report: AuditReport, verbose: bool = False) -> None:
    print("=" * 76)
    print("Win32 Client Win32 Resource Readiness Audit")
    print("=" * 76)
    print(f"Directory : {report.resources_dir}")
    print(f"Scanned   : {report.total_files_scanned:,} total files")
    print(f"Verdict   : {report.verdict}")
    print("-" * 76)
    print(f"{'Category':<12} {'Total':>7}  Breakdown")
    print("-" * 76)

    print(
        f"{'.lua':<12} {report.lua.total:>7}  "
        f"plain={report.lua.plaintext}, bt_enc={report.lua.bt_encrypted}, "
        f"lua51_bc={report.lua.lua51_bytecode}, luajit_bc={report.lua.luajit_bytecode}, "
        f"other_bc={report.lua.lua_other_bytecode}, bad={report.lua.empty_or_unknown}"
    )
    print(
        f"{'.plistb':<12} {report.plistb.total:>7}  "
        f"raw={report.plistb.plain_or_raw}, bt_enc={report.plistb.bt_encrypted}, empty={report.plistb.empty}"
    )
    print(
        f"{'.xmlb':<12} {report.xmlb.total:>7}  "
        f"raw={report.xmlb.plain_or_raw}, bt_enc={report.xmlb.bt_encrypted}, empty={report.xmlb.empty}"
    )
    print(
        f"{'.pb':<12} {report.pb.total:>7}  "
        f"raw={report.pb.plain_or_raw}, bt_enc={report.pb.bt_encrypted}, empty={report.pb.empty}"
    )
    print(
        f"{'.pvr.ccz':<12} {report.pvr_ccz.total:>7}  "
        f"ccz={report.pvr_ccz.valid_ccz}, bt_enc={report.pvr_ccz.bt_encrypted}, bad={report.pvr_ccz.unexpected_header}"
    )
    print(
        f"{'.png':<12} {report.png.total:>7}  "
        f"plain={report.png.plaintext_valid}, bt_enc={report.png.bt_encrypted}, bad={report.png.invalid_or_mismatched}"
    )
    print(
        f"{'.jpg/.jpeg':<12} {report.jpg.total:>7}  "
        f"plain={report.jpg.plaintext_valid}, bt_enc={report.jpg.bt_encrypted}, bad={report.jpg.invalid_or_mismatched}"
    )
    print(
        f"{'.db':<12} {report.db.total:>7}  "
        f"sqlite3={report.db.valid_sqlite3}, invalid={report.db.invalid_magic}, "
        f"err={report.db.open_or_query_errors}, "
        f"last_col_hex_FE={report.db.dbs_with_hex_fefefefe_last_col}, "
        f"last_col_plain={report.db.dbs_plaintext_last_col_only}"
    )
    print("-" * 76)
    print("0xFEFEFEFE bt_decrypt Key Index Distribution (expected 0..15):")
    print(f"  .png       : {format_key_histogram(report.png.bt_key_indices)}")
    print(f"  .jpg/.jpeg : {format_key_histogram(report.jpg.bt_key_indices)}")
    print(f"  .lua       : {format_key_histogram(report.lua.bt_key_indices)}")
    print(f"  .pvr.ccz   : {format_key_histogram(report.pvr_ccz.bt_key_indices)}")
    print(f"  .db lastcol: {format_key_histogram(report.db.last_col_bt_key_indices)}")

    if report.blockers:
        print("-" * 76)
        print("BLOCKERS:")
        for b in report.blockers:
            print(f"  [!] {b}")

    if report.warnings:
        print("-" * 76)
        print("WARNINGS:")
        for w in report.warnings:
            print(f"  [*] {w}")

    if verbose:
        if report.lua.bytecode_samples:
            print("-" * 76)
            print("Lua Bytecode Samples:")
            for s in report.lua.bytecode_samples:
                print(f"  - {s}")
        if report.db.error_samples:
            print("-" * 76)
            print("DB Error Samples:")
            for s in report.db.error_samples:
                print(f"  - {s}")
        if report.out_of_range_key_indices:
            print("-" * 76)
            print("Out-of-Range bt_decrypt Key Index Samples:")
            for s in report.out_of_range_key_indices:
                print(f"  - {s}")

    print("=" * 76)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit an extracted Win32 Client Resources/ directory for Win32 launch readiness."
    )
    parser.add_argument(
        "resources_dir",
        type=Path,
        help="Path to the extracted Win32 Client Resources/ directory.",
    )
    parser.add_argument(
        "--db-sample-rows",
        type=int,
        default=5,
        help="Rows to sample per SQLite table when checking last-column hex+0xFEFEFEFE (0 = all rows, default: 5).",
    )
    parser.add_argument(
        "--json",
        type=Path,
        default=None,
        help="Optional output path to write the structured JSON audit report.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print sample file paths for bytecode, DB errors, and key-index anomalies.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with code 1 if any warnings are present (not just blockers).",
    )
    args = parser.parse_args(argv)

    if not args.resources_dir.exists() or not args.resources_dir.is_dir():
        print(f"Error: resources_dir does not exist or is not a directory: {args.resources_dir}", file=sys.stderr)
        return 2

    report = audit_resources(args.resources_dir, db_sample_rows=max(0, args.db_sample_rows))
    print_concise_report(report, verbose=args.verbose)

    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")
        print(f"JSON report written to: {args.json}")

    if report.blockers:
        return 1
    if args.strict and report.warnings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
