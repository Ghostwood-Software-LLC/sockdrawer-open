#!/usr/bin/env python3
"""Open a Sock Drawer archive (.mjarchive) without the app.

    python3 sockdrawer_open.py ARCHIVE OUTPUT_FOLDER
    python3 sockdrawer_open.py --list ARCHIVE

Asks for the archive's passphrase, then writes every photo and video in the archive
to OUTPUT_FOLDER as the original file, named by the date it was taken (UTC). Items
that were in Recently Deleted go in OUTPUT_FOLDER/Recently Deleted. manifest.csv
lists every item with its albums and whether it was a favourite.

Needs Python 3.9+ and the `cryptography` package. Reads the archive and writes the
output folder; nothing else, and no network.

Exit status: 0 everything written; 1 nothing written (wrong passphrase, damaged or
unrecognised archive); 2 written, but some items could not be (see the messages and
the empty `file` cells in manifest.csv).

The format is described in FORMAT.md, next to this file.
"""

from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import getpass
import hashlib
import json
import os
import re
import struct
import sys
import unicodedata
from dataclasses import dataclass
from typing import BinaryIO, Callable, Optional

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover - depends on the machine
    sys.exit("This needs the `cryptography` package: python3 -m pip install cryptography")

# --- The format. Every constant here mirrors one in the app; see FORMAT.md. ---------

ARCHIVE_MAGIC = b"MJA1"
ARCHIVE_VERSION = 1
FILE_MAGIC = b"MJV1"
FILE_HEADER_LENGTH = 32
GCM_OVERHEAD = 12 + 16  # nonce + tag, in AES.GCM.SealedBox.combined
MAX_CHUNK_SIZE = 64 << 20
MAX_TABLE_BYTES = 64 << 20
MAX_INDEX_BYTES = 256 << 20
MAX_ITERATIONS = 10_000_000
KEY_LENGTH = 32
INDEX_NAME = "index.mji"
# Swift's JSONEncoder writes a Date as seconds since 2001-01-01 00:00:00 UTC.
SWIFT_EPOCH = dt.datetime(2001, 1, 1, tzinfo=dt.timezone.utc)

# Every field the app writes. Anything else means a newer app wrote this archive, and
# a field this script does not know might be a second file it would silently leave out.
KNOWN_INDEX_FIELDS = {
    "schemaVersion", "items", "albums", "keys", "didBackfillCaptureDates",
    "lastArchivedAt", "backupReminderSnoozedUntil",
}
KNOWN_ITEM_FIELDS = {
    "id", "kind", "addedAt", "byteCount", "pixelWidth", "pixelHeight", "duration",
    "capturedAt", "fileExtension", "albumIDs", "isFavorite", "deletedAt", "contentHash",
    "keyID",
}
KNOWN_ALBUM_FIELDS = {"id", "name", "createdAt"}
KNOWN_WRAP_FIELDS = {"salt", "iterations", "ciphertext", "slot"}
KNOWN_ENTRY_FIELDS = {"name", "length"}
KNOWN_KINDS = {"photo", "video"}
KNOWN_SCHEMAS = {0, 1, 2}

ENTRY_NAME = re.compile(r"^(?P<id>[0-9A-Fa-f-]{36})\.(?P<ext>mjv|mjt)$")


class ArchiveError(Exception):
    """Nothing can be written: the archive cannot be opened or is not understood."""


class WrongPassphrase(ArchiveError):
    pass


# --- Reading the archive --------------------------------------------------------------


@dataclass
class Entry:
    name: str
    length: int
    offset: int  # where its bytes start in the archive


@dataclass
class Archive:
    path: str
    wrap: dict
    entries: list  # [Entry]

    def entry(self, name: str) -> Optional[Entry]:
        return next((e for e in self.entries if e.name == name), None)


def _read_exact(f: BinaryIO, n: int) -> bytes:
    data = f.read(n)
    if len(data) != n:
        raise ArchiveError("The archive is incomplete; the copy may not have finished.")
    return data


def _read_block(f: BinaryIO) -> bytes:
    (length,) = struct.unpack(">I", _read_exact(f, 4))
    if not 0 < length <= MAX_TABLE_BYTES:
        raise ArchiveError("That file is not a Sock Drawer archive, or it is damaged.")
    return _read_exact(f, length)


def _require_fields(obj: object, known: set, what: str) -> dict:
    if not isinstance(obj, dict):
        raise ArchiveError(f"Unexpected {what} in the archive.")
    unknown = set(obj) - known
    if unknown:
        raise ArchiveError(
            f"This archive was written by a newer version of the app ({what} has "
            f"{', '.join(sorted(unknown))}). Get a newer copy of this script.")
    return obj


def read_archive(path: str) -> Archive:
    with open(path, "rb") as f:
        if f.read(4) != ARCHIVE_MAGIC:
            raise ArchiveError("That file is not a Sock Drawer archive, or it is damaged.")
        (version,) = struct.unpack(">I", _read_exact(f, 4))
        if version != ARCHIVE_VERSION:
            raise ArchiveError(
                f"This archive is format version {version}; this script reads version "
                f"{ARCHIVE_VERSION}. Get a newer copy of this script.")
        try:
            wrap = json.loads(_read_block(f))
            table = json.loads(_read_block(f))
        except ValueError:
            raise ArchiveError("That file is not a Sock Drawer archive, or it is damaged.")
        _require_fields(wrap, KNOWN_WRAP_FIELDS, "the key wrap")
        if not isinstance(table, list):
            raise ArchiveError("That file is not a Sock Drawer archive, or it is damaged.")
        offset = f.tell()

    entries, seen = [], set()
    for raw in table:
        _require_fields(raw, KNOWN_ENTRY_FIELDS, "a table entry")
        name, length = raw.get("name"), raw.get("length")
        if not isinstance(name, str) or not isinstance(length, int) or length < 0:
            raise ArchiveError("That file is not a Sock Drawer archive, or it is damaged.")
        if name != INDEX_NAME and not ENTRY_NAME.match(name):
            raise ArchiveError(
                f"This archive holds a file this script does not know ({name!r}); it was "
                "probably written by a newer version of the app. Get a newer copy of this script.")
        if name in seen:
            raise ArchiveError("That file is not a Sock Drawer archive, or it is damaged.")
        seen.add(name)
        entries.append(Entry(name, length, offset))
        offset += length

    # A size check before a single byte is written: a short archive fails here, whole,
    # rather than after half the photos are out.
    if os.path.getsize(path) < offset:
        raise ArchiveError("The archive is incomplete; the copy may not have finished.")
    if INDEX_NAME not in seen:
        raise ArchiveError("That file is not a Sock Drawer archive, or it is damaged.")
    return Archive(path, wrap, entries)


def unwrap_key(wrap: dict, passphrase: str) -> bytes:
    try:
        salt = base64.b64decode(wrap["salt"], validate=True)
        sealed = base64.b64decode(wrap["ciphertext"], validate=True)
        iterations = wrap["iterations"]
        slot = wrap["slot"]
    except (KeyError, ValueError, TypeError):
        raise ArchiveError("That file is not a Sock Drawer archive, or it is damaged.")
    # The count is not authenticated; out of range it could pin a core for hours.
    if not isinstance(iterations, int) or not 1 <= iterations <= MAX_ITERATIONS:
        raise ArchiveError("That file is not a Sock Drawer archive, or it is damaged.")
    if len(sealed) != GCM_OVERHEAD + KEY_LENGTH:
        raise ArchiveError("That file is not a Sock Drawer archive, or it is damaged.")
    # The app normalises to NFC first: the same passphrase typed on two keyboards can
    # differ byte for byte.
    secret = unicodedata.normalize("NFC", passphrase).encode("utf-8")
    derived = hashlib.pbkdf2_hmac("sha256", secret, salt, iterations, KEY_LENGTH)
    try:
        # The slot name is authenticated, not just stored.
        key = AESGCM(derived).decrypt(sealed[:12], sealed[12:], str(slot).encode("utf-8"))
    except InvalidTag:
        raise WrongPassphrase("That passphrase does not open this archive.")
    return key


# --- MJV1: chunked AES-GCM ------------------------------------------------------------


def decrypt_stream(src: BinaryIO, length: int, key: bytes,
                   write: Callable[[bytes], None]) -> int:
    """Decrypts one sealed file of exactly `length` bytes from `src`, passing plaintext
    to `write` chunk by chunk. Returns the plaintext length. Raises ValueError if
    anything does not authenticate or add up."""
    if length < FILE_HEADER_LENGTH:
        raise ValueError("too short")
    header = src.read(FILE_HEADER_LENGTH)
    if len(header) != FILE_HEADER_LENGTH or header[:4] != FILE_MAGIC:
        raise ValueError("bad header")
    chunk_size, plain_length = struct.unpack(">IQ", header[4:16])
    if not 0 < chunk_size <= MAX_CHUNK_SIZE or plain_length > (1 << 63) - 1:
        raise ValueError("bad header")

    aes = AESGCM(key)
    remaining = length - FILE_HEADER_LENGTH
    index = total = 0
    while remaining > 0:
        if remaining < 4:
            raise ValueError("truncated")
        (sealed_length,) = struct.unpack(">I", src.read(4))
        remaining -= 4
        # Bounded by the entry and the chunk size, so a corrupt length cannot make this
        # read into the next file or ask for a huge allocation.
        if not GCM_OVERHEAD <= sealed_length <= min(remaining, chunk_size + GCM_OVERHEAD):
            raise ValueError("bad frame")
        sealed = src.read(sealed_length)
        if len(sealed) != sealed_length:
            raise ValueError("truncated")
        remaining -= sealed_length
        aad = header + struct.pack(">Q", index)
        try:
            plain = aes.decrypt(sealed[:12], sealed[12:], aad)
        except InvalidTag:
            raise ValueError("does not authenticate")
        total += len(plain)
        if total > plain_length:
            raise ValueError("longer than its header says")
        write(plain)
        index += 1
    # No end marker in the format: the length in the header is what catches a file
    # cut off at a frame boundary.
    if index == 0 or total != plain_length:
        raise ValueError("shorter than its header says")
    return total


def decrypt_entry_bytes(archive: Archive, entry: Entry, key: bytes, limit: int) -> bytes:
    if entry.length > limit:
        raise ArchiveError("That file is not a Sock Drawer archive, or it is damaged.")
    out = bytearray()
    with open(archive.path, "rb") as f:
        f.seek(entry.offset)
        decrypt_stream(f, entry.length, key, out.extend)
    return bytes(out)


# --- The index ------------------------------------------------------------------------


def swift_date(value) -> Optional[dt.datetime]:
    if value is None:
        return None
    if not isinstance(value, (int, float)):
        raise ArchiveError("The archive's index is not in a form this script understands.")
    return SWIFT_EPOCH + dt.timedelta(seconds=value)


def decode_keys(raw) -> dict:
    """`[UUID: Data]` from Swift's JSONEncoder. A UUID is not a String key, so it comes
    out as a flat [key, value, key, value] array; a dictionary is accepted too, in case
    a later Swift writes it that way."""
    if raw is None:
        return {}
    if isinstance(raw, dict):
        pairs = list(raw.items())
    elif isinstance(raw, list) and len(raw) % 2 == 0:
        pairs = list(zip(raw[0::2], raw[1::2]))
    else:
        raise ArchiveError("The archive's index is not in a form this script understands.")
    keys = {}
    for key_id, value in pairs:
        try:
            keys[str(key_id).upper()] = base64.b64decode(value, validate=True)
        except (ValueError, TypeError):
            raise ArchiveError("The archive's index is not in a form this script understands.")
    return keys


def read_index(data: bytes) -> dict:
    try:
        raw = json.loads(data)
    except ValueError:
        raise ArchiveError("The archive's index is not in a form this script understands.")
    if isinstance(raw, list):  # schema 0: a bare array of items
        raw = {"schemaVersion": 0, "items": raw}
    _require_fields(raw, KNOWN_INDEX_FIELDS, "the index")
    schema = raw.get("schemaVersion", 1)
    if schema not in KNOWN_SCHEMAS:
        raise ArchiveError(
            f"This archive's index is schema {schema}; this script reads "
            f"{sorted(KNOWN_SCHEMAS)}. Get a newer copy of this script.")
    items = raw.get("items") or []
    albums = raw.get("albums") or []
    for item in items:
        _require_fields(item, KNOWN_ITEM_FIELDS, "an item")
        if item.get("kind") not in KNOWN_KINDS:
            raise ArchiveError(
                f"This archive holds a kind of item this script does not know "
                f"({item.get('kind')!r}). Get a newer copy of this script.")
        if not isinstance(item.get("id"), str):
            raise ArchiveError("The archive's index is not in a form this script understands.")
    for album in albums:
        _require_fields(album, KNOWN_ALBUM_FIELDS, "an album")
    return {"items": items, "albums": albums, "keys": decode_keys(raw.get("keys"))}


# --- Output ---------------------------------------------------------------------------


def safe_extension(ext) -> str:
    ext = str(ext or "").lower()
    return ext if re.fullmatch(r"[a-z0-9]{1,10}", ext) else "bin"


def taken_value(item: dict):
    """When the camera took it if known, else when it was added: the app's own rule."""
    captured = item.get("capturedAt")
    return captured if captured is not None else item.get("addedAt")


def output_name(item: dict) -> str:
    taken = swift_date(taken_value(item))
    stamp = taken.strftime("%Y-%m-%d_%H%M%S") if taken else "undated"
    short = item["id"].replace("-", "")[:8].lower()
    return f"{stamp}_{short}.{safe_extension(item.get('fileExtension'))}"


def relative_path(item: dict) -> str:
    name = output_name(item)
    return f"Recently Deleted/{name}" if item.get("deletedAt") is not None else name


def iso(value) -> str:
    when = swift_date(value)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ") if when else ""


@dataclass
class Result:
    written: int = 0
    skipped: int = 0  # already there from an earlier run
    failed: int = 0


def extract(archive: Archive, vault_key: bytes, index: dict, out_dir: str,
            log: Callable[[str], None] = print) -> Result:
    os.makedirs(out_dir, exist_ok=True)
    album_names = {a["id"]: a.get("name", "Untitled") for a in index["albums"]}
    result = Result()
    rows = []

    with open(archive.path, "rb") as src:
        for item in index["items"]:
            rel = relative_path(item)
            row = {
                "id": item["id"], "file": "", "kind": item["kind"],
                "taken_utc": iso(taken_value(item)),
                "added_utc": iso(item.get("addedAt")),
                "deleted_utc": iso(item.get("deletedAt")),
                "albums": "; ".join(sorted(album_names.get(a, "")
                                           for a in item.get("albumIDs") or [])),
                "favorite": "yes" if item.get("isFavorite") else "",
                "problem": "",
            }
            rows.append(row)

            # Entry names are the app's own uppercase UUID strings; match on the raw id,
            # never on Python's lowercase str(uuid).
            entry = archive.entry(f"{item['id']}.mjv")
            key_id = item.get("keyID")
            key = vault_key if key_id is None else index["keys"].get(str(key_id).upper())
            problem = None
            if entry is None:
                problem = "its file is not in the archive"
            elif key is None:
                problem = "the key it was encrypted with is not in the archive"
            if problem:
                row["problem"] = problem
                result.failed += 1
                log(f"Could not write {item['id']}: {problem}.")
                continue

            final = os.path.join(out_dir, *rel.split("/"))
            os.makedirs(os.path.dirname(final), exist_ok=True)

            src.seek(entry.offset)
            header = src.read(FILE_HEADER_LENGTH)
            expected = struct.unpack(">Q", header[8:16])[0] if len(header) == 32 else -1
            if os.path.exists(final) and os.path.getsize(final) == expected:
                row["file"] = rel
                result.skipped += 1
                continue

            # Written beside its final name and renamed only once every chunk has
            # authenticated and the length adds up. An interrupted run or a full disk
            # leaves a .part, never a short file that looks finished.
            part = final + ".part"
            src.seek(entry.offset)
            try:
                with open(part, "wb") as out:
                    decrypt_stream(src, entry.length, key, out.write)
                os.replace(part, final)
            except ValueError as error:
                _remove(part)
                row["problem"] = f"damaged ({error})"
                result.failed += 1
                log(f"Could not write {item['id']}: it is damaged ({error}).")
                continue
            except BaseException:
                _remove(part)
                raise
            row["file"] = rel
            result.written += 1
            log(f"  {rel}")

    manifest = os.path.join(out_dir, "manifest.csv")
    with open(manifest + ".part", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]) if rows else ["id"])
        writer.writeheader()
        writer.writerows(rows)
    os.replace(manifest + ".part", manifest)
    return result


def _remove(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


# --- Entry point ----------------------------------------------------------------------


def open_archive(path: str, passphrase: str) -> tuple:
    archive = read_archive(path)
    key = unwrap_key(archive.wrap, passphrase)
    index_entry = archive.entry(INDEX_NAME)
    try:
        data = decrypt_entry_bytes(archive, index_entry, key, MAX_INDEX_BYTES)
    except ValueError:
        raise ArchiveError("The archive's index is damaged.")
    return archive, key, read_index(data)


def main(argv=None, passphrase: Optional[str] = None,
         log: Callable[[str], None] = print) -> int:
    parser = argparse.ArgumentParser(
        description="Open a Sock Drawer archive (.mjarchive) without the app.")
    parser.add_argument("archive", help="the .mjarchive file")
    parser.add_argument("output", nargs="?", help="folder to write the photos and videos to")
    parser.add_argument("--list", action="store_true",
                        help="list what is in the archive and write nothing")
    args = parser.parse_args(argv)
    if not args.list and not args.output:
        parser.error("give an output folder, or --list")

    if passphrase is None:
        passphrase = os.environ.get("SOCKDRAWER_PASSPHRASE") or getpass.getpass("Passphrase: ")

    try:
        archive, key, index = open_archive(args.archive, passphrase)
    except (ArchiveError, OSError) as error:
        log(f"Error: {error}")
        return 1

    if args.list:
        for item in index["items"]:
            present = archive.entry(f"{item['id']}.mjv") is not None
            log(f"{relative_path(item)}{'' if present else '  (file missing)'}")
        log(f"{len(index['items'])} items, {len(index['albums'])} albums.")
        return 0

    try:
        result = extract(archive, key, index, args.output, log)
    except OSError as error:
        log(f"Error: {error}")
        return 1
    log(f"Done: {result.written} written, {result.skipped} already there, "
        f"{result.failed} could not be written.")
    return 2 if result.failed else 0


if __name__ == "__main__":
    sys.exit(main())
