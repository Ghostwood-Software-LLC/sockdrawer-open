#!/usr/bin/env python3
"""Tests for sockdrawer_open.py against archives the app itself wrote.

    python3 test_open.py

Reads every fixture directory (archive.mjarchive + expected.json): fixtures/ next to
this file, plus any listed in DECRYPT_FIXTURE_DIRS (separated like PATH). In the app's
CI that is build/decrypt-fixture, written fresh by DecryptFixtureTests on every run, so
a change to the app's format fails here the same day.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import shutil
import struct
import sys
import tempfile
import unicodedata
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import sockdrawer_open as tool  # noqa: E402


def fixture_dirs():
    dirs = [os.path.join(HERE, "fixtures")]
    dirs += [d for d in os.environ.get("DECRYPT_FIXTURE_DIRS", "").split(os.pathsep) if d]
    found = [d for d in dirs if os.path.exists(os.path.join(d, "expected.json"))]
    if not found:
        raise SystemExit("No fixture found; see DecryptFixtureTests in the app.")
    return found


class Fixture:
    def __init__(self, directory):
        self.dir = directory
        self.archive = os.path.join(directory, "archive.mjarchive")
        with open(os.path.join(directory, "expected.json"), encoding="utf-8") as f:
            self.expected = json.load(f)
        self.passphrase = self.expected["passphrase"]
        self.items = self.expected["items"]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def run(archive, out, passphrase, *extra):
    log = []
    code = tool.main([archive, out, *extra] if out else [archive, *extra],
                     passphrase=passphrase, log=log.append)
    return code, log


class OpenTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sockdrawer-open-")
        self.fixtures = [Fixture(d) for d in fixture_dirs()]

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def out(self, name="out"):
        return os.path.join(self.tmp, name)

    # --- The format the app writes is the format this reads -----------------------

    def test_the_tool_knows_every_field_and_kind_the_app_writes(self):
        for fx in self.fixtures:
            with self.subTest(fixture=fx.dir):
                fmt = fx.expected["format"]
                self.assertEqual(set(fmt["indexFields"]), tool.KNOWN_INDEX_FIELDS)
                self.assertEqual(set(fmt["itemFields"]), tool.KNOWN_ITEM_FIELDS)
                self.assertEqual(set(fmt["albumFields"]), tool.KNOWN_ALBUM_FIELDS)
                self.assertEqual(set(fmt["wrapFields"]), tool.KNOWN_WRAP_FIELDS)
                self.assertEqual(set(fmt["entryFields"]), tool.KNOWN_ENTRY_FIELDS)
                self.assertEqual(set(fmt["kinds"]), tool.KNOWN_KINDS)
                self.assertEqual(fmt["archiveMagic"].encode(), tool.ARCHIVE_MAGIC)
                self.assertEqual(fmt["archiveVersion"], tool.ARCHIVE_VERSION)
                self.assertEqual(fmt["fileMagic"].encode(), tool.FILE_MAGIC)
                self.assertEqual(fmt["fileHeaderLength"], tool.FILE_HEADER_LENGTH)
                self.assertIn(fmt["indexSchema"], tool.KNOWN_SCHEMAS)
                self.assertEqual(fmt["maxIterations"], tool.MAX_ITERATIONS)

    # --- Round trip ---------------------------------------------------------------

    def test_every_item_comes_out_byte_for_byte_under_its_expected_name(self):
        for fx in self.fixtures:
            with self.subTest(fixture=fx.dir):
                out = self.out(os.path.basename(fx.dir))
                code, log = run(fx.archive, out, fx.passphrase)
                # The fixture has one item whose file was lost, so: written, but not all.
                self.assertEqual(code, 2, log)
                for item in fx.items:
                    if item["missing"]:
                        continue
                    path = os.path.join(out, *item["file"].split("/"))
                    self.assertTrue(os.path.exists(path), f"missing {item['file']}")
                    self.assertEqual(sha256(path), item["sha256"], item["file"])
                self.assertEqual(self.leftover_parts(out), [])

    def test_the_fixture_covers_every_case(self):
        for fx in self.fixtures:
            with self.subTest(fixture=fx.dir):
                self.assertTrue(any(i["missing"] for i in fx.items))
                self.assertTrue(any(i["deleted"] and not i["missing"] for i in fx.items))
                self.assertTrue(any(i["mergedKey"] and not i["missing"] for i in fx.items))
                self.assertTrue(any(i["kind"] == "video" for i in fx.items))
                self.assertTrue(any(i["albums"] for i in fx.items))
                self.assertTrue(any(ord(c) > 127 for c in fx.passphrase))

    def test_the_manifest_lists_every_item_with_its_albums(self):
        for fx in self.fixtures:
            with self.subTest(fixture=fx.dir):
                out = self.out(os.path.basename(fx.dir))
                run(fx.archive, out, fx.passphrase)
                with open(os.path.join(out, "manifest.csv"), newline="", encoding="utf-8") as f:
                    rows = {r["id"]: r for r in csv.DictReader(f)}
                self.assertEqual(set(rows), {i["id"] for i in fx.items})
                for item in fx.items:
                    row = rows[item["id"]]
                    self.assertEqual(row["file"], item["file"])
                    self.assertEqual(row["albums"], "; ".join(item["albums"]))
                    self.assertEqual(row["favorite"], "yes" if item["favorite"] else "")
                    self.assertEqual(bool(row["deleted_utc"]), item["deleted"])
                    self.assertEqual(bool(row["problem"]), item["missing"])

    def test_a_second_run_skips_what_is_already_there(self):
        fx = self.fixtures[0]
        out = self.out()
        run(fx.archive, out, fx.passphrase)
        code, log = run(fx.archive, out, fx.passphrase)
        self.assertEqual(code, 2)
        present = sum(1 for i in fx.items if not i["missing"])
        self.assertIn(f"0 written, {present} already there", log[-1])

    def test_list_writes_nothing(self):
        fx = self.fixtures[0]
        code, log = run(fx.archive, None, fx.passphrase, "--list")
        self.assertEqual(code, 0, log)
        self.assertIn(f"{len(fx.items)} items", log[-1])
        self.assertEqual(os.listdir(self.tmp), [])

    # --- Passphrases --------------------------------------------------------------

    def test_a_passphrase_typed_decomposed_still_opens_it(self):
        for fx in self.fixtures:
            with self.subTest(fixture=fx.dir):
                nfd = unicodedata.normalize("NFD", fx.passphrase)
                self.assertNotEqual(nfd, fx.passphrase, "fixture passphrase has nothing to decompose")
                code, log = run(fx.archive, None, nfd, "--list")
                self.assertEqual(code, 0, log)

    def test_the_wrong_passphrase_writes_nothing(self):
        fx = self.fixtures[0]
        out = self.out()
        code, log = run(fx.archive, out, fx.passphrase + "x")
        self.assertEqual(code, 1)
        self.assertIn("passphrase does not open", log[-1])
        self.assertFalse(os.path.exists(out))

    # --- Damage -------------------------------------------------------------------

    def test_a_cut_off_archive_writes_nothing(self):
        fx = self.fixtures[0]
        with open(fx.archive, "rb") as f:
            data = f.read()
        for cut in (1, 1024, len(data) // 2):
            with self.subTest(cut=cut):
                path = os.path.join(self.tmp, f"cut-{cut}.mjarchive")
                with open(path, "wb") as f:
                    f.write(data[:-cut])
                out = self.out(f"cut-{cut}")
                code, log = run(path, out, fx.passphrase)
                self.assertEqual(code, 1, log)
                self.assertIn("incomplete", log[-1])
                self.assertFalse(os.path.exists(out))

    def test_a_file_cut_at_a_frame_boundary_is_refused(self):
        # MJV1 has no end marker; only the length in its header catches this.
        fx = self.fixtures[0]
        archive = tool.read_archive(fx.archive)
        key = tool.unwrap_key(archive.wrap, fx.passphrase)
        video = next(i for i in fx.items if i["kind"] == "video")
        entry = archive.entry(video["id"] + ".mjv")
        with open(fx.archive, "rb") as f:
            f.seek(entry.offset)
            sealed = f.read(entry.length)
        first_frame = 4 + struct.unpack(">I", sealed[32:36])[0]
        self.assertLess(32 + first_frame, len(sealed), "the video should span several frames")
        with self.assertRaises(ValueError):
            tool.decrypt_stream(io.BytesIO(sealed), 32 + first_frame, key, lambda _: None)

    def test_a_damaged_file_is_reported_and_leaves_nothing_behind(self):
        fx = self.fixtures[0]
        archive = tool.read_archive(fx.archive)
        video = next(i for i in fx.items if i["kind"] == "video")
        entry = archive.entry(video["id"] + ".mjv")
        path = os.path.join(self.tmp, "damaged.mjarchive")
        shutil.copy(fx.archive, path)
        with open(path, "r+b") as f:
            f.seek(entry.offset + entry.length - 100)  # inside the last frame
            byte = f.read(1)
            f.seek(-1, os.SEEK_CUR)
            f.write(bytes([byte[0] ^ 0xFF]))
        out = self.out()
        code, log = run(path, out, fx.passphrase)
        self.assertEqual(code, 2)
        self.assertFalse(os.path.exists(os.path.join(out, video["file"])))
        self.assertEqual(self.leftover_parts(out), [])
        self.assertTrue(any("damaged" in line for line in log))

    # --- Fails closed on what it does not know ------------------------------------

    def test_an_unknown_item_field_or_kind_stops_it(self):
        for change in ({"pairedVideo": "x"}, {"kind": "livePhoto"}):
            with self.subTest(change=change):
                item = {"id": "A" * 8 + "-AAAA-AAAA-AAAA-" + "A" * 12, "kind": "photo",
                        "addedAt": 0, "byteCount": 1, "fileExtension": "jpg"}
                item.update(change)
                index = json.dumps({"schemaVersion": 2, "items": [item]}).encode()
                with self.assertRaises(tool.ArchiveError):
                    tool.read_index(index)

    def test_older_indexes_are_read(self):
        item = {"id": "B" * 8 + "-BBBB-BBBB-BBBB-" + "B" * 12, "kind": "photo",
                "addedAt": 0, "byteCount": 1}
        legacy = tool.read_index(json.dumps([item]).encode())         # schema 0
        unversioned = tool.read_index(json.dumps({"items": [item]}).encode())  # schema 1
        self.assertEqual(len(legacy["items"]), 1)
        self.assertEqual(len(unversioned["items"]), 1)
        # Swift's dates count from 2001: zero is 2001-01-01, not 1970.
        self.assertTrue(tool.output_name(item).startswith("2001-01-01_000000_"))

    @staticmethod
    def leftover_parts(out):
        return [os.path.join(d, f) for d, _, files in os.walk(out)
                for f in files if f.endswith(".part")]


if __name__ == "__main__":
    unittest.main(verbosity=2)
