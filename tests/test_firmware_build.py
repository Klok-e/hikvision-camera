"""Integrity contracts, using real native CramFS and AES implementations."""

import importlib.util
from pathlib import Path
import random
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib


MODULE_PATH = Path(__file__).resolve().parents[1] / "firmware" / "build_firmware.py"
spec = importlib.util.spec_from_file_location("firmware_builder", MODULE_PATH)
fw = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = fw
spec.loader.exec_module(fw)


def repair_crc(image):
    image = bytearray(image)
    image[32:36] = b"\0" * 4
    struct.pack_into("<I", image, 32, zlib.crc32(image))
    return bytes(image)


def package_fixture(app):
    contents = [b"\0" * 500, b"native compatibility\xff", b"native kernel\xfe", app]
    header = bytearray(240)
    header[:4] = b"SWKH"
    struct.pack_into("<II", header, 8, 240, 4)
    header[16:32] = bytes(range(16))
    header[36:64] = bytes(range(28))
    members = []
    offset = 240
    for name, body in zip(fw.MEMBERS, contents):
        members.append(fw.Member(name, offset, body))
        offset += len(body)
    plain = bytearray(432)
    struct.pack_into("<I", plain, 0, 0x484b3533)
    struct.pack_into("<I", plain, 28, 3)
    struct.pack_into("<I", plain, 60, offset - 240)
    plain[64:204] = bytes(range(140))
    for i, member in enumerate(members[1:]):
        pos = 204 + 76 * i
        name = member.name.encode()
        plain[pos:pos + len(name)] = name
        plain[pos + 32:pos + 52] = fw.sha0(member.data)
        struct.pack_into("<II", plain, pos + 52, len(member.data), member.offset)
        plain[pos + 60:pos + 76] = bytes([i + 1]) * 16
    plain[4:24] = fw.sha0(bytes(plain[24:]))
    members[0] = fw.Member(fw.MEMBERS[0], 240, fw.encrypt_manifest(bytes(plain), 500))
    for i, member in enumerate(members):
        pos = 64 + 44 * i
        name = member.name.encode()
        header[pos:pos + len(name)] = name
        struct.pack_into("<III", header, pos + 32, member.offset, len(member.data), sum(member.data) & 0xffffffff)
    struct.pack_into("<I", header, 32, offset)
    struct.pack_into("<I", header, 4, sum(header[12:]) & 0xffffffff)
    return fw.xor_header(header) + b"".join(member.data for member in members)


class HashAndPackageTests(unittest.TestCase):
    def test_sha0_known_published_vectors(self):
        self.assertEqual(fw.sha0(b"").hex(), "f96cea198ad1dd5617ac084a3d92c6107708c0ef")
        self.assertEqual(fw.sha0(b"abc").hex(), "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880")

    def test_truncated_and_wrong_length_packages_are_rejected(self):
        package = package_fixture(b"small app")
        for malformed in (b"", package[:239], package[:-1], package + b"extra"):
            with self.subTest(length=len(malformed)), self.assertRaises(ValueError):
                fw.parse_package(malformed)

    def test_member_tampering_is_rejected(self):
        package = bytearray(package_fixture(b"small app"))
        package[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            fw.parse_package(package)

    def test_manifest_rejects_wrong_hash_bounds_and_ciphertext(self):
        package = package_fixture(b"small app")
        _, members = fw.parse_package(package)
        fw.verify_manifest(members, len(package))
        changed = list(members)
        changed[-1] = fw.Member("app.img", members[-1].offset, b"other app")
        with self.assertRaisesRegex(ValueError, "SHA-0 mismatch"):
            fw.verify_manifest(changed, len(package))
        plain = bytearray(fw.decrypt_manifest(members[0].data))
        struct.pack_into("<I", plain, 204 + 152 + 56, 0xffffffff)
        plain[4:24] = fw.sha0(bytes(plain[24:]))
        changed[0] = fw.Member(fw.MEMBERS[0], 240, fw.encrypt_manifest(bytes(plain), 500))
        with self.assertRaisesRegex(ValueError, "bounds mismatch"):
            fw.verify_manifest(changed, len(package))
        for malformed in (b"", struct.pack("<I", 0xffffffff) + members[0].data[4:], members[0].data[:-1] + b"x"):
            with self.assertRaises(ValueError):
                fw.decrypt_manifest(malformed)

    def test_build_refuses_unverified_source_and_existing_destinations(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            source = directory / "source.dav"
            source.write_bytes(b"unverified source")
            output = directory / "patched.dav"
            with self.assertRaisesRegex(ValueError, "verified official"):
                fw.build(source, directory / "missing-watchdog", output)
            self.assertFalse(output.exists())
            output.write_bytes(b"preserve me")
            with self.assertRaisesRegex(ValueError, "overwrite"):
                fw.build(source, directory / "missing-watchdog", output)
            self.assertEqual(output.read_bytes(), b"preserve me")


@unittest.skipUnless(all(shutil.which(tool) for tool in ("mkfs.cramfs", "fsck.cramfs", "fakeroot")), "native CramFS tools required")
class FilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        source = self.directory / "fixture"
        source.mkdir()
        self.original_initrun = b"#!/bin/sh\n# original non-UTF8 \xff\nln -s /dav/WebComponents.exe /home/webLib/codebase/WebComponents.exe\n/bin/native &\n"
        (source / "initrun.sh").write_bytes(self.original_initrun)
        (source / "native.bin").write_bytes(bytes(range(256)) * 40)
        (source / "IEfile.tar.gz").write_bytes(b"unchanged native web archive\x00\xff" * 10)
        (source / "WebComponents.exe").write_bytes(b"MZ" + random.Random(7).randbytes(24000))
        recipe = self.directory / "fixture.py"
        recipe.write_text("import os,subprocess,sys\np=sys.argv[1]\nfor f in [p]+[p+'/'+n for n in os.listdir(p)]:\n os.chown(f,1086,62);os.chmod(f,0o755 if f.endswith('initrun.sh') else 0o775 if f==p else 0o640)\nsubprocess.run(['mkfs.cramfs','-E','-N','little','-e','27','-n','r2_app',p,sys.argv[2]],check=True)\n")
        image = self.directory / "fixture.cramfs"
        subprocess.run(["fakeroot", sys.executable, str(recipe), str(source), str(image)], check=True, capture_output=True)
        self.image = image.read_bytes()
        self.watchdog = b"#!/bin/sh\nwhile :; do sleep 60; done\n"

    def tearDown(self):
        self.temp.cleanup()

    def patch_image(self):
        directory = self.directory / "patch"
        directory.mkdir()
        return fw.patch_cramfs(self.image, self.watchdog, directory)[0]

    def test_native_rebuild_preserves_binary_bytes_and_all_ownership_permissions(self):
        image = self.patch_image()
        root, files = fw.parse_cramfs(image)
        self.assertEqual((root.uid, root.gid, root.mode), (1086, 62, stat.S_IFDIR | 0o775))
        self.assertEqual(files["native.bin"], fw.Inode(stat.S_IFREG | 0o640, 1086, 62, bytes(range(256)) * 40))
        self.assertEqual(files["IEfile.tar.gz"], fw.Inode(stat.S_IFREG | 0o640, 1086, 62, b"unchanged native web archive\x00\xff" * 10))
        self.assertEqual(files["initrun.sh"].data, b"#!/bin/sh\n# original non-UTF8 \xff\n/bin/native &\n" + fw.START_COMMAND)
        self.assertNotIn("WebComponents.exe", files)
        self.assertNotIn(b"WebComponents.exe", files["initrun.sh"].data)
        self.assertEqual(files["network-watchdog.sh"], fw.Inode(stat.S_IFREG | 0o755, 1086, 62, self.watchdog))
        self.assertEqual(struct.unpack_from("<I", image, 36)[0], 27)
        self.assertEqual(image[48:64], b"r2_app" + b"\0" * 10)
        self.assertLess(len(image), len(self.image))

    def test_source_requires_installer_and_exactly_one_obsolete_symlink_line(self):
        _, files = fw.parse_cramfs(self.image)
        missing = dict(files)
        del missing["WebComponents.exe"]
        with self.assertRaisesRegex(ValueError, "installer"):
            fw.expected_initrun(missing)
        original = files["initrun.sh"]
        for contents in (self.original_initrun.replace(fw.OBSOLETE_LINK, b""), self.original_initrun + fw.OBSOLETE_LINK, self.original_initrun.replace(fw.OBSOLETE_LINK, b"#" + fw.OBSOLETE_LINK)):
            with self.subTest(contents=contents):
                malformed = dict(files)
                malformed["initrun.sh"] = fw.Inode(original.mode, original.uid, original.gid, contents)
                with self.assertRaisesRegex(ValueError, "exactly one"):
                    fw.expected_initrun(malformed)
        commented_link = b"#ln -s /dav/WebComponents.exe /home/webLib/codebase/WebComponents.exe\n"
        files["initrun.sh"] = fw.Inode(original.mode, original.uid, original.gid, commented_link + self.original_initrun)
        self.assertEqual(fw.expected_initrun(files), commented_link + b"#!/bin/sh\n# original non-UTF8 \xff\n/bin/native &\n" + fw.START_COMMAND)

    def test_cramfs_rejects_corruption_and_out_of_bounds_inode_after_valid_crc(self):
        damaged = bytearray(self.image)
        damaged[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "CRC mismatch"):
            fw.parse_cramfs(damaged)
        bad_inode = bytearray(self.image)
        word = struct.unpack_from("<I", bad_inode, 84)[0]
        struct.pack_into("<I", bad_inode, 84, 0xffffffc0 | (word & 63))
        with self.assertRaisesRegex(ValueError, "out of bounds"):
            fw.parse_cramfs(repair_crc(bad_inode))

    def test_signed_repack_accepts_only_requested_patch_and_preserves_unknown_fields(self):
        original = package_fixture(self.image)
        header, members = fw.parse_package(original)
        artifact = fw.repack(header, members, self.patch_image())
        with patch.object(fw, "OFFICIAL_SHA256", fw.sha256(original)):
            report = fw.verify_artifact(original, artifact, self.watchdog)
            self.assertTrue(all(report["checks"].values()))
            self.assertTrue(report["members"]["uImage"]["unchanged"])
            self.assertFalse(report["flash_performed"])
            self.assertEqual(report["files"]["WebComponents.exe"]["change"], "removed")
            self.assertFalse(report["files"]["WebComponents.exe"]["present"])
            self.assertEqual(report["files"]["IEfile.tar.gz"]["change"], "unchanged")
            self.assertEqual(report["files"]["initrun.sh"]["change"], "modified")
            self.assertEqual(report["files"]["network-watchdog.sh"]["change"], "added")
            self.assertEqual(report["modifications"]["initrun.sh"]["removed_command"], "ln -s /dav/WebComponents.exe /home/webLib/codebase/WebComponents.exe\n")
            self.assertTrue(report["checks"]["all_retained_inode_metadata_preserved"])
            with self.assertRaisesRegex(ValueError, "Watchdog bytes/metadata"):
                fw.verify_artifact(original, artifact, b"#!/bin/sh\nwrong\n")
            # A fully re-signed filesystem with changed ownership must still fail.
            _, altered_members = fw.parse_package(artifact)
            altered_app = bytearray(altered_members[-1].data)
            mode_uid = struct.unpack_from("<I", altered_app, 76)[0]
            struct.pack_into("<I", altered_app, 76, (mode_uid & 0xffff) | (42 << 16))
            tampered = fw.repack(header, members, repair_crc(altered_app))
            with self.assertRaisesRegex(ValueError, "Unexpected filesystem change"):
                fw.verify_artifact(original, tampered, self.watchdog)

    def test_resigned_image_exceeding_official_application_size_is_rejected(self):
        original = package_fixture(self.image)
        header, members = fw.parse_package(original)
        image = bytearray(self.patch_image())
        image.extend(b"\0" * (len(self.image) + 4096 - len(image)))
        struct.pack_into("<I", image, 4, len(image))
        artifact = fw.repack(header, members, repair_crc(image))
        with patch.object(fw, "OFFICIAL_SHA256", fw.sha256(original)):
            with self.assertRaisesRegex(ValueError, "exceeds official image size"):
                fw.verify_artifact(original, artifact, self.watchdog)

    def test_build_writes_verifiable_manifest_and_is_deterministic(self):
        original = package_fixture(self.image)
        source = self.directory / "source.dav"
        source.write_bytes(original)
        script = self.directory / "watchdog.sh"
        script.write_bytes(self.watchdog)
        with patch.object(fw, "OFFICIAL_SHA256", fw.sha256(original)):
            first = self.directory / "one.dav"
            second = self.directory / "two.dav"
            report = fw.build(source, script, first)
            fw.build(source, script, second)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertTrue(first.with_name(first.name + ".manifest.json").exists())
        self.assertTrue(report["checks"]["native_fsck_cramfs_extract"])


if __name__ == "__main__":
    unittest.main()
