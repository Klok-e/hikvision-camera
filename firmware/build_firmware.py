#!/usr/bin/env python3
"""Build and verify a narrowly scoped watchdog addition to official R2 firmware.

Container/signature format reference:
https://github.com/renaudallard/hikvision_R2_firmware/blob/main/hikfw.py
No upload, device connection, or flash operation is provided.
"""

import argparse
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


OFFICIAL_SHA256 = "d9dd1fbe0581aec1a931b9743299fec872c58bbb5f71cf2645f4d4ede7d246fb"
DEFAULT_SOURCE = Path(__file__).resolve().parent / "official" / "digicap.dav"
MEMBERS = ("_cfgUpgSecPls", "_cfgUpgClass", "uImage", "app.img")
XOR_KEY = bytes.fromhex("bacdbcfed6caddd3bab9a3abbfcbb5be")
START_COMMAND = b"\n/bin/sh /dav/network-watchdog.sh >/dev/null 2>&1 &\n"
OBSOLETE_LINK = b"ln -s /dav/WebComponents.exe /home/webLib/codebase/WebComponents.exe\n"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


@lru_cache(maxsize=12)
def sha0(data):
    """SHA-0, whose message expansion omits SHA-1's rotate operation."""
    words = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    padded = data + b"\x80" + b"\0" * ((55 - len(data)) % 64) + struct.pack(">Q", len(data) * 8)
    mask = 0xffffffff
    for offset in range(0, len(padded), 64):
        w = list(struct.unpack_from(">16I", padded, offset))
        for i in range(16, 80):
            w.append(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16])
        a, b, c, d, e = words
        for i in range(80):
            if i < 20:
                f, k = (b & c) | (~b & d), 0x5A827999
            elif i < 40:
                f, k = b ^ c ^ d, 0x6ED9EBA1
            elif i < 60:
                f, k = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
            else:
                f, k = b ^ c ^ d, 0xCA62C1D6
            a, b, c, d, e = (((a << 5) | (a >> 27)) + f + e + k + w[i]) & mask, a, ((b << 30) | (b >> 2)) & mask, c, d
        words = [(old + new) & mask for old, new in zip(words, (a, b, c, d, e))]
    return struct.pack(">5I", *words)


def xor_header(data):
    return bytes(value ^ XOR_KEY[(i + (i >> 4)) & 15] for i, value in enumerate(data))


def cstring(raw):
    require(b"\0" in raw, "Unterminated member name")
    name, padding = raw.split(b"\0", 1)
    require(name and not padding.strip(b"\0"), "Invalid member name padding")
    require(all(32 < value < 127 for value in name) and b"/" not in name and b"\\" not in name, "Unsafe member name")
    return name.decode("ascii")


@dataclass(frozen=True)
class Member:
    name: str
    offset: int
    data: bytes


def parse_package(data):
    require(len(data) >= 240, "Truncated SWKH header")
    header = xor_header(data[:240])
    require(header[:4] == b"SWKH", "Wrong SWKH magic")
    require(struct.unpack_from("<II", header, 8) == (240, 4), "Unexpected SWKH layout")
    require(struct.unpack_from("<I", header, 32)[0] == len(data), "Wrong SWKH total size")
    require(struct.unpack_from("<I", header, 4)[0] == sum(header[12:]) & 0xffffffff, "SWKH header checksum mismatch")
    members = []
    cursor = 240
    for i, expected in enumerate(MEMBERS):
        pos = 64 + 44 * i
        name = cstring(header[pos:pos + 32])
        offset, size, checksum = struct.unpack_from("<III", header, pos + 32)
        require(name == expected and offset == cursor and size <= len(data) - offset, "Invalid SWKH member layout")
        body = data[offset:offset + size]
        require(sum(body) & 0xffffffff == checksum, f"SWKH checksum mismatch: {name}")
        members.append(Member(name, offset, body))
        cursor += size
    require(cursor == len(data), "Trailing SWKH data")
    return header, members


def aes_key():
    key, previous = b"", b""
    while len(key) < 32:
        previous = hashlib.md5(hashlib.md5(previous + b"h@k8807H$Z5998" + b"\0" * 17 + b"HangZhou").digest()).digest()
        key += previous
    return key[:32]


def decrypt_manifest(data):
    require(len(data) >= 20, "Truncated encrypted manifest")
    length = struct.unpack_from("<I", data)[0]
    require(0 < length <= len(data) - 4 and length % 16 == 0, "Invalid encrypted manifest length")
    require(not data[4 + length:].strip(b"\0"), "Unexpected encrypted manifest trailer")
    decryptor = Cipher(algorithms.AES(aes_key()), modes.ECB()).decryptor()
    plain = decryptor.update(data[4:4 + length]) + decryptor.finalize()
    pad = plain[-1]
    require(1 <= pad <= 16 and plain[-pad:] == bytes([pad]) * pad, "Invalid manifest padding")
    plain = plain[:-pad]
    require(len(plain) >= 204 and struct.unpack_from("<I", plain)[0] == 0x484b3533, "Invalid manifest header")
    count = struct.unpack_from("<I", plain, 28)[0]
    require(count == 3 and len(plain) == 204 + 76 * count, "Unexpected manifest row layout")
    require(plain[4:24] == sha0(plain[24:]), "Manifest header SHA-0 mismatch")
    return plain


def encrypt_manifest(plain, size):
    pad = 16 - len(plain) % 16
    encryptor = Cipher(algorithms.AES(aes_key()), modes.ECB()).encryptor()
    encrypted = encryptor.update(plain + bytes([pad]) * pad) + encryptor.finalize()
    result = struct.pack("<I", len(encrypted)) + encrypted
    require(len(result) <= size, "Manifest grew beyond its reserved member size")
    return result + b"\0" * (size - len(result))


def verify_manifest(members, package_size):
    plain = decrypt_manifest(members[0].data)
    # The vendor field excludes the 240-byte SWKH header.
    require(struct.unpack_from("<I", plain, 60)[0] == package_size - 240, "Manifest payload size mismatch")
    for i, member in enumerate(members[1:]):
        pos = 204 + 76 * i
        require(cstring(plain[pos:pos + 32]) == member.name, "Manifest member name mismatch")
        require(struct.unpack_from("<II", plain, pos + 52) == (len(member.data), member.offset), "Manifest member bounds mismatch")
        require(plain[pos + 32:pos + 52] == sha0(member.data), f"Manifest SHA-0 mismatch: {member.name}")
    return plain


@dataclass(frozen=True)
class Inode:
    mode: int
    uid: int
    gid: int
    data: bytes


def parse_cramfs(image):
    require(len(image) >= 76, "Truncated CramFS superblock")
    magic, size, flags, reserved = struct.unpack_from("<IIII", image)
    require(magic == 0x28cd3d45 and size == len(image), "Invalid CramFS magic/size")
    require(flags == 3 and reserved == 0 and image[16:32] == b"Compressed ROMFS", "Unsupported CramFS features")
    crc_image = bytearray(image)
    crc_image[32:36] = b"\0" * 4
    require(zlib.crc32(crc_image) == struct.unpack_from("<I", image, 32)[0], "CramFS CRC mismatch")

    def inode_at(pos):
        require(0 <= pos <= len(image) - 12, "CramFS inode out of bounds")
        a, b, c = struct.unpack_from("<III", image, pos)
        return a & 65535, a >> 16, b >> 24, b & 0xffffff, (c >> 6) * 4, (c & 63) * 4

    mode, uid, gid, root_size, root_offset, namelen = inode_at(64)
    require(stat.S_ISDIR(mode) and namelen == 0 and root_offset == 76, "Unsupported CramFS root")
    end = root_offset + root_size
    require(end <= len(image), "CramFS directory exceeds image")
    root = Inode(mode, uid, gid, b"")
    files = {}
    cursor = root_offset
    while cursor < end:
        require(cursor + 12 <= end, "Truncated CramFS directory entry")
        mode, uid, gid, size, offset, namelen = inode_at(cursor)
        require(namelen and cursor + 12 + namelen <= end, "Invalid CramFS filename size")
        raw_name = image[cursor + 12:cursor + 12 + namelen]
        name = raw_name.rstrip(b"\0").decode("ascii")
        require(name and name not in (".", "..") and "/" not in name and "\\" not in name and "\0" not in name and name not in files, "Unsafe CramFS filename")
        require(stat.S_ISREG(mode), "Only flat regular-file CramFS images are supported")
        blocks = (size + 4095) // 4096
        require((not blocks and offset == 0) or (offset >= end and offset + 4 * blocks <= len(image)), "CramFS block table out of bounds")
        block_start = offset + 4 * blocks
        output = bytearray()
        for block in range(blocks):
            block_end = struct.unpack_from("<I", image, offset + 4 * block)[0]
            require(block_start < block_end <= len(image), "CramFS compressed block out of bounds")
            decoder = zlib.decompressobj()
            try:
                decompressed = decoder.decompress(image[block_start:block_end], 4097)
            except zlib.error as exc:
                raise ValueError("Invalid CramFS compressed block") from exc
            require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail, "Invalid CramFS compressed block")
            require(len(decompressed) == min(4096, size - len(output)), "CramFS decompressed size mismatch")
            output.extend(decompressed)
            block_start = block_end
        files[name] = Inode(mode, uid, gid, bytes(output))
        cursor += 12 + namelen
    require(cursor == end and struct.unpack_from("<I", image, 44)[0] == len(files) + 1, "CramFS inode count mismatch")
    require(list(files) == sorted(files), "CramFS directory is not sorted")
    return root, files


def run(command):
    return subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def native_check(image, directory):
    path = directory / "check.cramfs"
    path.write_bytes(image)
    run(["fsck.cramfs", "--extract", str(path)])


def expected_initrun(files):
    require("initrun.sh" in files and "WebComponents.exe" in files and "network-watchdog.sh" not in files, "Unexpected init/installer/watchdog entries")
    original = files["initrun.sh"].data
    lines = original.splitlines(keepends=True)
    require(lines.count(OBSOLETE_LINK) == 1, "Expected exactly one original ActiveX symlink command")
    require(b"network-watchdog.sh" not in original, "Watchdog already referenced in initrun")
    return b"".join(line for line in lines if line != OBSOLETE_LINK) + START_COMMAND


def patch_cramfs(original, watchdog, directory):
    root, files = parse_cramfs(original)
    initrun = expected_initrun(files)
    require(watchdog.startswith(b"#!/bin/sh\n") and b"\0" not in watchdog, "Watchdog must be a /bin/sh script without NUL bytes")
    native_check(original, directory)
    source = directory / "tree"
    source.mkdir()
    expected = dict(files)
    del expected["WebComponents.exe"]
    init = files["initrun.sh"]
    expected["initrun.sh"] = Inode(init.mode, init.uid, init.gid, initrun)
    expected["network-watchdog.sh"] = Inode(stat.S_IFREG | 0o755, init.uid, init.gid, watchdog)
    metadata = [(str(source), root.uid, root.gid, root.mode)]
    for name, inode in sorted(expected.items()):
        path = source / name
        path.write_bytes(inode.data)
        metadata.append((str(path), inode.uid, inode.gid, inode.mode))
    recipe = directory / "metadata.json"
    recipe.write_text(json.dumps(metadata))
    builder = directory / "mkfs.py"
    builder.write_text("import json,os,subprocess,sys\nfor p,u,g,m in json.load(open(sys.argv[1])):\n os.chown(p,u,g); os.chmod(p,m)\nsubprocess.run(sys.argv[2:],check=True)\n")
    result = directory / "new.cramfs"
    name = original[48:64].rstrip(b"\0").decode("ascii")
    edition = struct.unpack_from("<I", original, 36)[0]
    run(["fakeroot", sys.executable, str(builder), str(recipe), "mkfs.cramfs", "-E", "-N", "little", "-e", str(edition), "-n", name, str(source), str(result)])
    image = result.read_bytes()
    new_root, new_files = parse_cramfs(image)
    require(new_root == root and new_files == dict(sorted(expected.items())), "Rebuilt CramFS content or metadata mismatch")
    require(image[36:40] == original[36:40] and image[48:64] == original[48:64], "CramFS name/edition changed")
    require([name for name in new_files if name in files] == [name for name in files if name != "WebComponents.exe"], "Retained inode ordering changed")
    native_check(image, directory)
    return image, files, new_files


def repack(header, old_members, app):
    members = list(old_members)
    members[-1] = Member("app.img", members[-1].offset, app)
    size = members[-1].offset + len(app)
    plain = bytearray(verify_manifest(old_members, old_members[-1].offset + len(old_members[-1].data)))
    struct.pack_into("<I", plain, 60, size - 240)
    for i, member in enumerate(members[1:]):
        pos = 204 + 76 * i
        plain[pos + 32:pos + 52] = sha0(member.data)
        struct.pack_into("<II", plain, pos + 52, len(member.data), member.offset)
    plain[4:24] = sha0(bytes(plain[24:]))
    members[0] = Member(members[0].name, members[0].offset, encrypt_manifest(bytes(plain), len(members[0].data)))
    new_header = bytearray(header)
    struct.pack_into("<I", new_header, 32, size)
    for i, member in enumerate(members):
        struct.pack_into("<III", new_header, 96 + 44 * i, member.offset, len(member.data), sum(member.data) & 0xffffffff)
    struct.pack_into("<I", new_header, 4, sum(new_header[12:]) & 0xffffffff)
    return xor_header(new_header) + b"".join(member.data for member in members)


def verify_artifact(original, artifact, watchdog):
    require(sha256(original) == OFFICIAL_SHA256, "Source is not the verified official image")
    header, before = parse_package(original)
    new_header, after = parse_package(artifact)
    old_plain = verify_manifest(before, len(original))
    new_plain = verify_manifest(after, len(artifact))
    require(before[1:3] == after[1:3], "Native compatibility member or kernel changed")
    require(len(after[-1].data) <= len(before[-1].data), "Application image exceeds official image size")
    old_root, old_files = parse_cramfs(before[-1].data)
    new_root, new_files = parse_cramfs(after[-1].data)
    initrun = expected_initrun(old_files)
    require(old_root == new_root and set(new_files) == (set(old_files) - {"WebComponents.exe"}) | {"network-watchdog.sh"}, "Unexpected filesystem metadata or entries")
    for name, inode in old_files.items():
        if name == "WebComponents.exe":
            continue
        expected = Inode(inode.mode, inode.uid, inode.gid, initrun) if name == "initrun.sh" else inode
        require(new_files[name] == expected, f"Unexpected filesystem change: {name}")
    init = old_files["initrun.sh"]
    require(new_files["network-watchdog.sh"] == Inode(stat.S_IFREG | 0o755, init.uid, init.gid, watchdog), "Watchdog bytes/metadata mismatch")
    require(before[-1].data[36:40] == after[-1].data[36:40] and before[-1].data[48:64] == after[-1].data[48:64], "Filesystem edition/name changed")
    mutable_header = set(range(4, 8)) | set(range(32, 36))
    for i in (0, 3):
        mutable_header.update(range(96 + 44 * i, 108 + 44 * i))
    require(all(a == b for i, (a, b) in enumerate(zip(header, new_header)) if i not in mutable_header), "Unrelated SWKH header fields changed")
    mutable_plain = set(range(4, 24)) | set(range(60, 64)) | set(range(204 + 152 + 32, 204 + 152 + 60))
    require(all(a == b for i, (a, b) in enumerate(zip(old_plain, new_plain)) if i not in mutable_plain), "Unrelated signed manifest fields changed")
    require([n for n in new_files if n in old_files] == [n for n in old_files if n != "WebComponents.exe"], "Retained inode ordering changed")
    file_comparison = {
        name: {"sha256": sha256(inode.data), "size": len(inode.data), "mode": oct(inode.mode), "uid": inode.uid, "gid": inode.gid, "present": True,
               "change": "added" if name not in old_files else "modified" if inode.data != old_files[name].data else "unchanged"}
        for name, inode in new_files.items()
    }
    removed = old_files["WebComponents.exe"]
    file_comparison["WebComponents.exe"] = {"sha256": sha256(removed.data), "size": len(removed.data), "mode": oct(removed.mode), "uid": removed.uid, "gid": removed.gid, "present": False, "change": "removed"}
    return {
        "source_sha256": sha256(original), "output_sha256": sha256(artifact), "output_size": len(artifact),
        "watchdog_sha256": sha256(watchdog),
        "modifications": {"WebComponents.exe": "remove obsolete ActiveX installer", "initrun.sh": {"removed_command": OBSOLETE_LINK.decode("ascii"), "appended_command": START_COMMAND.decode("ascii")}, "network-watchdog.sh": "add mode 0755 with initrun owner"},
        "checks": {"swkh_header_and_all_member_checksums": True, "encrypted_manifest_header_and_all_member_sha0": True, "cramfs_crc_and_all_decompressed_files": True, "all_retained_inode_metadata_preserved": True, "kernel_and_compatibility_bytes_unchanged": True, "all_other_application_files_unchanged": True, "original_header_and_manifest_fields_preserved": True, "application_image_within_official_size": True},
        "application_image_size": {"official": len(before[-1].data), "candidate": len(after[-1].data), "delta": len(after[-1].data) - len(before[-1].data)},
        "files": file_comparison,
        "members": {member.name: {"offset": member.offset, "size": len(member.data), "sha256": sha256(member.data), "unchanged": member.data == before[i].data} for i, member in enumerate(after)},
        "flash_performed": False,
    }


def build(source, watchdog_path, output):
    manifest_path = output.with_name(output.name + ".manifest.json")
    require(not output.exists() and not manifest_path.exists(), "Refusing to overwrite output or manifest")
    original = source.read_bytes()
    require(sha256(original) == OFFICIAL_SHA256, "Source is not the verified official image")
    watchdog = watchdog_path.read_bytes()
    header, members = parse_package(original)
    verify_manifest(members, len(original))
    with tempfile.TemporaryDirectory(prefix="r2-watchdog-") as temp:
        directory = Path(temp)
        app, _, _ = patch_cramfs(members[-1].data, watchdog, directory)
        artifact = repack(header, members, app)
        report = verify_artifact(original, artifact, watchdog)
        native_check(parse_package(artifact)[1][-1].data, directory)
        report["checks"]["native_fsck_cramfs_extract"] = True
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as handle:
        handle.write(artifact)
    with manifest_path.open("x") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--watchdog", type=Path, required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--output", type=Path, help="build a new candidate and JSON manifest")
    action.add_argument("--verify", type=Path, help="independently check an existing candidate without writing it")
    args = parser.parse_args()
    try:
        if args.verify:
            original = args.source.read_bytes()
            artifact = args.verify.read_bytes()
            report = verify_artifact(original, artifact, args.watchdog.read_bytes())
            with tempfile.TemporaryDirectory(prefix="r2-verify-") as temp:
                native_check(parse_package(artifact)[1][-1].data, Path(temp))
            report["checks"]["native_fsck_cramfs_extract"] = True
            print(json.dumps(report, indent=2, sort_keys=True))
            return
        report = build(args.source, args.watchdog, args.output)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Build refused: {exc}\n")
    print(json.dumps({"output": str(args.output), "sha256": report["output_sha256"], "manifest": str(args.output) + ".manifest.json", "flash_performed": False}, indent=2))


if __name__ == "__main__":
    main()
