import os
import io
import zlib
import struct
import os.path
import marshal
import argparse
import compileall
import configparser

from pathlib import Path
from uuid import uuid4 as uniquename
from importlib.util import MAGIC_NUMBER

import lief
import lxml.etree as ET

PYINST21_COOKIE_SIZE = 24 + 64
MAGIC = b"MEI\014\013\012\013\016"  # Magic number which identifies pyinstaller
pyc_magic = MAGIC_NUMBER


def _writePyc(filename, pyver, data):
    with open(filename, "wb") as pycFile:
        pycFile.write(pyc_magic)  # pyc magic

        if pyver >= 37:  # PEP 552 -- Deterministic pycs
            pycFile.write(b"\0" * 4)  # Bitfield
            pycFile.write(b"\0" * 8)  # (Timestamp + size) || hash

        else:
            pycFile.write(b"\0" * 4)  # Timestamp
            if pyver >= 33:
                pycFile.write(b"\0" * 4)  # Size parameter added in Python 3.3

        pycFile.write(data)


def _readPyc(filename, pyver):
    data = Path(filename).read_bytes()

    if pyver >= 37:
        data = data[16:]
    elif pyver >= 33:
        data = data[12:]

    return data


class PYZArchiveEntry:
    def __init__(self, internal_name, filepath, ispkg, position, length):
        self.internal_name = internal_name
        self.filepath = filepath
        self.ispkg = ispkg
        self.position = position
        self.length = length
        self.data = None

    def set_data(self, data):
        self.data = data


class PYZArchive:
    def __init__(self):
        self.entries: list(PYZArchiveEntry) = []

    def parse_from_data(self, pyzdata):
        self.pyzdata_file = io.BytesIO(pyzdata)
        pyzmagic = self.pyzdata_file.read(4)
        assert pyzmagic == b"PYZ\0"  # Sanity Check

        pycheader = self.pyzdata_file.read(4)  # Python magic value

        if pyc_magic != pycheader:
            print(
                "[!] Warning: This script is running in a different Python version than the one used to build the executable."
            )
            # print('[!] Please run this script in Python{0} to prevent extraction errors during unmarshalling'.format(self.pyver))

        (tocPosition,) = struct.unpack("!i", self.pyzdata_file.read(4))
        self.pyzdata_file.seek(tocPosition, os.SEEK_SET)

        try:
            toc = marshal.load(self.pyzdata_file)
        except:
            print("[!] Marshal load error")
            return

        # From pyinstaller 3.1+ toc is a list of tuples
        for entry in toc:
            internal_name = entry[0]
            ispkg = entry[1][0]
            position = entry[1][1]
            length = entry[1][2]

            self.add_entry(
                PYZArchiveEntry(internal_name, internal_name, ispkg, position, length)
            )

    def add_entry(self, entry: PYZArchiveEntry):
        save_pos = self.pyzdata_file.tell()
        self.pyzdata_file.seek(entry.position)
        self.add_entry_with_data(entry, self.pyzdata_file.read(entry.length))
        self.pyzdata_file.seek(save_pos, os.SEEK_SET)

    def add_entry_with_data(self, entry: PYZArchiveEntry, data: bytes):
        entry.set_data(data)
        self.entries.append(entry)

    def dump_tree(self):
        root = ET.Element("PYZArchive")

        for entry in self.entries:
            ET.SubElement(
                root,
                "PYZArchiveEntry",
                {
                    "internal_name": entry.internal_name,
                    "ispkg": str(entry.ispkg),
                    "filepath": entry.filepath,
                },
            )

        return root

    def extract(self, output_dir: Path, pyver):
        print(f"        [+] Extracting PYZArchive (Total entries: {len(self.entries)})")
        for idx, entry in enumerate(self.entries):
            data = entry.data
            print(
                f"            [P] {entry.internal_name} [{idx+1}/{len(self.entries)}]"
            )

            # Replacing \\ and / isn't really needed
            filepath = (
                entry.filepath.replace("\\", os.path.sep)
                .replace("/", os.path.sep)
                .replace("..", "__")
                .replace(".", os.path.sep)
            )
            if entry.ispkg == 1:
                filepath = str(Path(filepath).joinpath("__init__.pyc"))
            else:
                filepath += ".pyc"

            op = output_dir.joinpath(filepath)
            if os.sep in filepath:
                op.parent.mkdir(parents=True, exist_ok=True)

            _writePyc(str(op), pyver, zlib.decompress(data))
            entry.filepath = str(op)


class CArchiveEntry:
    def __init__(
        self,
        position,
        compressed_size,
        uncompressed_size,
        compression_flags,
        type_data,
        internal_name,
        filepath,
    ):
        self.position = position
        self.compressed_size = compressed_size
        self.uncompressed_size = uncompressed_size
        self.compression_flags = compression_flags
        self.type_data = type_data
        self.internal_name = internal_name
        self.filepath = filepath
        self.data = None

    def set_data(self, data):
        self.data = data


class CArchive:
    def __init__(self):
        self.entries: list(CArchiveEntry) = []
        self.pydata_file = None
        self.pyver = None
        self.pylibname = None

    def parse_from_file(self, pydata_path):
        self.pydata_file = io.BufferedRandom(io.FileIO(pydata_path, mode="r+b"))
        self.pydata_file.seek(-PYINST21_COOKIE_SIZE, os.SEEK_END)

        magic_from_file = self.pydata_file.read(len(MAGIC))

        if magic_from_file != MAGIC:
            print(
                "[!] Error : Unsupported pyinstaller version or not a pyinstaller archive"
            )
            return

        self.pydata_file.seek(-PYINST21_COOKIE_SIZE, os.SEEK_END)

        # Read CArchive cookie
        (
            magic,
            lengthofPackage,
            toc,
            tocLen,
            self.pyver,
            self.pylibname,
        ) = struct.unpack("!8siiii64s", self.pydata_file.read(PYINST21_COOKIE_SIZE))

        self.pydata_file.seek(toc, os.SEEK_SET)
        parsedLen = 0

        # Parse table of contents
        while parsedLen < tocLen:
            (entrySize,) = struct.unpack("!i", self.pydata_file.read(4))
            nameLen = struct.calcsize("!iiiiBc")

            (
                entryPos,
                cmprsdDataSize,
                uncmprsdDataSize,
                cmprsFlag,
                typeCmprsData,
                internal_name,
            ) = struct.unpack(
                "!iiiBc{0}s".format(entrySize - nameLen),
                self.pydata_file.read(entrySize - 4),
            )

            internal_name = internal_name.rstrip(b"\0").decode("utf-8")
            filename = internal_name

            if len(filename) == 0:
                filename = str(uniquename())
                print(
                    "[!] Warning: Found an unamed file in CArchive. Using random name {0}".format(
                        filename
                    )
                )

            carchiveentry = CArchiveEntry(
                entryPos,
                cmprsdDataSize,
                uncmprsdDataSize,
                cmprsFlag,
                typeCmprsData.decode(),
                internal_name,
                filename,
            )

            self.add_entry(carchiveentry)
            parsedLen += entrySize

    def add_entry(self, entry: CArchiveEntry):
        save_pos = self.pydata_file.tell()
        self.pydata_file.seek(entry.position)
        data = self.pydata_file.read(entry.compressed_size)
        self.add_entry_with_data(entry, data)
        self.pydata_file.seek(save_pos, os.SEEK_SET)

    def add_entry_with_data(self, entry: CArchiveEntry, data: bytes):
        if entry.type_data in ("z", "Z"):
            pyz_archive = PYZArchive()
            pyz_archive.parse_from_data(data)
            data = pyz_archive

        entry.set_data(data)
        self.entries.append(entry)

    def dump_tree(self):
        root = ET.Element(
            "CArchive",
            {
                "pyver": str(self.pyver),
                "pylibname": str(self.pylibname.strip(b"\0").decode()),
            },
        )

        for entry in self.entries:
            elem = ET.SubElement(
                root,
                "CArchiveEntry",
                {
                    "internal_name": entry.internal_name,
                    "compression_flags": str(entry.compression_flags),
                    "type_data": entry.type_data,
                    "filepath": entry.filepath,
                },
            )

            if entry.type_data in ("z", "Z"):
                elem.append(entry.data.dump_tree())

        return root

    def extract(self, output_dir: Path):
        print(f"[+] Extracting CArchive (Total entries: {len(self.entries)})")
        for idx, entry in enumerate(self.entries):
            data = entry.data
            print(f"    [C] {entry.internal_name} [{idx+1}/{len(self.entries)}]")

            filepath = (
                entry.filepath.replace("\\", os.path.sep)
                .replace("/", os.path.sep)
                .replace("..", "__")
            )

            if type(data) == bytes:
                if entry.compression_flags == 1:
                    data = zlib.decompress(data)
                    assert len(data) == entry.uncompressed_size

                op = output_dir.joinpath(filepath)
                if os.sep in filepath:
                    op.parent.mkdir(parents=True, exist_ok=True)

                if entry.type_data in ("s"):
                    op = op.with_suffix(".pyc")
                    _writePyc(str(op), self.pyver, data)

                elif entry.type_data in ("m", "M"):
                    op = op.with_suffix(".pyc")
                    op.write_bytes(data)

                else:
                    op.write_bytes(data)

                entry.filepath = str(op)
            else:
                pyz_extract_dir = output_dir.joinpath(filepath)
                pyz_extract_dir.mkdir(exist_ok=True)
                entry.data.extract(pyz_extract_dir, self.pyver)
                entry.filepath = str(pyz_extract_dir)


class PYZArchiveBuilder:
    @staticmethod
    def load_tree(tree, pyver, scanpy, ignore_missing):
        pyzarchive = PYZArchive()

        for e in tree.findall(".//PYZArchive/"):
            internal_name = str(e.attrib["internal_name"])
            filepath = e.attrib["filepath"]
            ispkg = e.attrib["ispkg"]

            if scanpy:
                # Check if a corresponding .py exist
                py_filepath = Path(filepath).with_suffix(".py")
                if py_filepath.is_file():
                    print(f"    - Compiling {py_filepath}", end="")
                    if compileall.compile_file(str(py_filepath), legacy=True, quiet=2):
                        print(" [OK]")
                    else:
                        print(" [FAIL]")

            if not Path(filepath).exists() and ignore_missing:
                print(f"[!] Ignoring missing file {filepath}")
                continue

            data = _readPyc(filepath, pyver)

            pyzarchiveentry = PYZArchiveEntry(
                internal_name, filepath, ispkg, -1, len(data)
            )
            pyzarchive.add_entry_with_data(pyzarchiveentry, data)

        return pyzarchive

    @staticmethod
    def build(pyzarchive: PYZArchive):
        toc = []
        print(
            f"        [+] Building PYZArchive (Total entries: {len(pyzarchive.entries)})"
        )

        pyzdata = io.BytesIO()
        pyzdata.write(b"PYZ\0")
        pyzdata.write(pyc_magic)
        pyzdata.write(b"\0\0\0\0")
        pyzdata.write(b"\0" * 5)

        for idx, entry in enumerate(pyzarchive.entries):
            print(
                f"            [P] {entry.internal_name} [{idx+1}/{len(pyzarchive.entries)}]"
            )

            compressed_data = zlib.compress(entry.data, 6)
            position = pyzdata.tell()
            length = len(compressed_data)
            pyzdata.write(compressed_data)

            toc.append((entry.internal_name, (int(entry.ispkg), position, length)))

        tocbytes = marshal.dumps(toc, marshal.version)
        toc_position = pyzdata.tell()
        pyzdata.write(tocbytes)
        pyzdata.seek(8)
        pyzdata.write(struct.pack("!i", toc_position))
        return pyzdata.getvalue()


class CArchiveBuilder:
    @staticmethod
    def load_tree_from_file(xml_file, scanpy, ignore_missing):
        tree = ET.parse(xml_file)

        carchive = CArchive()

        carchive.pyver = int(tree.getroot().attrib["pyver"])
        carchive.pylibname = tree.getroot().attrib["pylibname"]

        for e in tree.findall("./CArchiveEntry"):
            internal_name = e.attrib["internal_name"]
            filepath = e.attrib["filepath"]
            compression_flags = int(e.attrib["compression_flags"])
            type_data = e.attrib["type_data"]

            if type_data not in ("z", "Z"):
                # ARCHIVE_ITEM_PYSOURCE
                # ARCHIVE_ITEM_PYPACKAGE
                # ARCHIVE_ITEM_PYMODULE
                if scanpy and type_data in ("s", "m", "M"):
                    # Check if a corresponding .py exist
                    py_filepath = Path(filepath).with_suffix(".py")
                    if py_filepath.is_file():
                        print(f"    - Compiling {py_filepath}", end="")
                        if compileall.compile_file(
                            str(py_filepath), legacy=True, quiet=2
                        ):
                            print(" [OK]")
                        else:
                            print(" [FAIL]")

                if not Path(filepath).exists() and ignore_missing:
                    print(f"[!] Ignoring missing file {filepath}")
                    continue

                if type_data in ("s"):
                    data = _readPyc(filepath, carchive.pyver)
                else:
                    data = Path(filepath).read_bytes()

                if compression_flags == 1:
                    compressed_data = zlib.compress(data, 9)
                else:
                    compressed_data = data

                carchiveentry = CArchiveEntry(
                    -1,
                    len(compressed_data),
                    len(data),
                    compression_flags,
                    type_data,
                    internal_name,
                    "",
                )
                carchive.add_entry_with_data(carchiveentry, compressed_data)
            else:
                pyzarchive = PYZArchiveBuilder.load_tree(e, carchive.pyver, scanpy, ignore_missing)
                carchiveentry = CArchiveEntry(
                    -1, -1, -1, compression_flags, type_data, internal_name, ""
                )
                carchiveentry.set_data(pyzarchive)
                carchive.entries.append(carchiveentry)

        return carchive

    @staticmethod
    def build(carchive: CArchive):
        toc_list = []
        print(f"[+] Building CArchive (Total entries: {len(carchive.entries)})")

        carchivedata = io.BytesIO()
        for idx, entry in enumerate(carchive.entries):
            print(f"    [C] {entry.internal_name} [{idx+1}/{len(carchive.entries)}]")
            if entry.type_data not in ("z", "Z"):
                data = entry.data

            elif entry.type_data in ("z", "Z"):
                data = PYZArchiveBuilder.build(entry.data)
                entry.compressed_size = entry.uncompressed_size = len(data)

            else:
                raise ("Unknown type code")

            position = carchivedata.tell()
            carchivedata.write(data)

            toc_list.append(
                (
                    position,
                    entry.compressed_size,
                    entry.uncompressed_size,
                    entry.compression_flags,
                    entry.type_data,
                    entry.internal_name,
                )
            )

        toc_pos = carchivedata.tell()

        ENTRYSTRUCT = (
            "!iiiiBB"  # (structlen, dpos, dlen, ulen, flag, typcd) followed by name
        )
        ENTRYLEN = struct.calcsize(ENTRYSTRUCT)

        print("[+] Writing CArchive Table of Contents")
        for (dpos, dlen, ulen, flag, typcd, nm) in toc_list:
            nm = nm.encode("utf-8")
            nmlen = len(nm) + 1  # add 1 for a '\0'

            # align to 16 byte boundary so xplatform C can read
            toclen = nmlen + ENTRYLEN
            if toclen % 16 == 0:
                pad = b"\0"
            else:
                padlen = 16 - (toclen % 16)
                pad = b"\0" * padlen
                nmlen = nmlen + padlen

            toc_entry_data = struct.pack(
                ENTRYSTRUCT + "%is" % nmlen,
                nmlen + ENTRYLEN,
                dpos,
                dlen,
                ulen,
                flag,
                ord(typcd),
                nm + pad,
            )

            carchivedata.write(toc_entry_data)

        toc_len = carchivedata.tell() - toc_pos

        total_len = toc_pos + toc_len + PYINST21_COOKIE_SIZE

        cookie = struct.pack(
            "!8siiii64s",
            MAGIC,
            total_len,
            toc_pos,
            toc_len,
            carchive.pyver,
            carchive.pylibname.encode("ascii"),
        )

        print("[+] Writing CArchive cookie")
        carchivedata.write(cookie)

        return carchivedata.getvalue()


def do_extract(exe_file):
    pe_bytes = open(exe_file, "rb").read()
    pe_size = len(pe_bytes)

    pe = lief.parse(exe_file)

    base_dir = Path(exe_file + "-repacker")
    print(f"[+] Creating output directory {base_dir}")
    base_dir.mkdir(exist_ok=True)

    config = configparser.ConfigParser()
    config["DEFAULT"]["input_name"] = os.path.basename(exe_file)
    config.write(base_dir.joinpath("config.ini").open("w"))

    overlay_bytes = bytes(pe.overlay)
    overlay_size = len(overlay_bytes)

    bootloader_dir = base_dir.joinpath("BOOTLOADER")
    bootloader_dir.mkdir(exist_ok=True)
    print("[+] Dumping bootloader")

    bootloader_dir.joinpath("bootloader.exe").write_bytes(
        pe_bytes[: pe_size - overlay_size]
    )

    carchive_dir = base_dir.joinpath("CARCHIVE")
    carchive_dir.mkdir(exist_ok=True)
    print("[+] Dumping CArchive")

    carchive_dir.joinpath("carchive").write_bytes(overlay_bytes)

    carchive = CArchive()
    carchive.parse_from_file(carchive_dir.joinpath("carchive"))

    extract_dir = base_dir.joinpath("tmp")
    extract_dir.mkdir(exist_ok=True)
    carchive.extract(extract_dir)

    print("[+] Writing filelist")
    ET.ElementTree(carchive.dump_tree()).write(
        str(base_dir.joinpath("filelist.xml")), pretty_print=True
    )
    print("[+] Done!")


def do_build(input_dir, scanpy, ignore_missing):
    input_path = Path(input_dir)
    filelist_path = input_path.joinpath("filelist.xml")
    config_path = input_path.joinpath("config.ini")

    if not config_path.exists():
        print(f"[!] Missing {config_path}")
        return

    config = configparser.ConfigParser()
    config.read(config_path)
    input_file = config["DEFAULT"]["input_name"]

    if filelist_path.exists():
        print("[+] Loading filelist")
        carchive = CArchiveBuilder.load_tree_from_file(str(filelist_path), scanpy, ignore_missing)
        carchdata = CArchiveBuilder.build(carchive)

        bootloader_path = input_path.joinpath("BOOTLOADER/bootloader.exe")

        if bootloader_path.exists():
            bootloader = bootloader_path.read_bytes()
            output_file = os.path.splitext(input_file)[0] + "-repacked.exe"
            print(f"[+] Writing new exe to {output_file}")
            input_path.joinpath(output_file).write_bytes(bootloader + carchdata)
            print("[+] Done!")

        else:
            print(f"[!] Missing {bootloader_path}")

    else:
        print(f"[!] Missing {filelist_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest="command", required=True)

    extract_parser = subparsers.add_parser("extract", help="Command to extract the exe")
    extract_parser.add_argument("file", help="Path to the exe")

    build_parser = subparsers.add_parser("build", help="Command to build an exe")
    build_parser.add_argument(
        "--scanpy",
        help="Use corresponding .py file instead of .pyc (if it exists)",
        dest="scanpy",
        action="store_true",
    )

    build_parser.add_argument(
        "--ignore-missing",
        help="Ignore missing files",
        dest="ignore_missing",
        action="store_true",
    )

    build_parser.add_argument("directory", help="Path to the repacker directory")
    args = parser.parse_args()

    if args.command == "extract":
        do_extract(args.file)

    elif args.command == "build":
        do_build(args.directory, args.scanpy, args.ignore_missing)
