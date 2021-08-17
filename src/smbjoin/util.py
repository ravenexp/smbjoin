"""
Utility functions module

Provides high level wrappers for the Samba TDB API functions
and some binary encoding functions.
"""

from typing import Dict, Union

import struct
import os

# No type stubs for tdb and no way to add them
import tdb  # type: ignore


def sid_encode(sid: str) -> bytes:
    """
    Encodes a machine SID string into the binary representation
    used by Windows and Samba.
    """

    parts = sid.split("-")

    if parts[0] != "S" or parts[1] != "1":
        raise ValueError(f"Not a SID string: {sid}")

    if parts[2] != "5":
        raise ValueError(f"Not a valid NT SID: {sid}")

    if len(parts) != 7:
        raise ValueError(f"Not a machine SID: {sid}")

    words = (int(parts[3]), int(parts[4]), int(parts[5]), int(parts[6]))

    sid_bytes = b"\x01\x04\x00\x00\x00\x00\x00\x05"
    sid_bytes += struct.pack("<IIII", *words)

    return sid_bytes


def tdb_save(keyvals: Dict[str, Union[str, bytes]], fname: str) -> None:
    """
    Stores the user provided key-value pairs into a new TDB database file.
    """

    osflags = os.O_CREAT | os.O_RDWR
    tdb_obj = tdb.open(fname, flags=osflags)

    for key, value in keyvals.items():
        raw_key = key.encode("ascii")

        if isinstance(value, str):
            # String values are usually stored in the null-terminated format
            raw_value = value.encode("ascii") + b"\x00"
        else:
            raw_value = bytes(value)

        tdb_obj.store(raw_key, raw_value)
