#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import struct
import sys
import tempfile
import tokenize
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF



ZSS_VERSION = "0.5.0-beta"

ZSSPY_MAGIC = b"ZSSPY\x01\x00\x00"
ZSSPY_FORMAT_VERSION = 1

ZSON_MAGIC = b"ZSSON\x01\x00\x00"
ZSON_SCHEMA_VERSION = 1

DEFAULT_N_LAYERS = 5
MAX_N_LAYERS = 255
MIN_N_LAYERS = 1

NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
X25519_PUBKEY_SIZE = 32
MASTER_KEY_SIZE = 32

WRAP_OVERHEAD = X25519_PUBKEY_SIZE + NONCE_SIZE + MASTER_KEY_SIZE + TAG_SIZE

ZSSPY_HEADER_FIXED = (
    8 + 2 + 1 + 3 + X25519_PUBKEY_SIZE + NONCE_SIZE + MASTER_KEY_SIZE + TAG_SIZE
)

ZSS_HOME = Path.home() / ".zss"
KEYS_DIR = ZSS_HOME / "keys"
ZSON_PATH = ZSS_HOME / "zss.zson"
PRIVATE_KEY_PATH = KEYS_DIR / "master.x25519"
PUBLIC_KEY_PATH = KEYS_DIR / "master.pub"

DIRECTIVE_PREFIX = "#<zss>{"
DIRECTIVE_OPEN_KW = "write_to"
DIRECTIVE_CLOSE_KW = "closing!write"
FILENAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*\.zspy$")
DIRECTIVE_LINE_RE = re.compile(
    r"^\s*#\s*<zss>\s*\{\s*(write_to|closing!write)\s*!\s*([a-zA-Z_][a-zA-Z0-9_]*)\.zspy\s*\}\s*$"
)
LOAD_STUB_TEMPLATE = 'from zss import load; load("{filename}")'

_SEED_PEPPER = bytearray(
    b"\x12\x9a\xf1\x4c\xb8\xe2\x07\x3d\x91\x55\xcc\xae\x62\xeb\x10\x2f"
    b"\x7c\x48\x91\x03\xbd\xf6\x58\xa1\xde\xc4\x39\x82\x71\x90\x55\x77"
)
_SEED_SALT = bytearray(
    b"\xa4\x21\x6f\x03\xd8\x9c\x57\x1e\xb3\x40\x7a\xe2\x0c\x6d\x95\x28"
)

INFO_ZSON = b"zss:zson:v1"
INFO_WRAP = b"zss:wrap:v1"
INFO_LAYER_PREFIX = b"zss:layer:"
INFO_MASTER = b"zss:master:v1"

_seed_wiped = False



class ZssError(Exception):
    pass


class ZssParseError(ZssError):
    pass


class ZssCryptoError(ZssError):
    pass


class ZssFormatError(ZssError):
    pass


class ZssKeyError(ZssError):
    pass


class ZssConfigError(ZssError):
    pass



def zero_fill(buf: Any) -> None:
    if buf is None:
        return
    if isinstance(buf, bytearray):
        n = len(buf)
        if n == 0:
            return
        try:
            import ctypes as _ct
            addr = (_ct.c_char * n).from_buffer(buf)
            _ct.memset(addr, 0, n)
            return
        except Exception:
            pass
        for i in range(n):
            buf[i] = 0
    elif isinstance(buf, bytes):
        pass
    elif isinstance(buf, list):
        for i in range(len(buf)):
            if isinstance(buf[i], (bytearray, list)):
                zero_fill(buf[i])
            else:
                buf[i] = 0


def _secure_random(n: int) -> bytes:
    return os.urandom(n)


def _ensure_dir(path: Path, mode: int = 0o700) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _check_file_perms(path: Path, expected: int = 0o600) -> bool:
    try:
        st = os.stat(path)
    except OSError:
        return False
    return (st.st_mode & 0o077) == 0


def atomic_write_bytes(path: Path, data: bytes, mode: int = 0o600) -> None:
    path = Path(path)
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=str(parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def atomic_write_text(path: Path, text: str, mode: int = 0o600) -> None:
    atomic_write_bytes(path, text.encode("utf-8"), mode)


def safe_delete(path: Path) -> None:
    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError:
        return
    try:
        with open(path, "r+b") as f:
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass
    try:
        os.unlink(path)
    except OSError:
        pass


def read_bytes(path: Path) -> bytes:
    return Path(path).read_bytes()


def write_bytes(path: Path, data: bytes, mode: int = 0o600) -> None:
    atomic_write_bytes(path, data, mode)


def normalize_filename(name: str) -> str:
    if not isinstance(name, str) or not name:
        raise ZssFormatError(f"empty filename")
    if not FILENAME_RE.match(name):
        raise ZssFormatError(f"bad filename {name!r}: must match {FILENAME_RE.pattern}")
    return name


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _wipe_seeds() -> None:
    global _seed_wiped
    if _seed_wiped:
        return
    zero_fill(_SEED_PEPPER)
    zero_fill(_SEED_SALT)
    _seed_wiped = True



def generate_keypair() -> tuple[X25519PrivateKey, X25519PublicKey]:
    priv = X25519PrivateKey.generate()
    return priv, priv.public_key()


def serialize_private_key(priv: X25519PrivateKey) -> bytes:
    return priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def deserialize_private_key(data: bytes) -> X25519PrivateKey:
    if len(data) != 32:
        raise ZssKeyError(f"private key must be 32 bytes, got {len(data)}")
    return X25519PrivateKey.from_private_bytes(data)


def serialize_public_key(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def deserialize_public_key(data: bytes) -> X25519PublicKey:
    if len(data) != 32:
        raise ZssKeyError(f"public key must be 32 bytes, got {len(data)}")
    return X25519PublicKey.from_public_bytes(data)


def derive_shared(priv: X25519PrivateKey, pub: X25519PublicKey) -> bytes:
    return priv.exchange(pub)


def save_private_key(priv: X25519PrivateKey, path: Optional[Path] = None) -> None:
    if path is None:
        path = PRIVATE_KEY_PATH
    _ensure_dir(path.parent, mode=0o700)
    data = serialize_private_key(priv)
    atomic_write_bytes(path, data, mode=0o600)
    if not _check_file_perms(path, 0o600):
        raise ZssKeyError(f"failed to set 0600 on {path}")


def load_private_key(path: Optional[Path] = None) -> X25519PrivateKey:
    if path is None:
        path = PRIVATE_KEY_PATH
    if not path.exists():
        raise ZssKeyError(f"private key not found: {path}. Run `zss init` first.")
    if not _check_file_perms(path, 0o600):
        sys.stderr.write(
            f"warning: {path} has permissive mode, expected 0600. Continuing.\n"
        )
    data = read_bytes(path)
    try:
        return deserialize_private_key(data)
    except Exception as e:
        raise ZssKeyError(f"cannot parse private key {path}: {e}") from e


def save_public_key(pub: X25519PublicKey, path: Optional[Path] = None) -> None:
    if path is None:
        path = PUBLIC_KEY_PATH
    _ensure_dir(path.parent, mode=0o700)
    atomic_write_bytes(path, serialize_public_key(pub), mode=0o644)


def load_public_key(path: Optional[Path] = None) -> X25519PublicKey:
    if path is None:
        path = PUBLIC_KEY_PATH
    if not path.exists():
        raise ZssKeyError(f"public key not found: {path}")
    data = read_bytes(path)
    try:
        return deserialize_public_key(data)
    except Exception as e:
        raise ZssKeyError(f"cannot parse public key {path}: {e}") from e



def hkdf_derive(master: bytes, salt: bytes, info: bytes, length: int = KEY_SIZE) -> bytes:
    if length <= 0 or length > 255 * hashes.SHA256().digest_size:
        raise ZssCryptoError(f"bad hkdf length {length}")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(master)


def derive_master_key(shared: bytes, salt: bytes) -> bytes:
    return hkdf_derive(shared, salt=salt, info=INFO_MASTER, length=MASTER_KEY_SIZE)


def derive_wrap_key(shared: bytes, salt: bytes) -> bytes:
    return hkdf_derive(shared, salt=salt, info=INFO_WRAP, length=KEY_SIZE)


def derive_zson_key(priv: X25519PrivateKey, salt: bytes) -> bytes:
    self_shared = priv.exchange(priv.public_key())
    return hkdf_derive(self_shared, salt=salt, info=INFO_ZSON, length=KEY_SIZE)


def derive_layer_keys(master: bytes, n: int, salt: bytes) -> list[bytes]:
    if not (MIN_N_LAYERS <= n <= MAX_N_LAYERS):
        raise ZssCryptoError(f"n_layers out of range: {n}")
    keys: list[bytes] = []
    for i in range(1, n + 1):
        info = INFO_LAYER_PREFIX + str(i).encode("ascii")
        keys.append(hkdf_derive(master, salt=salt, info=info, length=KEY_SIZE))
    return keys



def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    if len(key) != KEY_SIZE:
        raise ZssCryptoError(f"key must be {KEY_SIZE} bytes, got {len(key)}")
    nonce = _secure_random(NONCE_SIZE)
    aead = ChaCha20Poly1305(key)
    ct = aead.encrypt(nonce, plaintext, aad)
    return nonce, ct


def aead_decrypt(
    key: bytes, nonce: bytes, ciphertext_with_tag: bytes, aad: bytes = b""
) -> bytes:
    if len(key) != KEY_SIZE:
        raise ZssCryptoError(f"key must be {KEY_SIZE} bytes, got {len(key)}")
    if len(nonce) != NONCE_SIZE:
        raise ZssCryptoError(f"nonce must be {NONCE_SIZE} bytes, got {len(nonce)}")
    if len(ciphertext_with_tag) < TAG_SIZE:
        raise ZssCryptoError("ciphertext too short to contain tag")
    aead = ChaCha20Poly1305(key)
    try:
        return aead.decrypt(nonce, ciphertext_with_tag, aad)
    except InvalidTag as e:
        raise ZssCryptoError("AEAD tag verification failed") from e


def _split_ct_tag(blob: bytes) -> tuple[bytes, bytes]:
    if len(blob) < TAG_SIZE:
        raise ZssCryptoError("ciphertext too short to contain tag")
    return blob[:-TAG_SIZE], blob[-TAG_SIZE:]


def _join_ct_tag(ct: bytes, tag: bytes) -> bytes:
    if len(tag) != TAG_SIZE:
        raise ZssCryptoError(f"tag must be {TAG_SIZE} bytes")
    return ct + tag



def _layer_aad(salt: bytes, layer_index: int, total_layers: int) -> bytes:
    if not (1 <= layer_index <= total_layers):
        raise ZssCryptoError(f"bad layer index {layer_index}/{total_layers}")
    return (
        b"zss:layer-aad:v1"
        b"|salt=" + salt
        + b"|i=" + str(layer_index).encode("ascii")
        + b"|n=" + str(total_layers).encode("ascii")
    )


@dataclass
class LayeredCiphertext:
    salt: bytes
    n_layers: int
    nonces: list[bytes]
    tags: list[bytes]
    ciphertext: bytes

    def total_overhead(self) -> int:
        return len(self.salt) + self.n_layers * (NONCE_SIZE + TAG_SIZE)


def encrypt_layers(plaintext: bytes, master: bytes, n: int, salt: bytes) -> LayeredCiphertext:
    if not (MIN_N_LAYERS <= n <= MAX_N_LAYERS):
        raise ZssCryptoError(f"n_layers out of range: {n}")
    if len(master) != MASTER_KEY_SIZE:
        raise ZssCryptoError(f"master must be {MASTER_KEY_SIZE} bytes")
    if len(salt) < 16:
        raise ZssCryptoError("salt must be at least 16 bytes")

    keys = derive_layer_keys(master, n, salt)
    nonces: list[bytes] = []
    tags: list[bytes] = []
    current = plaintext
    for i in range(n):
        key = keys[i]
        aad = _layer_aad(salt, i + 1, n)
        nonce, ct_with_tag = aead_encrypt(key, current, aad)
        ct, tag = _split_ct_tag(ct_with_tag)
        nonces.append(nonce)
        tags.append(tag)
        current = ct

    for k in keys:
        kb = bytearray(k)
        zero_fill(kb)

    return LayeredCiphertext(
        salt=salt,
        n_layers=n,
        nonces=nonces,
        tags=tags,
        ciphertext=current,
    )


def decrypt_layers(blob: LayeredCiphertext, master: bytes) -> bytes:
    if not (MIN_N_LAYERS <= blob.n_layers <= MAX_N_LAYERS):
        raise ZssCryptoError(f"n_layers out of range: {blob.n_layers}")
    if len(blob.nonces) != blob.n_layers or len(blob.tags) != blob.n_layers:
        raise ZssCryptoError("nonces/tags count mismatch with n_layers")
    if len(master) != MASTER_KEY_SIZE:
        raise ZssCryptoError(f"master must be {MASTER_KEY_SIZE} bytes")

    keys = derive_layer_keys(master, blob.n_layers, blob.salt)
    current = blob.ciphertext
    for i in range(blob.n_layers - 1, -1, -1):
        key = keys[i]
        aad = _layer_aad(blob.salt, i + 1, blob.n_layers)
        ct_with_tag = _join_ct_tag(current, blob.tags[i])
        try:
            current = aead_decrypt(key, blob.nonces[i], ct_with_tag, aad)
        except ZssCryptoError:
            for k in keys:
                zero_fill(bytearray(k))
            raise ZssCryptoError(
                f"layer {i + 1}/{blob.n_layers} tag verification failed"
            )

    for k in keys:
        zero_fill(bytearray(k))
    return current



@dataclass
class WrappedMasterKey:
    eph_pubkey: bytes
    wrap_nonce: bytes
    wrapped: bytes


def wrap_master_key(master: bytes, recipient_pub: X25519PublicKey) -> WrappedMasterKey:
    if len(master) != MASTER_KEY_SIZE:
        raise ZssCryptoError(f"master must be {MASTER_KEY_SIZE} bytes")

    eph_priv, eph_pub = generate_keypair()
    eph_pub_bytes = serialize_public_key(eph_pub)
    recipient_pub_bytes = serialize_public_key(recipient_pub)

    shared = eph_priv.exchange(recipient_pub)
    salt = eph_pub_bytes
    wrap_key = derive_wrap_key(shared, salt)

    aad = b"zss:wrap:v1|eph=" + eph_pub_bytes + b"|rcp=" + recipient_pub_bytes
    nonce = _secure_random(NONCE_SIZE)
    aead = ChaCha20Poly1305(wrap_key)
    wrapped = aead.encrypt(nonce, master, aad)

    zero_fill(bytearray(shared))
    zero_fill(bytearray(wrap_key))

    return WrappedMasterKey(
        eph_pubkey=eph_pub_bytes,
        wrap_nonce=nonce,
        wrapped=wrapped,
    )


def unwrap_master_key(
    wrap: WrappedMasterKey, recipient_priv: X25519PrivateKey
) -> bytes:
    if len(wrap.eph_pubkey) != X25519_PUBKEY_SIZE:
        raise ZssCryptoError("bad ephemeral pubkey length")
    if len(wrap.wrap_nonce) != NONCE_SIZE:
        raise ZssCryptoError("bad wrap nonce length")
    if len(wrap.wrapped) != MASTER_KEY_SIZE + TAG_SIZE:
        raise ZssCryptoError(
            f"bad wrapped length: expected {MASTER_KEY_SIZE + TAG_SIZE}, "
            f"got {len(wrap.wrapped)}"
        )

    eph_pub = deserialize_public_key(wrap.eph_pubkey)
    recipient_pub = recipient_priv.public_key()
    recipient_pub_bytes = serialize_public_key(recipient_pub)

    shared = recipient_priv.exchange(eph_pub)
    salt = wrap.eph_pubkey
    wrap_key = derive_wrap_key(shared, salt)

    aad = b"zss:wrap:v1|eph=" + wrap.eph_pubkey + b"|rcp=" + recipient_pub_bytes
    aead = ChaCha20Poly1305(wrap_key)
    try:
        master = aead.decrypt(wrap.wrap_nonce, wrap.wrapped, aad)
    except InvalidTag as e:
        zero_fill(bytearray(shared))
        zero_fill(bytearray(wrap_key))
        raise ZssCryptoError("master key unwrap failed (tag mismatch)") from e

    zero_fill(bytearray(shared))
    zero_fill(bytearray(wrap_key))
    return master


def _wipe_wrapped(wrap: WrappedMasterKey) -> None:
    if wrap is None:
        return
    if isinstance(wrap.eph_pubkey, bytes):
        pass
    if isinstance(wrap.wrapped, (bytes, bytearray)):
        wb = bytearray(wrap.wrapped) if isinstance(wrap.wrapped, bytes) else wrap.wrapped
        zero_fill(wb)



@dataclass
class DirectiveBlock:
    filename: str
    body: str
    open_line: int
    close_line: int
    open_offset: int
    close_offset: int


@dataclass
class ParsedSource:
    rewritten: str
    blocks: list[DirectiveBlock]


_DIRECTIVE_TOKEN_RE = re.compile(
    r"""^
    \#\s*<zss>\s*\{\s*           # '#<zss>{' with optional ws
    (write_to|closing!write)     # keyword
    \s*!\s*                       # '!' separator
    ([A-Za-z_][A-Za-z0-9_]*)     # identifier
    \.zspy                        # required suffix
    \s*\}?\s*$                    # optional closing brace, then EOL
    """,
    re.VERBOSE,
)


def _classify_comment(text: str) -> Optional[tuple[str, str]]:
    if not text.startswith("#"):
        return None
    m = _DIRECTIVE_TOKEN_RE.match(text)
    if not m:
        return None
    keyword, ident = m.group(1), m.group(2)
    filename = ident + ".zspy"
    if keyword == "write_to":
        return ("open", filename)
    elif keyword == "closing!write":
        return ("close", filename)
    return None


def _iter_comments(source: str):
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except tokenize.TokenError as e:
        raise ZssParseError(f"cannot tokenize source: {e}") from e
    except IndentationError as e:
        raise ZssParseError(f"indentation error: {e}") from e

    for tok in tokens:
        if tok.type == tokenize.COMMENT:
            yield tok


def parse_source_with_directives(source: str) -> ParsedSource:
    lines = source.splitlines(keepends=True)
    line_offsets = [0]
    pos = 0
    for ln in lines:
        pos += len(ln)
        line_offsets.append(pos)

    def row_col_to_offset(row: int, col: int) -> int:
        if row - 1 >= len(line_offsets):
            return len(source)
        return line_offsets[row - 1] + col

    stack: list[dict] = []
    blocks: list[DirectiveBlock] = []

    for tok in _iter_comments(source):
        classified = _classify_comment(tok.string)
        if classified is None:
            continue
        kind, filename = classified

        if kind == "open":
            if stack:
                prev = stack[-1]
                raise ZssParseError(
                    f"nested directive at line {tok.start[0]}: "
                    f"previous block '{prev['filename']}' opened at line "
                    f"{prev['open_line']} is still open"
                )
            stack.append({
                "filename": filename,
                "open_line": tok.start[0],
                "open_row": tok.start[0],
                "open_col": tok.start[1],
                "open_end_row": tok.end[0],
                "open_end_col": tok.end[1],
                "open_offset": row_col_to_offset(tok.start[0], tok.start[1]),
                "open_end_offset": row_col_to_offset(tok.end[0], tok.end[1]),
                "body_start_offset": row_col_to_offset(tok.end[0], tok.end[1]),
            })
        else:
            if not stack:
                raise ZssParseError(
                    f"closing directive at line {tok.start[0]} has no matching open"
                )
            top = stack[-1]
            if top["filename"] != filename:
                raise ZssParseError(
                    f"filename mismatch: open '{top['filename']}' at line "
                    f"{top['open_line']} vs close '{filename}' at line {tok.start[0]}"
                )
            close_offset = row_col_to_offset(tok.start[0], tok.start[1])
            close_end_offset = row_col_to_offset(tok.end[0], tok.end[1])
            body = source[top["body_start_offset"]:close_offset]
            blocks.append(DirectiveBlock(
                filename=filename,
                body=body,
                open_line=top["open_line"],
                close_line=tok.start[0],
                open_offset=top["open_offset"],
                close_offset=close_end_offset,
            ))
            stack.pop()

    if stack:
        top = stack[-1]
        raise ZssParseError(
            f"unclosed directive block '{top['filename']}' opened at line "
            f"{top['open_line']}"
        )

    if not blocks:
        return ParsedSource(rewritten=source, blocks=[])

    blocks.sort(key=lambda b: b.open_offset)

    for i in range(1, len(blocks)):
        if blocks[i].open_offset < blocks[i - 1].close_offset:
            raise ZssParseError(
                f"overlapping blocks: '{blocks[i-1].filename}' and "
                f"'{blocks[i].filename}'"
            )

    out_parts: list[str] = []
    cursor = 0
    for b in blocks:
        out_parts.append(source[cursor:b.open_offset])
        line_start = source.rfind("\n", 0, b.open_offset) + 1
        indent = source[line_start:b.open_offset]
        close_line_end = b.close_offset
        if close_line_end < len(source) and source[close_line_end] == "\n":
            close_line_end += 1
        elif close_line_end < len(source) - 1 and source[close_line_end:close_line_end+2] == "\r\n":
            close_line_end += 2
        out_parts.pop()
        out_parts.append(source[cursor:line_start])
        out_parts.append(indent + LOAD_STUB_TEMPLATE.format(filename=b.filename) + "\n")
        cursor = close_line_end
    out_parts.append(source[cursor:])
    rewritten = "".join(out_parts)

    return ParsedSource(rewritten=rewritten, blocks=blocks)


def validate_filename_strict(name: str) -> str:
    if not isinstance(name, str):
        raise ZssParseError(f"filename must be str, got {type(name).__name__}")
    if not FILENAME_RE.match(name):
        raise ZssParseError(
            f"bad filename {name!r}: must match {FILENAME_RE.pattern}. "
            "No paths, no '..' , no leading digits."
        )
    return name


def has_directives(source: str) -> bool:
    try:
        for tok in _iter_comments(source):
            if _classify_comment(tok.string) is not None:
                return True
    except ZssParseError:
        return False
    return False


def find_directive_filenames(source: str) -> list[str]:
    names: list[str] = []
    try:
        for tok in _iter_comments(source):
            classified = _classify_comment(tok.string)
            if classified and classified[0] == "open":
                names.append(classified[1])
    except ZssParseError:
        pass
    return names



ZSSPY_HEADER_MAGIC_SIZE = 8
ZSSPY_HEADER_VERSION_SIZE = 2
ZSSPY_HEADER_N_SIZE = 1
ZSSPY_HEADER_RESERVED_SIZE = 3
ZSSPY_HEADER_STATIC_PREFIX = (
    ZSSPY_HEADER_MAGIC_SIZE
    + ZSSPY_HEADER_VERSION_SIZE
    + ZSSPY_HEADER_N_SIZE
    + ZSSPY_HEADER_RESERVED_SIZE
)

ZSSPY_FILE_SALT_SIZE = 16


def _pack_header_prefix(n_layers: int) -> bytes:
    if not (MIN_N_LAYERS <= n_layers <= MAX_N_LAYERS):
        raise ZssFormatError(f"n_layers out of range: {n_layers}")
    return (
        ZSSPY_MAGIC
        + struct.pack("<H", ZSSPY_FORMAT_VERSION)
        + struct.pack("<B", n_layers)
        + b"\x00\x00\x00"
    )


def _unpack_header_prefix(buf: bytes) -> tuple[bytes, int, int, bytes]:
    if len(buf) < ZSSPY_HEADER_STATIC_PREFIX:
        raise ZssFormatError(
            f"truncated header: need {ZSSPY_HEADER_STATIC_PREFIX} bytes, got {len(buf)}"
        )
    magic = buf[:8]
    if magic != ZSSPY_MAGIC:
        raise ZssFormatError(
            f"bad magic: expected {ZSSPY_MAGIC!r}, got {magic!r}. "
            "This is not a .zspy file."
        )
    fmt_version = struct.unpack("<H", buf[8:10])[0]
    n_layers = struct.unpack("<B", buf[10:11])[0]
    reserved = buf[11:14]
    if reserved[0] not in (0, 1):
        raise ZssFormatError(
            f"unsupported reserved[0]={reserved[0]}. "
            "File may be from a newer ZSS version."
        )
    if reserved[1] != 0 or reserved[2] != 0:
        raise ZssFormatError(
            f"reserved bytes [1..2] non-zero: {reserved[1:]!r}. "
            "File may be from a newer ZSS version."
        )
    if fmt_version > ZSSPY_FORMAT_VERSION:
        raise ZssFormatError(
            f"file format version {fmt_version} is newer than supported "
            f"{ZSSPY_FORMAT_VERSION}. Update ZSS."
        )
    if fmt_version < ZSSPY_FORMAT_VERSION:
        raise ZssFormatError(
            f"file format version {fmt_version} is older than supported "
            f"{ZSSPY_FORMAT_VERSION}. No migration in beta; re-pack the file."
        )
    if not (MIN_N_LAYERS <= n_layers <= MAX_N_LAYERS):
        raise ZssFormatError(f"n_layers out of range in header: {n_layers}")
    return magic, fmt_version, n_layers, reserved


@dataclass
class ZsspyHeader:
    magic: bytes
    fmt_version: int
    n_layers: int
    eph_pubkey: bytes
    wrap_nonce: bytes
    wrapped_master: bytes
    wrap_tag: bytes
    layer_nonces: list[bytes]
    layer_tags: list[bytes]
    file_salt: bytes
    orig_sha256: bytes
    timestamp: int
    zss_version: str
    ciphertext: bytes


def build_zspy(
    plaintext: bytes,
    master: bytes,
    n_layers: int,
    recipient_pub: X25519PublicKey,
    *,
    timestamp: Optional[int] = None,
) -> bytes:
    if not isinstance(plaintext, (bytes, bytearray)):
        raise ZssFormatError("plaintext must be bytes")
    plaintext = bytes(plaintext)

    wrap = wrap_master_key(master, recipient_pub)
    if len(wrap.wrapped) != MASTER_KEY_SIZE + TAG_SIZE:
        raise ZssCryptoError("internal: wrapped has unexpected length")
    wrapped_master = wrap.wrapped[:MASTER_KEY_SIZE]
    wrap_tag = wrap.wrapped[MASTER_KEY_SIZE:]

    file_salt = _secure_random(ZSSPY_FILE_SALT_SIZE)

    layered = encrypt_layers(plaintext, master, n_layers, file_salt)

    orig_hash = sha256(plaintext)

    import time
    if timestamp is None:
        timestamp = int(time.time())
    if not (0 <= timestamp < 2**63):
        raise ZssFormatError(f"timestamp out of range: {timestamp}")

    zss_ver_bytes = ZSS_VERSION.encode("utf-8")
    if len(zss_ver_bytes) > 255:
        raise ZssFormatError("zss_version string too long")

    out = bytearray()
    out += _pack_header_prefix(n_layers)
    out += wrap.eph_pubkey
    out += wrap.wrap_nonce
    out += wrapped_master
    out += wrap_tag
    for nonce in layered.nonces:
        out += nonce
    for tag in layered.tags:
        out += tag
    out += file_salt
    out += orig_hash
    out += struct.pack("<Q", timestamp)
    out += struct.pack("<B", len(zss_ver_bytes))
    out += zss_ver_bytes
    out += struct.pack("<I", len(layered.ciphertext))
    out += layered.ciphertext

    return bytes(out)


def parse_zspy(data: bytes) -> ZsspyHeader:
    if not isinstance(data, (bytes, bytearray)):
        raise ZssFormatError("data must be bytes")
    data = bytes(data)

    pos = 0
    if len(data) < ZSSPY_HEADER_STATIC_PREFIX:
        raise ZssFormatError("file too short for header prefix")
    magic, fmt_version, n_layers, reserved = _unpack_header_prefix(
        data[:ZSSPY_HEADER_STATIC_PREFIX]
    )
    is_archive = (reserved[0] == 1)
    pos = ZSSPY_HEADER_STATIC_PREFIX

    fixed_crypto_size = (
        X25519_PUBKEY_SIZE + NONCE_SIZE + MASTER_KEY_SIZE + TAG_SIZE
    )
    if len(data) < pos + fixed_crypto_size:
        raise ZssFormatError("truncated: missing wrap fields")
    eph_pubkey = data[pos:pos + X25519_PUBKEY_SIZE]; pos += X25519_PUBKEY_SIZE
    wrap_nonce = data[pos:pos + NONCE_SIZE]; pos += NONCE_SIZE
    wrapped_master = data[pos:pos + MASTER_KEY_SIZE]; pos += MASTER_KEY_SIZE
    wrap_tag = data[pos:pos + TAG_SIZE]; pos += TAG_SIZE

    if is_archive:
        layer_nonces: list[bytes] = []
        layer_tags: list[bytes] = []
    else:
        nonces_size = NONCE_SIZE * n_layers
        tags_size = TAG_SIZE * n_layers
        if len(data) < pos + nonces_size + tags_size:
            raise ZssFormatError("truncated: missing layer nonces/tags")
        layer_nonces = [
            data[pos + i * NONCE_SIZE: pos + (i + 1) * NONCE_SIZE]
            for i in range(n_layers)
        ]
        pos += nonces_size
        layer_tags = [
            data[pos + i * TAG_SIZE: pos + (i + 1) * TAG_SIZE]
            for i in range(n_layers)
        ]
        pos += tags_size

    if len(data) < pos + ZSSPY_FILE_SALT_SIZE + 32 + 8 + 1:
        raise ZssFormatError("truncated: missing salt/hash/ts/verlen")
    file_salt = data[pos:pos + ZSSPY_FILE_SALT_SIZE]; pos += ZSSPY_FILE_SALT_SIZE
    orig_sha256 = data[pos:pos + 32]; pos += 32
    timestamp = struct.unpack("<Q", data[pos:pos + 8])[0]; pos += 8
    ver_len = data[pos]; pos += 1
    if len(data) < pos + ver_len + 4:
        raise ZssFormatError("truncated: missing version string or ct_len")
    zss_version = data[pos:pos + ver_len].decode("utf-8", errors="replace")
    pos += ver_len
    ct_len = struct.unpack("<I", data[pos:pos + 4])[0]; pos += 4
    if len(data) < pos + ct_len:
        raise ZssFormatError(
            f"truncated: ciphertext says {ct_len} bytes, only {len(data) - pos} left"
        )
    ciphertext = data[pos:pos + ct_len]; pos += ct_len

    return ZsspyHeader(
        magic=magic,
        fmt_version=fmt_version,
        n_layers=n_layers,
        eph_pubkey=eph_pubkey,
        wrap_nonce=wrap_nonce,
        wrapped_master=wrapped_master,
        wrap_tag=wrap_tag,
        layer_nonces=layer_nonces,
        layer_tags=layer_tags,
        file_salt=file_salt,
        orig_sha256=orig_sha256,
        timestamp=timestamp,
        zss_version=zss_version,
        ciphertext=ciphertext,
    )


def decrypt_zspy(header: ZsspyHeader, recipient_priv: X25519PrivateKey) -> bytes:
    wrap = WrappedMasterKey(
        eph_pubkey=header.eph_pubkey,
        wrap_nonce=header.wrap_nonce,
        wrapped=header.wrapped_master + header.wrap_tag,
    )
    try:
        master = unwrap_master_key(wrap, recipient_priv)
    except ZssCryptoError:
        raise

    try:
        blob = LayeredCiphertext(
            salt=header.file_salt,
            n_layers=header.n_layers,
            nonces=header.layer_nonces,
            tags=header.layer_tags,
            ciphertext=header.ciphertext,
        )
        plaintext = decrypt_layers(blob, master)
    finally:
        zero_fill(bytearray(master))

    actual = sha256(plaintext)
    if actual != header.orig_sha256:
        zero_fill(bytearray(plaintext))
        raise ZssCryptoError(
            "orig_sha256 mismatch after successful decryption — file is corrupt "
            "or implementation bug"
        )

    return plaintext


def zspy_public_info(header: ZsspyHeader) -> dict:
    import datetime
    try:
        ts_iso = datetime.datetime.fromtimestamp(
            header.timestamp, tz=datetime.timezone.utc
        ).isoformat() if header.timestamp > 0 else None
    except (OSError, OverflowError, ValueError):
        ts_iso = None
    return {
        "fmt_version": header.fmt_version,
        "n_layers": header.n_layers,
        "eph_pubkey": _b64e(header.eph_pubkey),
        "file_salt": _b64e(header.file_salt),
        "orig_sha256": _b64e(header.orig_sha256),
        "timestamp": header.timestamp,
        "timestamp_iso": ts_iso,
        "zss_version": header.zss_version,
        "ciphertext_size": len(header.ciphertext),
    }


def is_zspy_file(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            head = f.read(len(ZSSPY_MAGIC))
        return head == ZSSPY_MAGIC
    except OSError:
        return False



ZSON_SALT_SIZE = 16
ZSON_HEADER_FIXED = 8 + 2 + 1 + 3 + ZSON_SALT_SIZE + NONCE_SIZE + 4

ZSON_DEFAULT_SETTINGS = {
    "default_n_layers": DEFAULT_N_LAYERS,
    "verify_integrity": True,
    "format_version": ZSSPY_FORMAT_VERSION,
}


def _default_zson_payload(*, profile_name: Optional[str] = None) -> dict:
    import time
    now = int(time.time())
    return {
        "schema_version": ZSON_SCHEMA_VERSION,
        "created_at": now,
        "updated_at": now,
        "profile_name": profile_name,
        "settings": dict(ZSON_DEFAULT_SETTINGS),
        "secrets": {
            "hkdf_salt": _b64e(_secure_random(ZSON_SALT_SIZE)),
            "pepper": _b64e(bytes(_SEED_PEPPER)),
            "service_const": _b64e(_secure_random(16)),
        },
        "cache": {},
    }


def _zson_encrypt(payload: dict, salt: bytes, key: bytes) -> bytes:
    plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    nonce = _secure_random(NONCE_SIZE)
    aead = ChaCha20Poly1305(key)
    aad = b"zss:zson:v1|salt=" + salt
    ct = aead.encrypt(nonce, plaintext, aad)
    out = bytearray()
    out += ZSON_MAGIC
    out += struct.pack("<H", ZSON_SCHEMA_VERSION)
    out += b"\x00"
    out += b"\x00\x00\x00"
    out += salt
    out += nonce
    out += struct.pack("<I", len(ct))
    out += ct
    return bytes(out)


def _zson_decrypt(data: bytes, key_provider) -> tuple[dict, bytes]:
    if len(data) < ZSON_HEADER_FIXED:
        raise ZssConfigError(f".zson too short: {len(data)} < {ZSON_HEADER_FIXED}")
    if data[:8] != ZSON_MAGIC:
        raise ZssConfigError(
            f"bad .zson magic: {data[:8]!r}. This is not a ZSS state file."
        )
    schema_version = struct.unpack("<H", data[8:10])[0]
    if schema_version > ZSON_SCHEMA_VERSION:
        raise ZssConfigError(
            f".zson schema {schema_version} is newer than supported "
            f"{ZSON_SCHEMA_VERSION}. Update ZSS."
        )
    salt = data[14:14 + ZSON_SALT_SIZE]
    nonce = data[14 + ZSON_SALT_SIZE:14 + ZSON_SALT_SIZE + NONCE_SIZE]
    ct_len = struct.unpack("<I", data[14 + ZSON_SALT_SIZE + NONCE_SIZE:14 + ZSON_SALT_SIZE + NONCE_SIZE + 4])[0]
    ct_start = ZSON_HEADER_FIXED
    if len(data) < ct_start + ct_len:
        raise ZssConfigError(
            f".zson truncated: declared {ct_len} bytes payload, "
            f"only {len(data) - ct_start} available"
        )
    ct = data[ct_start:ct_start + ct_len]

    key = key_provider(salt)
    if len(key) != KEY_SIZE:
        raise ZssConfigError("internal: zson key wrong size")
    aead = ChaCha20Poly1305(key)
    aad = b"zss:zson:v1|salt=" + salt
    try:
        plaintext = aead.decrypt(nonce, ct, aad)
    except InvalidTag as e:
        raise ZssConfigError(
            ".zson decryption failed (tag mismatch). File is corrupt, was re-encrypted "
            "with a different key, or you're using the wrong private key."
        ) from e

    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ZssConfigError(f".zson payload is not valid JSON: {e}") from e

    if schema_version < ZSON_SCHEMA_VERSION:
        payload = _migrate_zson_payload(payload, schema_version)

    return payload, salt


def _migrate_zson_payload(payload: dict, from_version: int) -> dict:
    v = from_version
    while v < ZSON_SCHEMA_VERSION:
        migrator = _ZSON_MIGRATIONS.get(v)
        if migrator is None:
            raise ZssConfigError(f"no migration path from schema {v}")
        payload = migrator(payload)
        v += 1
    payload["schema_version"] = ZSON_SCHEMA_VERSION
    return payload


_ZSON_MIGRATIONS: dict[int, Any] = {}


def _validate_zson_payload(payload: dict) -> None:
    if not isinstance(payload, dict):
        raise ZssConfigError(f".zson payload is not a dict: {type(payload).__name__}")
    for key in ("schema_version", "created_at", "updated_at", "settings", "secrets", "cache"):
        if key not in payload:
            raise ZssConfigError(f".zson payload missing required key: {key}")
    if payload["schema_version"] != ZSON_SCHEMA_VERSION:
        raise ZssConfigError(
            f".zson payload schema_version mismatch: "
            f"{payload['schema_version']} != {ZSON_SCHEMA_VERSION}"
        )
    if not isinstance(payload["settings"], dict):
        raise ZssConfigError(".zson settings is not a dict")
    if not isinstance(payload["secrets"], dict):
        raise ZssConfigError(".zson secrets is not a dict")
    if not isinstance(payload["cache"], dict):
        raise ZssConfigError(".zson cache is not a dict")
    for k in ("hkdf_salt", "pepper", "service_const"):
        if k not in payload["secrets"]:
            raise ZssConfigError(f".zson secrets missing key: {k}")


def zson_exists(path: Optional[Path] = None) -> bool:
    if path is None:
        path = ZSON_PATH
    return Path(path).exists() and Path(path).is_file()


def load_zson(priv: X25519PrivateKey, path: Optional[Path] = None) -> dict:
    if path is None:
        path = ZSON_PATH
    if not zson_exists(path):
        raise ZssConfigError(
            f".zson not found at {path}. Run `zss init` first or set ZSS_HOME."
        )
    data = read_bytes(path)

    def key_provider(salt: bytes) -> bytes:
        return derive_zson_key(priv, salt)

    payload, salt = _zson_decrypt(data, key_provider)
    _validate_zson_payload(payload)
    return payload


def save_zson(payload: dict, priv: X25519PrivateKey, path: Optional[Path] = None) -> None:
    if path is None:
        path = ZSON_PATH
    _validate_zson_payload(payload)
    salt_b64 = payload["secrets"].get("hkdf_salt")
    if salt_b64:
        salt = _b64d(salt_b64)
        if len(salt) != ZSON_SALT_SIZE:
            raise ZssConfigError(
                f"hkdf_salt wrong size: {len(salt)} != {ZSON_SALT_SIZE}"
            )
    else:
        salt = _secure_random(ZSON_SALT_SIZE)
        payload["secrets"]["hkdf_salt"] = _b64e(salt)

    key = derive_zson_key(priv, salt)
    blob = _zson_encrypt(payload, salt, key)
    zero_fill(bytearray(key))
    atomic_write_bytes(path, blob, mode=0o600)


def init_zson(priv: X25519PrivateKey, path: Optional[Path] = None, profile_name: Optional[str] = None) -> dict:
    if path is None:
        path = ZSON_PATH
    payload = _default_zson_payload(profile_name=profile_name)
    save_zson(payload, priv, path)
    _wipe_seeds()
    return payload


def update_zson_cache(
    payload: dict,
    *,
    dir_path: Path,
    zspy_files: Optional[list[dict]] = None,
    py_with_directives: Optional[list[str]] = None,
) -> dict:
    import copy
    new_payload = copy.deepcopy(payload)
    cache = new_payload.setdefault("cache", {})
    dir_key = str(Path(dir_path).resolve())
    entry = cache.setdefault(dir_key, {"zspy": [], "py_with_directives": []})
    if zspy_files is not None:
        entry["zspy"] = zspy_files
    if py_with_directives is not None:
        entry["py_with_directives"] = py_with_directives
    import time
    new_payload["updated_at"] = int(time.time())
    return new_payload


def get_zson_setting(payload: dict, key: str, default: Any = None) -> Any:
    return payload.get("settings", {}).get(key, default)



def _resolve_zspy_path(caller_file: str, name: str) -> Path:
    validate_filename_strict(name)
    caller_path = Path(caller_file).resolve()
    if caller_path.exists():
        base = caller_path.parent
    else:
        base = Path.cwd()
    return base / name


def _exec_decrypted(plaintext: str, namespace: dict, *, zspy_path: Path) -> None:
    code = compile(plaintext, str(zspy_path), "exec")
    namespace.setdefault("__file__", str(zspy_path))
    exec(code, namespace)


def load(name: str, *, _caller_frame_depth: int = 1) -> Any:
    import inspect
    frame = inspect.currentframe()
    try:
        for _ in range(_caller_frame_depth):
            if frame is None:
                raise ZssError("cannot determine caller frame for load()")
            frame = frame.f_back
        if frame is None:
            raise ZssError("cannot determine caller frame for load()")
        caller_file = frame.f_globals.get("__file__", "")
        caller_globals = frame.f_globals
    finally:
        del frame

    if not caller_file:
        raise ZssError("load() called without __file__ in caller globals")

    zspy_path = _resolve_zspy_path(caller_file, name)
    if not zspy_path.exists():
        raise ZssFormatError(f".zspy not found: {zspy_path}")

    data = read_bytes(zspy_path)
    header = parse_zspy(data)

    try:
        priv = load_private_key()
    except ZssKeyError:
        raise

    try:
        plaintext_bytes = decrypt_zspy(header, priv)
    finally:
        pass

    try:
        plaintext = plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        zero_fill(bytearray(plaintext_bytes))
        raise ZssFormatError(f"decrypted source is not valid UTF-8: {e}") from e

    try:
        _exec_decrypted(plaintext, caller_globals, zspy_path=zspy_path)
    finally:
        zero_fill(bytearray(plaintext_bytes))



def _print(msg: str = "") -> None:
    sys.stdout.write(msg + "\n")


def _eprint(msg: str = "") -> None:
    sys.stderr.write(msg + "\n")


def _zss_home_env_override() -> None:
    global ZSS_HOME, KEYS_DIR, ZSON_PATH, PRIVATE_KEY_PATH, PUBLIC_KEY_PATH
    env = os.environ.get("ZSS_HOME")
    if not env:
        return
    ZSS_HOME = Path(env).expanduser()
    KEYS_DIR = ZSS_HOME / "keys"
    ZSON_PATH = ZSS_HOME / "zss.zson"
    PRIVATE_KEY_PATH = KEYS_DIR / "master.x25519"
    PUBLIC_KEY_PATH = KEYS_DIR / "master.pub"


def cmd_init(args: argparse.Namespace) -> int:
    _zss_home_env_override()
    _ensure_dir(ZSS_HOME, mode=0o700)
    _ensure_dir(KEYS_DIR, mode=0o700)

    if PRIVATE_KEY_PATH.exists() and not args.force:
        _eprint(f"error: private key already exists at {PRIVATE_KEY_PATH}")
        _eprint("use --force to overwrite (your existing .zspy files will become unreadable).")
        return 1

    if PRIVATE_KEY_PATH.exists() and args.force:
        safe_delete(PRIVATE_KEY_PATH)
        if PUBLIC_KEY_PATH.exists():
            PUBLIC_KEY_PATH.unlink(missing_ok=True)
        if ZSON_PATH.exists():
            safe_delete(ZSON_PATH)

    priv, pub = generate_keypair()
    save_private_key(priv, PRIVATE_KEY_PATH)
    save_public_key(pub, PUBLIC_KEY_PATH)

    payload = init_zson(priv, ZSON_PATH, profile_name=args.profile)

    _print(f"ZSS initialized.")
    _print(f"  version:        {ZSS_VERSION}")
    _print(f"  private key:    {PRIVATE_KEY_PATH} (mode 0600)")
    _print(f"  public key:     {PUBLIC_KEY_PATH}")
    _print(f"  state file:     {ZSON_PATH}")
    _print(f"  default layers: {payload['settings']['default_n_layers']}")
    _print(f"")
    _print(f"Next steps:")
    _print(f"  1. Add #<zss>{{write_to!name.zspy ... #<zss>{{closing!write!name.zspy")
    _print(f"     blocks to your .py files.")
    _print(f"  2. Run `zss pack yourfile.py` to encrypt blocks into .zspy files.")
    _print(f"  3. Run `zss run yourfile.py` to execute the packed program.")
    return 0


def cmd_pack(args: argparse.Namespace) -> int:
    _zss_home_env_override()
    py_path = Path(args.file).expanduser().resolve()
    if not py_path.is_file():
        _eprint(f"error: source file not found: {py_path}")
        return 1
    if py_path.suffix != ".py":
        _eprint(f"error: expected a .py file, got {py_path.name}")
        return 1

    try:
        source = py_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        _eprint(f"error: source is not valid UTF-8: {e}")
        return 1

    try:
        parsed = parse_source_with_directives(source)
    except ZssParseError as e:
        _eprint(f"error: parse failure in {py_path}: {e}")
        return 1
    except ZssError as e:
        _eprint(f"error: {e}")
        return 1

    if not parsed.blocks:
        _eprint(f"error: no #<zss>{{...}} directives found in {py_path}")
        _eprint("nothing to pack. Add directives first.")
        return 1

    seen: set[str] = set()
    for b in parsed.blocks:
        if b.filename in seen:
            _eprint(f"error: duplicate directive filename '{b.filename}' in {py_path}")
            return 1
        seen.add(b.filename)

    try:
        priv = load_private_key(PRIVATE_KEY_PATH)
    except ZssKeyError as e:
        _eprint(f"error: {e}")
        return 1
    pub = priv.public_key()

    n_layers = args.layers
    if n_layers is None:
        try:
            payload = load_zson(priv, ZSON_PATH)
            n_layers = int(get_zson_setting(payload, "default_n_layers", DEFAULT_N_LAYERS))
        except ZssConfigError:
            n_layers = DEFAULT_N_LAYERS

    if not (MIN_N_LAYERS <= n_layers <= MAX_N_LAYERS):
        _eprint(f"error: --layers must be in [{MIN_N_LAYERS}..{MAX_N_LAYERS}], got {n_layers}")
        return 1

    out_dir = py_path.parent
    written: list[Path] = []
    for block in parsed.blocks:
        body = block.body
        master = _secure_random(MASTER_KEY_SIZE)
        try:
            blob = build_zspy(body.encode("utf-8"), master, n_layers, pub)
        finally:
            zero_fill(bytearray(master))
        out_path = out_dir / block.filename
        atomic_write_bytes(out_path, blob, mode=0o644)
        written.append(out_path)

    bak_path = py_path.with_suffix(py_path.suffix + ".bak")
    if bak_path.exists() and not args.no_clobber:
        pass
    elif bak_path.exists() and args.no_clobber:
        _eprint(f"error: backup file exists: {bak_path} (use without --no-clobber to overwrite)")
        return 1

    try:
        atomic_write_text(bak_path, source, mode=0o600)
    except OSError as e:
        _eprint(f"error: cannot write backup {bak_path}: {e}")
        return 1

    if args.in_place:
        target = py_path
    else:
        target = py_path.with_suffix(".packed.py")

    try:
        atomic_write_text(target, parsed.rewritten, mode=0o644)
    except OSError as e:
        _eprint(f"error: cannot write packed source {target}: {e}")
        return 1

    _print(f"packed {py_path.name}:")
    for w in written:
        _print(f"  + {w.name} ({w.stat().st_size} bytes, {n_layers} layers)")
    _print(f"  -> {target.name} (rewritten with load() stubs)")
    _print(f"  backup: {bak_path.name}")
    if not args.in_place:
        _print(f"")
        _print(f"  Run with:  zss run {target.name}")
        _print(f"  Or replace the original manually if you prefer.")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    _zss_home_env_override()
    target = Path(args.file).expanduser().resolve()
    if not target.exists():
        _eprint(f"error: file not found: {target}")
        return 1

    if target.suffix == ".zspy":
        return _run_zspy_directly(target, args)

    if target.suffix == ".py":
        return _run_packed_py(target, args)

    _eprint(f"error: expected .py or .zspy, got {target.suffix}")
    return 1


def _run_zspy_directly(zspy_path: Path, args: argparse.Namespace) -> int:
    data = read_bytes(zspy_path)
    try:
        header = parse_zspy(data)
    except ZssFormatError as e:
        _eprint(f"error: {e}")
        return 1
    try:
        priv = load_private_key(PRIVATE_KEY_PATH)
    except ZssKeyError as e:
        _eprint(f"error: {e}")
        return 1
    try:
        plaintext_bytes = decrypt_zspy(header, priv)
    except ZssCryptoError as e:
        _eprint(f"error: decryption failed: {e}")
        return 1
    except ZssFormatError as e:
        _eprint(f"error: {e}")
        return 1

    try:
        plaintext = plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        zero_fill(bytearray(plaintext_bytes))
        _eprint(f"error: decrypted source is not valid UTF-8: {e}")
        return 1

    namespace: dict = {"__name__": "__main__", "__file__": str(zspy_path)}
    sys.argv = [str(zspy_path)] + list(args.arg or [])
    try:
        _exec_decrypted(plaintext, namespace, zspy_path=zspy_path)
    except SystemExit as e:
        zero_fill(bytearray(plaintext_bytes))
        return int(e.code) if e.code is not None else 0
    except Exception as e:
        zero_fill(bytearray(plaintext_bytes))
        if args.debug:
            raise
        _eprint(f"error: runtime exception in decrypted code: {type(e).__name__}: {e}")
        return 1
    finally:
        zero_fill(bytearray(plaintext_bytes))
    return 0


def _run_packed_py(py_path: Path, args: argparse.Namespace) -> int:
    source = py_path.read_text(encoding="utf-8")
    namespace: dict = {
        "__name__": "__main__",
        "__file__": str(py_path),
        "__builtins__": __builtins__,
    }
    sys.argv = [str(py_path)] + list(args.arg or [])

    script_dir = str(py_path.parent)
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

    current_module = sys.modules[__name__]
    saved_zss = sys.modules.get("zss")
    sys.modules["zss"] = current_module

    try:
        code = compile(source, str(py_path), "exec")
        exec(code, namespace)
    except SystemExit as e:
        return int(e.code) if e.code is not None else 0
    except ZssError as e:
        if args.debug:
            raise
        _eprint(f"error: {e}")
        return 1
    except Exception as e:
        if args.debug:
            raise
        _eprint(f"error: runtime exception: {type(e).__name__}: {e}")
        return 1
    finally:
        if saved_zss is not None:
            sys.modules["zss"] = saved_zss
        elif sys.modules.get("zss") is current_module:
            del sys.modules["zss"]
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    _zss_home_env_override()
    scan_dir = Path(args.dir).expanduser().resolve() if args.dir else Path.cwd()
    if not scan_dir.is_dir():
        _eprint(f"error: not a directory: {scan_dir}")
        return 1

    zspy_entries: list[dict] = []
    py_entries: list[dict] = []

    try:
        for entry in sorted(scan_dir.iterdir()):
            if entry.is_file() and entry.suffix == ".zspy":
                if is_zspy_file(entry):
                    try:
                        data = read_bytes(entry)
                        header = parse_zspy(data)
                        info = zspy_public_info(header)
                        info["name"] = entry.name
                        zspy_entries.append(info)
                    except ZssFormatError as e:
                        zspy_entries.append({"name": entry.name, "error": str(e)})
            elif entry.is_file() and entry.suffix == ".py":
                try:
                    src = entry.read_text(encoding="utf-8")
                    if has_directives(src):
                        names = find_directive_filenames(src)
                        py_entries.append({"name": entry.name, "directives": names})
                except UnicodeDecodeError:
                    pass
    except OSError as e:
        _eprint(f"error: cannot scan {scan_dir}: {e}")
        return 1

    zson_payload: Optional[dict] = None
    try:
        priv = load_private_key(PRIVATE_KEY_PATH)
        zson_payload = load_zson(priv, ZSON_PATH)
    except (ZssKeyError, ZssConfigError):
        pass

    if args.json:
        out = {
            "dir": str(scan_dir),
            "zspy": zspy_entries,
            "py_with_directives": py_entries,
            "zson_present": zson_payload is not None,
        }
        if zson_payload:
            out["zson_settings"] = zson_payload.get("settings", {})
        _print(json.dumps(out, indent=2, sort_keys=True))
        return 0

    _print(f"ZSS scan: {scan_dir}")
    _print(f"")
    if zspy_entries:
        _print(f"  .zspy files ({len(zspy_entries)}):")
        for e in zspy_entries:
            if "error" in e:
                _print(f"    {e['name']}: ERROR: {e['error']}")
            else:
                _print(
                    f"    {e['name']}: N={e['n_layers']} "
                    f"ct={e['ciphertext_size']}B "
                    f"ts={e.get('timestamp_iso', '?')} "
                    f"zss={e['zss_version']}"
                )
    else:
        _print(f"  .zspy files: none")
    _print(f"")
    if py_entries:
        _print(f"  .py with directives ({len(py_entries)}):")
        for e in py_entries:
            _print(f"    {e['name']}: blocks -> {', '.join(e['directives'])}")
    else:
        _print(f"  .py with directives: none")
    _print(f"")
    if zson_payload:
        _print(f"  .zson: {ZSON_PATH}")
        _print(f"    schema: {zson_payload['schema_version']}")
        _print(f"    created: {zson_payload.get('created_at')}")
        _print(f"    default_n_layers: {zson_payload['settings']['default_n_layers']}")
    else:
        _print(f"  .zson: not initialized (run `zss init`)")
    return 0


def cmd_test(args: argparse.Namespace) -> int:
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=args.verbose, stream=sys.stdout)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="zss",
        description="ZSS — Zero State Snapshot. Layered encrypted Python runtime.",
    )
    p.add_argument("--version", action="version", version=f"zss {ZSS_VERSION}")
    p.add_argument("--debug", action="store_true", help="show stack traces on errors")
    sub = p.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="generate keypair and .zson")
    p_init.add_argument("--force", action="store_true", help="overwrite existing keys")
    p_init.add_argument("--profile", default=None, help="optional profile name")
    p_init.set_defaults(func=cmd_init)

    p_pack = sub.add_parser("pack", help="pack .py with directives into .zspy files")
    p_pack.add_argument("file", help="source .py path")
    p_pack.add_argument("--layers", type=int, default=None,
                        help=f"number of AEAD layers (default: from .zson, "
                             f"fallback {DEFAULT_N_LAYERS})")
    p_pack.add_argument("--in-place", action="store_true",
                        help="overwrite the source .py instead of writing .packed.py")
    p_pack.add_argument("--no-clobber", action="store_true",
                        help="error if .py.bak backup already exists")
    p_pack.set_defaults(func=cmd_pack)

    p_run = sub.add_parser("run", help="run a .py with stubs or a .zspy directly")
    p_run.add_argument("file", help="path to .py or .zspy")
    p_run.add_argument("arg", nargs=argparse.REMAINDER,
                       help="arguments passed to the script (use -- first if needed)")
    p_run.set_defaults(func=cmd_run)

    p_list = sub.add_parser("list", help="scan current directory for .zspy and .py")
    p_list.add_argument("--dir", default=None, help="directory to scan (default: cwd)")
    p_list.add_argument("--json", action="store_true", help="machine-readable output")
    p_list.set_defaults(func=cmd_list)

    p_test = sub.add_parser("test", help="run embedded unit tests")
    p_test.add_argument("-v", "--verbose", action="count", default=1,
                        help="verbosity (repeat for more)")
    p_test.set_defaults(func=cmd_test)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    debug = bool(getattr(args, "debug", False))
    try:
        return args.func(args)
    except ZssError as e:
        if debug:
            raise
        _eprint(f"error: {e}")
        return 1
    except KeyboardInterrupt:
        _eprint("interrupted")
        return 130
    except SystemExit:
        raise
    except Exception as e:
        if debug:
            raise
        _eprint(f"internal error: {type(e).__name__}: {e}")
        return 2



import shutil
import tempfile
import time
from typing import Callable


class _ZssHomeFixture:

    def __init__(self):
        self.tmpdir: Optional[Path] = None
        self._saved_globals: dict = {}
        self._module = None

    def __enter__(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="zss-test-"))
        self._module = sys.modules[__name__]
        self._saved_globals = {
            "ZSS_HOME": getattr(self._module, "ZSS_HOME"),
            "KEYS_DIR": getattr(self._module, "KEYS_DIR"),
            "ZSON_PATH": getattr(self._module, "ZSON_PATH"),
            "PRIVATE_KEY_PATH": getattr(self._module, "PRIVATE_KEY_PATH"),
            "PUBLIC_KEY_PATH": getattr(self._module, "PUBLIC_KEY_PATH"),
        }
        setattr(self._module, "ZSS_HOME", self.tmpdir)
        setattr(self._module, "KEYS_DIR", self.tmpdir / "keys")
        setattr(self._module, "ZSON_PATH", self.tmpdir / "zss.zson")
        setattr(self._module, "PRIVATE_KEY_PATH", self.tmpdir / "keys" / "master.x25519")
        setattr(self._module, "PUBLIC_KEY_PATH", self.tmpdir / "keys" / "master.pub")
        os.environ["ZSS_HOME"] = str(self.tmpdir)
        _ensure_dir(self.tmpdir / "keys", mode=0o700)
        if "zss" not in sys.modules or sys.modules.get("zss") is not self._module:
            self._saved_zss_module = sys.modules.get("zss")
            sys.modules["zss"] = self._module
        else:
            self._saved_zss_module = None
        return self

    def __exit__(self, *exc):
        if self._module is not None:
            for k, v in self._saved_globals.items():
                setattr(self._module, k, v)
        if self._saved_zss_module is not None:
            sys.modules["zss"] = self._saved_zss_module
        elif "zss" in sys.modules and sys.modules["zss"] is self._module:
            del sys.modules["zss"]
        os.environ.pop("ZSS_HOME", None)
        if self.tmpdir and self.tmpdir.exists():
            shutil.rmtree(self.tmpdir, ignore_errors=True)
        return False


def _with_temp_zss_home(func: Callable) -> Callable:
    def wrapper(self, *args, **kwargs):
        with _ZssHomeFixture():
            return func(self, *args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper



class TestParser(unittest.TestCase):

    def test_basic_single_block(self):
        src = (
            "import os\n"
            "#<zss>{write_to!secret.zspy\n"
            "SECRET = 'hello'\n"
            "#<zss>{closing!write!secret.zspy\n"
            "print(SECRET)\n"
        )
        result = parse_source_with_directives(src)
        self.assertEqual(len(result.blocks), 1)
        self.assertEqual(result.blocks[0].filename, "secret.zspy")
        self.assertIn("SECRET = 'hello'", result.blocks[0].body)
        self.assertIn('from zss import load; load("secret.zspy")', result.rewritten)
        self.assertIn("print(SECRET)", result.rewritten)
        self.assertNotIn("SECRET = 'hello'", result.rewritten)

    def test_multiple_blocks_in_one_file(self):
        src = (
            "#<zss>{write_to!a.zspy\n"
            "A = 1\n"
            "#<zss>{closing!write!a.zspy\n"
            "#<zss>{write_to!b.zspy\n"
            "B = 2\n"
            "#<zss>{closing!write!b.zspy\n"
        )
        result = parse_source_with_directives(src)
        self.assertEqual(len(result.blocks), 2)
        self.assertEqual(result.blocks[0].filename, "a.zspy")
        self.assertEqual(result.blocks[1].filename, "b.zspy")
        self.assertIn("A = 1", result.blocks[0].body)
        self.assertIn("B = 2", result.blocks[1].body)

    def test_directive_inside_string_is_ignored(self):
        src = (
            "s = \"#<zss>{write_to!fake.zspy\\n\"\n"
            "#<zss>{write_to!real.zspy\n"
            "X = 1\n"
            "#<zss>{closing!write!real.zspy\n"
        )
        result = parse_source_with_directives(src)
        self.assertEqual(len(result.blocks), 1)
        self.assertEqual(result.blocks[0].filename, "real.zspy")

    def test_directive_inside_comment_is_not_directive(self):
        src = (
            "# this is a note: #<zss>{write_to!nope.zspy}\n"
            "#<zss>{write_to!real.zspy\n"
            "X = 1\n"
            "#<zss>{closing!write!real.zspy\n"
        )
        result = parse_source_with_directives(src)
        self.assertEqual(len(result.blocks), 1)
        self.assertEqual(result.blocks[0].filename, "real.zspy")

    def test_nested_blocks_are_error(self):
        src = (
            "#<zss>{write_to!outer.zspy\n"
            "X = 1\n"
            "#<zss>{write_to!inner.zspy\n"
            "Y = 2\n"
            "#<zss>{closing!write!inner.zspy\n"
            "#<zss>{closing!write!outer.zspy\n"
        )
        with self.assertRaises(ZssParseError) as ctx:
            parse_source_with_directives(src)
        self.assertIn("nested", str(ctx.exception).lower())

    def test_unclosed_block_is_error(self):
        src = (
            "#<zss>{write_to!secret.zspy\n"
            "X = 1\n"
        )
        with self.assertRaises(ZssParseError) as ctx:
            parse_source_with_directives(src)
        self.assertIn("unclosed", str(ctx.exception).lower())

    def test_close_without_open_is_error(self):
        src = (
            "X = 1\n"
            "#<zss>{closing!write!secret.zspy\n"
        )
        with self.assertRaises(ZssParseError) as ctx:
            parse_source_with_directives(src)
        self.assertIn("no matching open", str(ctx.exception).lower())

    def test_filename_mismatch_is_error(self):
        src = (
            "#<zss>{write_to!a.zspy\n"
            "X = 1\n"
            "#<zss>{closing!write!b.zspy\n"
        )
        with self.assertRaises(ZssParseError) as ctx:
            parse_source_with_directives(src)
        self.assertIn("mismatch", str(ctx.exception).lower())

    def test_empty_block_is_valid(self):
        src = (
            "#<zss>{write_to!empty.zspy\n"
            "#<zss>{closing!write!empty.zspy\n"
        )
        result = parse_source_with_directives(src)
        self.assertEqual(len(result.blocks), 1)
        self.assertEqual(result.blocks[0].body.strip(), "")

    def test_extra_whitespace_around_directive(self):
        src = (
            "#<zss>{  write_to!  spaced.zspy  }\n"
            "X = 1\n"
            "#<zss>{  closing!write!  spaced.zspy  }\n"
        )
        result = parse_source_with_directives(src)
        self.assertEqual(len(result.blocks), 1)
        self.assertEqual(result.blocks[0].filename, "spaced.zspy")

    def test_bad_filename_rejected(self):
        src = (
            "#<zss>{write_to!../escape.zspy\n"
            "X = 1\n"
            "#<zss>{closing!write!../escape.zspy\n"
        )
        result = parse_source_with_directives(src)
        self.assertEqual(len(result.blocks), 0)

    def test_has_directives_helper(self):
        self.assertFalse(has_directives("x = 1\n"))
        self.assertTrue(has_directives("#<zss>{write_to!a.zspy\n#<zss>{closing!write!a.zspy\n"))

    def test_find_directive_filenames_helper(self):
        src = (
            "#<zss>{write_to!a.zspy\n"
            "X\n"
            "#<zss>{closing!write!a.zspy\n"
            "#<zss>{write_to!b.zspy\n"
            "Y\n"
            "#<zss>{closing!write!b.zspy\n"
        )
        names = find_directive_filenames(src)
        self.assertEqual(names, ["a.zspy", "b.zspy"])

    def test_tokenization_failure_is_parse_error(self):
        src = 'x = """unclosed\n#<zss>{write_to!a.zspy\n'
        with self.assertRaises(ZssParseError):
            parse_source_with_directives(src)

    def test_body_preserves_inner_content_verbatim(self):
        body = (
            "\n"
            "def f():\n"
            "    return [\n"
            "        1,  # not a directive\n"
            "        2,\n"
            "    ]\n"
            "\n"
            "class C:\n"
            "    pass\n"
        )
        src = f"#<zss>{{write_to!x.zspy{body}#<zss>{{closing!write!x.zspy\n"
        result = parse_source_with_directives(src)
        self.assertEqual(result.blocks[0].body, body)



class TestCrypto(unittest.TestCase):

    def test_hkdf_deterministic(self):
        m = b"master-key-32-bytes-xxxxxxxxxxx"
        salt = b"salt16bytesxxxxx"
        k1 = hkdf_derive(m, salt, b"info1")
        k2 = hkdf_derive(m, salt, b"info1")
        self.assertEqual(k1, k2)
        self.assertEqual(len(k1), KEY_SIZE)
        k3 = hkdf_derive(m, salt, b"info2")
        self.assertNotEqual(k1, k3)

    def test_hkdf_different_masters_different_keys(self):
        salt = b"salt16bytesxxxxx"
        k1 = hkdf_derive(b"a" * 32, salt, b"info")
        k2 = hkdf_derive(b"b" * 32, salt, b"info")
        self.assertNotEqual(k1, k2)

    def test_aead_round_trip(self):
        key = _secure_random(KEY_SIZE)
        nonce, ct = aead_encrypt(key, b"hello world", b"aad")
        self.assertEqual(len(nonce), NONCE_SIZE)
        pt = aead_decrypt(key, nonce, ct, b"aad")
        self.assertEqual(pt, b"hello world")

    def test_aead_wrong_aad_fails(self):
        key = _secure_random(KEY_SIZE)
        nonce, ct = aead_encrypt(key, b"hello", b"aad1")
        with self.assertRaises(ZssCryptoError):
            aead_decrypt(key, nonce, ct, b"aad2")

    def test_aead_tampered_ciphertext_fails(self):
        key = _secure_random(KEY_SIZE)
        nonce, ct = aead_encrypt(key, b"hello", b"")
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        with self.assertRaises(ZssCryptoError):
            aead_decrypt(key, nonce, bytes(tampered), b"")

    def test_layer_keys_independence(self):
        master = _secure_random(MASTER_KEY_SIZE)
        salt = b"salt16bytesxxxxx"
        keys = derive_layer_keys(master, 5, salt)
        self.assertEqual(len(keys), 5)
        self.assertEqual(len(set(keys)), 5)
        keys2 = derive_layer_keys(master, 5, salt)
        self.assertEqual(keys, keys2)

    def test_encrypt_decrypt_layers_round_trip_n1(self):
        self._round_trip_layers(1)

    def test_encrypt_decrypt_layers_round_trip_n5(self):
        self._round_trip_layers(5)

    def test_encrypt_decrypt_layers_round_trip_n40(self):
        self._round_trip_layers(40)

    def _round_trip_layers(self, n: int):
        master = _secure_random(MASTER_KEY_SIZE)
        salt = _secure_random(16)
        plaintext = b"the quick brown fox jumps over the lazy dog " * 10
        blob = encrypt_layers(plaintext, master, n, salt)
        self.assertEqual(blob.n_layers, n)
        self.assertEqual(len(blob.nonces), n)
        self.assertEqual(len(blob.tags), n)
        recovered = decrypt_layers(blob, master)
        self.assertEqual(recovered, plaintext)

    def test_decrypt_with_wrong_master_fails(self):
        master = _secure_random(MASTER_KEY_SIZE)
        wrong = _secure_random(MASTER_KEY_SIZE)
        salt = _secure_random(16)
        blob = encrypt_layers(b"secret", master, 5, salt)
        with self.assertRaises(ZssCryptoError):
            decrypt_layers(blob, wrong)

    def test_decrypt_tampered_layer_tag_fails(self):
        master = _secure_random(MASTER_KEY_SIZE)
        salt = _secure_random(16)
        blob = encrypt_layers(b"secret", master, 5, salt)
        tampered_tags = list(blob.tags)
        t = bytearray(tampered_tags[-1])
        t[0] ^= 0xFF
        tampered_tags[-1] = bytes(t)
        blob2 = LayeredCiphertext(
            salt=blob.salt,
            n_layers=blob.n_layers,
            nonces=blob.nonces,
            tags=tampered_tags,
            ciphertext=blob.ciphertext,
        )
        with self.assertRaises(ZssCryptoError):
            decrypt_layers(blob2, master)

    def test_decrypt_tampered_ciphertext_fails(self):
        master = _secure_random(MASTER_KEY_SIZE)
        salt = _secure_random(16)
        blob = encrypt_layers(b"secret", master, 5, salt)
        tampered_ct = bytearray(blob.ciphertext)
        if len(tampered_ct) > 0:
            tampered_ct[0] ^= 0xFF
        blob2 = LayeredCiphertext(
            salt=blob.salt,
            n_layers=blob.n_layers,
            nonces=blob.nonces,
            tags=blob.tags,
            ciphertext=bytes(tampered_ct),
        )
        with self.assertRaises(ZssCryptoError):
            decrypt_layers(blob2, master)

    def test_wrap_unwrap_round_trip(self):
        priv, pub = generate_keypair()
        master = _secure_random(MASTER_KEY_SIZE)
        wrap = wrap_master_key(master, pub)
        recovered = unwrap_master_key(wrap, priv)
        self.assertEqual(recovered, master)

    def test_wrap_with_wrong_private_key_fails(self):
        priv1, pub1 = generate_keypair()
        priv2, pub2 = generate_keypair()
        master = _secure_random(MASTER_KEY_SIZE)
        wrap = wrap_master_key(master, pub1)
        with self.assertRaises(ZssCryptoError):
            unwrap_master_key(wrap, priv2)

    def test_wrap_tampered_ephemeral_pubkey_fails(self):
        priv, pub = generate_keypair()
        master = _secure_random(MASTER_KEY_SIZE)
        wrap = wrap_master_key(master, pub)
        bad = bytearray(wrap.eph_pubkey)
        bad[0] ^= 0xFF
        tampered = WrappedMasterKey(
            eph_pubkey=bytes(bad),
            wrap_nonce=wrap.wrap_nonce,
            wrapped=wrap.wrapped,
        )
        with self.assertRaises((ZssCryptoError, Exception)):
            unwrap_master_key(tampered, priv)

    def test_n_layers_out_of_range(self):
        master = _secure_random(MASTER_KEY_SIZE)
        salt = _secure_random(16)
        with self.assertRaises(ZssCryptoError):
            encrypt_layers(b"x", master, 0, salt)
        with self.assertRaises(ZssCryptoError):
            encrypt_layers(b"x", master, 256, salt)



class TestZspyFormat(unittest.TestCase):

    def _build(self, plaintext: bytes = b"print('hello')\n", n: int = 5) -> tuple[bytes, X25519PrivateKey, bytes]:
        priv, pub = generate_keypair()
        master = _secure_random(MASTER_KEY_SIZE)
        blob = build_zspy(plaintext, master, n, pub, timestamp=1700000000)
        zero_fill(bytearray(master))
        return blob, priv, plaintext

    def test_build_parse_round_trip(self):
        blob, priv, plaintext = self._build()
        header = parse_zspy(blob)
        self.assertEqual(header.fmt_version, ZSSPY_FORMAT_VERSION)
        self.assertEqual(header.n_layers, 5)
        self.assertEqual(len(header.layer_nonces), 5)
        self.assertEqual(len(header.layer_tags), 5)
        self.assertEqual(len(header.eph_pubkey), 32)
        self.assertEqual(header.timestamp, 1700000000)
        recovered = decrypt_zspy(header, priv)
        self.assertEqual(recovered, plaintext)

    def test_round_trip_with_large_plaintext(self):
        plaintext = b"x = " + repr(list(range(1000))).encode("ascii") + b"\n"
        blob, priv, _ = self._build(plaintext=plaintext, n=10)
        header = parse_zspy(blob)
        recovered = decrypt_zspy(header, priv)
        self.assertEqual(recovered, plaintext)

    def test_bad_magic_rejected(self):
        blob, _, _ = self._build()
        bad = bytearray(blob)
        bad[0] = ord("X")
        with self.assertRaises(ZssFormatError) as ctx:
            parse_zspy(bytes(bad))
        self.assertIn("not a .zspy", str(ctx.exception))

    def test_future_version_rejected(self):
        blob, _, _ = self._build()
        bad = bytearray(blob)
        bad[8] = 99
        bad[9] = 0
        with self.assertRaises(ZssFormatError) as ctx:
            parse_zspy(bytes(bad))
        self.assertIn("newer", str(ctx.exception).lower())

    def test_truncated_header_rejected(self):
        blob, _, _ = self._build()
        with self.assertRaises(ZssFormatError):
            parse_zspy(blob[:5])

    def test_tampered_ciphertext_fails_decryption(self):
        blob, priv, _ = self._build()
        header = parse_zspy(blob)
        bad = bytearray(blob)
        bad_ct = bytearray(header.ciphertext)
        if len(bad_ct) > 0:
            bad_ct[0] ^= 0xFF
        tampered_header = ZsspyHeader(
            magic=header.magic,
            fmt_version=header.fmt_version,
            n_layers=header.n_layers,
            eph_pubkey=header.eph_pubkey,
            wrap_nonce=header.wrap_nonce,
            wrapped_master=header.wrapped_master,
            wrap_tag=header.wrap_tag,
            layer_nonces=header.layer_nonces,
            layer_tags=header.layer_tags,
            file_salt=header.file_salt,
            orig_sha256=header.orig_sha256,
            timestamp=header.timestamp,
            zss_version=header.zss_version,
            ciphertext=bytes(bad_ct),
        )
        with self.assertRaises(ZssCryptoError):
            decrypt_zspy(tampered_header, priv)

    def test_tampered_orig_hash_fails(self):
        blob, priv, _ = self._build()
        header = parse_zspy(blob)
        bad_hash = bytearray(header.orig_sha256)
        bad_hash[0] ^= 0xFF
        tampered_header = ZsspyHeader(
            magic=header.magic,
            fmt_version=header.fmt_version,
            n_layers=header.n_layers,
            eph_pubkey=header.eph_pubkey,
            wrap_nonce=header.wrap_nonce,
            wrapped_master=header.wrapped_master,
            wrap_tag=header.wrap_tag,
            layer_nonces=header.layer_nonces,
            layer_tags=header.layer_tags,
            file_salt=header.file_salt,
            orig_sha256=bytes(bad_hash),
            timestamp=header.timestamp,
            zss_version=header.zss_version,
            ciphertext=header.ciphertext,
        )
        with self.assertRaises(ZssCryptoError):
            decrypt_zspy(tampered_header, priv)

    def test_is_zspy_file_helper(self, tmp_path=None):
        import tempfile
        blob, _, _ = self._build()
        with tempfile.NamedTemporaryFile(suffix=".zspy", delete=False) as f:
            f.write(blob)
            path = Path(f.name)
        try:
            self.assertTrue(is_zspy_file(path))
        finally:
            path.unlink(missing_ok=True)
        with tempfile.NamedTemporaryFile(suffix=".zspy", delete=False) as f:
            f.write(b"not a zspy file")
            path = Path(f.name)
        try:
            self.assertFalse(is_zspy_file(path))
        finally:
            path.unlink(missing_ok=True)

    def test_n_layers_zero_in_header_rejected(self):
        bad = bytearray()
        bad += ZSSPY_MAGIC
        bad += struct.pack("<H", ZSSPY_FORMAT_VERSION)
        bad += struct.pack("<B", 0)
        bad += b"\x00\x00\x00"
        with self.assertRaises(ZssFormatError):
            parse_zspy(bytes(bad))

    def test_public_info_does_not_decrypt(self):
        blob, _, _ = self._build()
        header = parse_zspy(blob)
        info = zspy_public_info(header)
        self.assertIn("n_layers", info)
        self.assertIn("eph_pubkey", info)
        self.assertEqual(info["n_layers"], 5)
        for v in info.values():
            if isinstance(v, str):
                self.assertNotIn("hello", v)



class TestZson(unittest.TestCase):

    def _make_priv(self) -> X25519PrivateKey:
        return X25519PrivateKey.generate()

    def test_init_creates_zson(self):
        priv = self._make_priv()
        with _ZssHomeFixture() as fx:
            payload = init_zson(priv, ZSON_PATH, profile_name="tester")
            self.assertTrue(ZSON_PATH.exists())
            self.assertEqual(payload["profile_name"], "tester")
            self.assertEqual(payload["schema_version"], ZSON_SCHEMA_VERSION)
            self.assertIn("hkdf_salt", payload["secrets"])
            self.assertIn("pepper", payload["secrets"])

    def test_init_then_load_round_trip(self):
        priv = self._make_priv()
        with _ZssHomeFixture():
            init_zson(priv, ZSON_PATH, profile_name="bob")
            loaded = load_zson(priv, ZSON_PATH)
            self.assertEqual(loaded["profile_name"], "bob")
            self.assertEqual(
                loaded["secrets"]["hkdf_salt"],
                loaded["secrets"]["hkdf_salt"],
            )

    def test_load_missing_zson_is_error(self):
        priv = self._make_priv()
        with _ZssHomeFixture():
            with self.assertRaises(ZssConfigError):
                load_zson(priv, ZSON_PATH)

    def test_corrupt_zson_is_error(self):
        priv = self._make_priv()
        with _ZssHomeFixture():
            init_zson(priv, ZSON_PATH)
            data = read_bytes(ZSON_PATH)
            atomic_write_bytes(ZSON_PATH, data[:-8], mode=0o600)
            with self.assertRaises(ZssConfigError):
                load_zson(priv, ZSON_PATH)

    def test_wrong_private_key_is_error(self):
        priv1 = self._make_priv()
        priv2 = self._make_priv()
        with _ZssHomeFixture():
            init_zson(priv1, ZSON_PATH, profile_name="alice")
            with self.assertRaises(ZssConfigError):
                load_zson(priv2, ZSON_PATH)

    def test_bad_magic_is_error(self):
        priv = self._make_priv()
        with _ZssHomeFixture():
            init_zson(priv, ZSON_PATH)
            atomic_write_bytes(ZSON_PATH, b"NOTZSSON" + b"\x00" * 100, mode=0o600)
            with self.assertRaises(ZssConfigError) as ctx:
                load_zson(priv, ZSON_PATH)
            self.assertIn("magic", str(ctx.exception).lower())

    def test_future_schema_is_error(self):
        priv = self._make_priv()
        with _ZssHomeFixture():
            init_zson(priv, ZSON_PATH)
            data = bytearray(read_bytes(ZSON_PATH))
            data[8] = 99
            data[9] = 0
            atomic_write_bytes(ZSON_PATH, bytes(data), mode=0o600)
            with self.assertRaises(ZssConfigError) as ctx:
                load_zson(priv, ZSON_PATH)
            self.assertIn("newer", str(ctx.exception).lower())

    def test_update_zson_cache_round_trip(self):
        priv = self._make_priv()
        with _ZssHomeFixture() as fx:
            payload = init_zson(priv, ZSON_PATH)
            new_payload = update_zson_cache(
                payload,
                dir_path=fx.tmpdir,
                zspy_files=[{"name": "a.zspy", "ts": 1}],
                py_with_directives=["foo.py"],
            )
            save_zson(new_payload, priv, ZSON_PATH)
            loaded = load_zson(priv, ZSON_PATH)
            dir_key = str(fx.tmpdir.resolve())
            self.assertIn(dir_key, loaded["cache"])
            self.assertEqual(loaded["cache"][dir_key]["py_with_directives"], ["foo.py"])

    def test_seeds_wiped_after_init(self):
        global _seed_wiped, _SEED_PEPPER, _SEED_SALT
        _seed_wiped = False
        original_pepper = bytes(_SEED_PEPPER)
        original_salt = bytes(_SEED_SALT)
        try:
            priv = self._make_priv()
            with _ZssHomeFixture():
                init_zson(priv, ZSON_PATH)
            self.assertTrue(_seed_wiped)
            self.assertEqual(bytes(_SEED_PEPPER), b"\x00" * 32)
            self.assertEqual(bytes(_SEED_SALT), b"\x00" * 16)
        finally:
            _SEED_PEPPER[:] = original_pepper
            _SEED_SALT[:] = original_salt
            _seed_wiped = False



class TestUtils(unittest.TestCase):

    def test_atomic_write_bytes_creates_file(self):
        with _ZssHomeFixture() as fx:
            p = fx.tmpdir / "foo.bin"
            atomic_write_bytes(p, b"hello", mode=0o600)
            self.assertTrue(p.exists())
            self.assertEqual(p.read_bytes(), b"hello")
            mode = p.stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)

    def test_atomic_write_replaces_existing(self):
        with _ZssHomeFixture() as fx:
            p = fx.tmpdir / "foo.bin"
            atomic_write_bytes(p, b"old", mode=0o600)
            atomic_write_bytes(p, b"new", mode=0o600)
            self.assertEqual(p.read_bytes(), b"new")

    def test_safe_delete_removes_file(self):
        with _ZssHomeFixture() as fx:
            p = fx.tmpdir / "secret.bin"
            atomic_write_bytes(p, b"sensitive", mode=0o600)
            self.assertTrue(p.exists())
            safe_delete(p)
            self.assertFalse(p.exists())

    def test_safe_delete_missing_is_noop(self):
        with _ZssHomeFixture() as fx:
            p = fx.tmpdir / "nope.bin"
            safe_delete(p)

    def test_normalize_filename_accepts_valid(self):
        self.assertEqual(normalize_filename("hello.zspy"), "hello.zspy")
        self.assertEqual(normalize_filename("_priv.zspy"), "_priv.zspy")
        self.assertEqual(normalize_filename("a1_b2.zspy"), "a1_b2.zspy")

    def test_normalize_filename_rejects_paths(self):
        with self.assertRaises(ZssFormatError):
            normalize_filename("../escape.zspy")
        with self.assertRaises(ZssFormatError):
            normalize_filename("/abs/path.zspy")
        with self.assertRaises(ZssFormatError):
            normalize_filename("dir/sub.zspy")
        with self.assertRaises(ZssFormatError):
            normalize_filename("1digit.zspy")
        with self.assertRaises(ZssFormatError):
            normalize_filename("noext")

    def test_zero_fill_bytearray(self):
        b = bytearray(b"\x01\x02\x03\x04")
        zero_fill(b)
        self.assertEqual(bytes(b), b"\x00\x00\x00\x00")

    def test_zero_fill_none_is_noop(self):
        zero_fill(None)

    def test_sha256_known_vector(self):
        self.assertEqual(
            sha256(b""),
            bytes.fromhex(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ),
        )
        self.assertEqual(
            sha256(b"abc"),
            bytes.fromhex(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            ),
        )

    def test_b64_round_trip(self):
        for s in [b"", b"x", b"hello world", os.urandom(64)]:
            self.assertEqual(_b64d(_b64e(s)), s)



class TestIntegration(unittest.TestCase):

    def test_pack_and_run_round_trip(self):
        with _ZssHomeFixture() as fx:
            _ensure_dir(KEYS_DIR, mode=0o700)
            priv, pub = generate_keypair()
            save_private_key(priv, PRIVATE_KEY_PATH)
            save_public_key(pub, PUBLIC_KEY_PATH)
            init_zson(priv, ZSON_PATH)

            src_path = fx.tmpdir / "demo.py"
            src_path.write_text(
                "from zss import load\n"
                "#<zss>{write_to!greet.zspy\n"
                "def hello():\n"
                "    return 'hi from zspy'\n"
                "#<zss>{closing!write!greet.zspy\n"
                "print(hello())\n",
                encoding="utf-8",
            )

            args = argparse.Namespace(
                file=str(src_path),
                layers=3,
                in_place=True,
                no_clobber=False,
            )
            rc = cmd_pack(args)
            self.assertEqual(rc, 0)
            self.assertTrue((fx.tmpdir / "greet.zspy").exists())
            self.assertTrue((fx.tmpdir / "demo.py.bak").exists())
            packed = src_path.read_text(encoding="utf-8")
            self.assertIn('from zss import load; load("greet.zspy")', packed)
            self.assertNotIn("def hello", packed)

            run_args = argparse.Namespace(
                file=str(src_path),
                arg=[],
                debug=False,
            )
            old_stdout = sys.stdout
            captured = io.StringIO()
            sys.stdout = captured
            try:
                rc = cmd_run(run_args)
            finally:
                sys.stdout = old_stdout
            self.assertEqual(rc, 0)
            self.assertIn("hi from zspy", captured.getvalue())

    def test_run_zspy_directly(self):
        with _ZssHomeFixture() as fx:
            _ensure_dir(KEYS_DIR, mode=0o700)
            priv, pub = generate_keypair()
            save_private_key(priv, PRIVATE_KEY_PATH)
            save_public_key(pub, PUBLIC_KEY_PATH)
            init_zson(priv, ZSON_PATH)

            plaintext = b"import sys; sys.stdout.write('zspy-ran\\n'); sys.exit(0)\n"
            master = _secure_random(MASTER_KEY_SIZE)
            try:
                blob = build_zspy(plaintext, master, 5, pub)
            finally:
                zero_fill(bytearray(master))
            zspy_path = fx.tmpdir / "direct.zspy"
            atomic_write_bytes(zspy_path, blob, mode=0o644)

            args = argparse.Namespace(file=str(zspy_path), arg=[], debug=False)
            old_stdout = sys.stdout
            captured = io.StringIO()
            sys.stdout = captured
            try:
                rc = cmd_run(args)
            finally:
                sys.stdout = old_stdout
            self.assertEqual(rc, 0)
            self.assertIn("zspy-ran", captured.getvalue())



import atexit
import runpy
import zlib


_ARC_DIR_RE = re.compile(
    r"^\s*#\s*dir-\s*\{\s*([A-Za-z_][A-Za-z0-9_]*\.py)\s*\}\s*"
    r"-directory!\s*([A-Za-z_][A-Za-z0-9_-]*)\s*!\s*$"
)
_ARC_ON_RE = re.compile(
    r"^\s*#\s*on\s*\{\s*([A-Za-z_][A-Za-z0-9_]*\.py)\s*\}\s*"
    r"-import--files\s*\{\s*([^}]*)\s*\}\s*$"
)

_ARC_OUTER_INFO = b"zss:archive-outer:v1"
_ARC_OUTER_AAD_PREFIX = b"zss:archive:v1|salt="


def _arc_parse_directives(source: str):
    dir_match = None
    on_match = None
    dir_count = 0
    on_count = 0
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, IndentationError) as e:
        raise ZssParseError(f"cannot tokenize source: {e}") from e

    for tok in tokens:
        if tok.type != tokenize.COMMENT:
            continue
        m = _ARC_DIR_RE.match(tok.string)
        if m:
            dir_count += 1
            if dir_count > 1:
                raise ZssParseError(
                    f"duplicate #dir directive at line {tok.start[0]}"
                )
            dir_match = m
            continue
        m = _ARC_ON_RE.match(tok.string)
        if m:
            on_count += 1
            if on_count > 1:
                raise ZssParseError(
                    f"duplicate #on directive at line {tok.start[0]}"
                )
            on_match = m
            continue

    if dir_match is None and on_match is None:
        return None

    if dir_match is None:
        raise ZssParseError("#on directive without matching #dir")
    if on_match is None:
        raise ZssParseError("#dir directive without matching #on")

    entry_dir = dir_match.group(1)
    name = dir_match.group(2)
    entry_on = on_match.group(1)
    files_str = on_match.group(2).strip()

    if entry_dir != entry_on:
        raise ZssParseError(
            f"entry mismatch: #dir says '{entry_dir}', #on says '{entry_on}'"
        )

    if files_str:
        files_list = [f.strip() for f in files_str.split(",") if f.strip()]
    else:
        files_list = None

    return (entry_dir, name, files_list)


def _arc_scan_py_files(dir_path: Path) -> list[str]:
    result = []
    for root, dirs, files in os.walk(dir_path):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for f in files:
            if f.endswith(".py"):
                full = Path(root) / f
                rel = full.relative_to(dir_path).as_posix()
                result.append(rel)
    return sorted(result)


def _arc_build_archive(
    py_path: Path,
    entry: str,
    name: str,
    files_list,
    n_layers: int,
    recipient_pub: X25519PublicKey,
    *,
    timestamp: Optional[int] = None,
) -> tuple[bytes, list[str]]:
    dir_path = py_path.parent / name
    if not dir_path.is_dir():
        raise ZssFormatError(f"directory not found: {dir_path}")

    if files_list is None:
        actual_files = _arc_scan_py_files(dir_path)
        if not actual_files:
            raise ZssFormatError(f"no .py files in {dir_path}")
    else:
        actual_files = list(files_list)
        for f in actual_files:
            fpath = dir_path / f
            if not fpath.is_file():
                raise ZssFormatError(f"file not found: {fpath}")

    if entry not in actual_files:
        raise ZssFormatError(
            f"entry '{entry}' not in file list: {actual_files}"
        )

    master = _secure_random(MASTER_KEY_SIZE)
    try:
        files_b64: dict[str, str] = {}
        file_hashes: dict[str, str] = {}
        for fname in actual_files:
            fpath = dir_path / fname
            content = fpath.read_bytes()
            salt = _secure_random(ZSSPY_FILE_SALT_SIZE)
            layered = encrypt_layers(content, master, n_layers, salt)
            blob = bytearray()
            blob += salt
            for n in layered.nonces:
                blob += n
            for t in layered.tags:
                blob += t
            blob += layered.ciphertext
            files_b64[fname] = _b64e(bytes(blob))
            file_hashes[fname] = sha256(content).hex()

        manifest = {
            "schema": 1,
            "entry": entry,
            "files": files_b64,
            "file_hashes": file_hashes,
        }
        manifest_bytes = json.dumps(
            manifest, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        compressed = zlib.compress(manifest_bytes, 9)

        file_salt = _secure_random(ZSSPY_FILE_SALT_SIZE)
        outer_key = hkdf_derive(master, file_salt, _ARC_OUTER_INFO, KEY_SIZE)
        outer_nonce = _secure_random(NONCE_SIZE)
        outer_aad = _ARC_OUTER_AAD_PREFIX + file_salt
        aead = ChaCha20Poly1305(outer_key)
        outer_ct = aead.encrypt(outer_nonce, compressed, outer_aad)
        zero_fill(bytearray(outer_key))

        wrap = wrap_master_key(master, recipient_pub)
        if len(wrap.wrapped) != MASTER_KEY_SIZE + TAG_SIZE:
            raise ZssCryptoError("internal: wrapped has unexpected length")
        wrapped_master = wrap.wrapped[:MASTER_KEY_SIZE]
        wrap_tag = wrap.wrapped[MASTER_KEY_SIZE:]

        import time
        if timestamp is None:
            timestamp = int(time.time())
        zss_ver_bytes = ZSS_VERSION.encode("utf-8")

        ct_payload = outer_nonce + outer_ct

        out = bytearray()
        out += ZSSPY_MAGIC
        out += struct.pack("<H", ZSSPY_FORMAT_VERSION)
        out += struct.pack("<B", n_layers)
        out += bytes([1, 0, 0])
        out += wrap.eph_pubkey
        out += wrap.wrap_nonce
        out += wrapped_master
        out += wrap_tag
        out += file_salt
        out += sha256(manifest_bytes)
        out += struct.pack("<Q", timestamp)
        out += struct.pack("<B", len(zss_ver_bytes))
        out += zss_ver_bytes
        out += struct.pack("<I", len(ct_payload))
        out += ct_payload

        return bytes(out), actual_files
    finally:
        zero_fill(bytearray(master))


@dataclass
class _ArcManifest:
    schema: int
    entry: str
    files: dict
    file_hashes: dict


def _arc_decrypt_archive(
    header: ZsspyHeader, recipient_priv: X25519PrivateKey
) -> _ArcManifest:
    wrap = WrappedMasterKey(
        eph_pubkey=header.eph_pubkey,
        wrap_nonce=header.wrap_nonce,
        wrapped=header.wrapped_master + header.wrap_tag,
    )
    master = unwrap_master_key(wrap, recipient_priv)

    try:
        outer_key = hkdf_derive(master, header.file_salt, _ARC_OUTER_INFO, KEY_SIZE)

        if len(header.ciphertext) < NONCE_SIZE:
            raise ZssCryptoError("archive ciphertext too short for outer nonce")
        outer_nonce = header.ciphertext[:NONCE_SIZE]
        outer_ct = header.ciphertext[NONCE_SIZE:]
        outer_aad = _ARC_OUTER_AAD_PREFIX + header.file_salt
        aead = ChaCha20Poly1305(outer_key)
        try:
            compressed = aead.decrypt(outer_nonce, outer_ct, outer_aad)
        except InvalidTag as e:
            raise ZssCryptoError(
                "archive outer AEAD tag verification failed"
            ) from e
        finally:
            zero_fill(bytearray(outer_key))

        try:
            manifest_bytes = zlib.decompress(compressed)
        except zlib.error as e:
            raise ZssCryptoError(f"zlib decompress failed: {e}") from e

        actual_hash = sha256(manifest_bytes)
        if actual_hash != header.orig_sha256:
            raise ZssCryptoError(
                "archive manifest hash mismatch — file is corrupt"
            )

        try:
            manifest = json.loads(manifest_bytes.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ZssFormatError(f"manifest is not valid JSON: {e}") from e

        if manifest.get("schema") != 1:
            raise ZssFormatError(
                f"unsupported manifest schema: {manifest.get('schema')}"
            )
        for k in ("entry", "files", "file_hashes"):
            if k not in manifest:
                raise ZssFormatError(f"manifest missing required key: {k}")

        entry = manifest["entry"]
        files_b64 = manifest["files"]
        file_hashes = manifest["file_hashes"]

        files_plain: dict[str, bytes] = {}
        n_layers = header.n_layers
        for fname, blob_b64 in files_b64.items():
            blob = _b64d(blob_b64)
            min_len = (
                ZSSPY_FILE_SALT_SIZE
                + NONCE_SIZE * n_layers
                + TAG_SIZE * n_layers
            )
            if len(blob) < min_len:
                raise ZssCryptoError(
                    f"archive file blob too short: {fname} ({len(blob)} < {min_len})"
                )
            pos = 0
            salt = blob[pos:pos + ZSSPY_FILE_SALT_SIZE]
            pos += ZSSPY_FILE_SALT_SIZE
            nonces = []
            for _ in range(n_layers):
                nonces.append(blob[pos:pos + NONCE_SIZE])
                pos += NONCE_SIZE
            tags = []
            for _ in range(n_layers):
                tags.append(blob[pos:pos + TAG_SIZE])
                pos += TAG_SIZE
            ct = blob[pos:]

            layered = LayeredCiphertext(
                salt=salt,
                n_layers=n_layers,
                nonces=nonces,
                tags=tags,
                ciphertext=ct,
            )
            plaintext = decrypt_layers(layered, master)

            expected_hash = file_hashes.get(fname)
            if expected_hash is None:
                zero_fill(bytearray(plaintext))
                raise ZssCryptoError(f"manifest missing file_hash for {fname}")
            actual = sha256(plaintext).hex()
            if actual != expected_hash:
                zero_fill(bytearray(plaintext))
                raise ZssCryptoError(f"file hash mismatch for {fname}")

            files_plain[fname] = plaintext

        return _ArcManifest(
            schema=manifest["schema"],
            entry=entry,
            files=files_plain,
            file_hashes=file_hashes,
        )
    finally:
        zero_fill(bytearray(master))


def _arc_materialize(manifest: _ArcManifest) -> Path:
    tmpdir = Path(tempfile.mkdtemp(prefix="zss-arc-"))
    for fname, content in manifest.files.items():
        fpath = tmpdir / fname
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_bytes(content)
    atexit.register(shutil.rmtree, str(tmpdir), True)
    return tmpdir


def _arc_run_entry(tmpdir: Path, entry: str, argv: list[str]) -> int:
    entry_path = tmpdir / entry
    if not entry_path.is_file():
        raise ZssFormatError(f"entry not found in archive: {entry}")

    if str(tmpdir) not in sys.path:
        sys.path.insert(0, str(tmpdir))
    sys.argv = [str(entry_path)] + list(argv)

    try:
        runpy.run_path(str(entry_path), run_name="__main__")
    except SystemExit as e:
        if isinstance(e.code, int):
            return e.code
        if e.code is None:
            return 0
        return 1
    return 0


def load_dir(name: str) -> None:
    if not isinstance(name, str) or not name.endswith(".zspy"):
        raise ZssFormatError(f"load_dir expects a .zspy name, got {name!r}")

    caller = sys._getframe(1)
    caller_file = caller.f_globals.get("__file__", "")
    if not caller_file:
        raise ZssError("load_dir() called without __file__ in caller globals")

    archive_path = _resolve_zspy_path(caller_file, name)
    if not archive_path.exists():
        raise ZssFormatError(f"archive not found: {archive_path}")

    data = read_bytes(archive_path)
    header = parse_zspy(data)

    if header.layer_nonces or header.layer_tags:
        raise ZssFormatError(
            f"{name} is a single-file .zspy, not an archive. Use load() instead."
        )

    priv = load_private_key()
    manifest = _arc_decrypt_archive(header, priv)
    tmpdir = _arc_materialize(manifest)
    rc = _arc_run_entry(tmpdir, manifest.entry, [])
    if rc != 0:
        raise SystemExit(rc)



_arc_orig_cmd_pack = cmd_pack


def _arc_cmd_pack_archive(args, py_path, arc_dirs) -> int:
    entry, name, files_list = arc_dirs
    _zss_home_env_override()
    try:
        priv = load_private_key(PRIVATE_KEY_PATH)
    except ZssKeyError as e:
        _eprint(f"error: {e}")
        return 1
    pub = priv.public_key()

    n_layers = args.layers
    if n_layers is None:
        try:
            payload = load_zson(priv, ZSON_PATH)
            n_layers = int(
                get_zson_setting(payload, "default_n_layers", DEFAULT_N_LAYERS)
            )
        except ZssConfigError:
            n_layers = DEFAULT_N_LAYERS

    if not (MIN_N_LAYERS <= n_layers <= MAX_N_LAYERS):
        _eprint(
            f"error: --layers must be in [{MIN_N_LAYERS}..{MAX_N_LAYERS}], got {n_layers}"
        )
        return 1

    try:
        blob, packed_files = _arc_build_archive(
            py_path, entry, name, files_list, n_layers, pub
        )
    except (ZssFormatError, ZssCryptoError, ZssParseError) as e:
        _eprint(f"error: {e}")
        return 1

    out_path = py_path.parent / f"{name}.zspy"
    atomic_write_bytes(out_path, blob, mode=0o644)

    bak_path = py_path.with_suffix(py_path.suffix + ".bak")
    if bak_path.exists() and args.no_clobber:
        _eprint(f"error: backup file exists: {bak_path}")
        return 1
    try:
        source = py_path.read_text(encoding="utf-8")
        atomic_write_text(bak_path, source, mode=0o600)
    except (OSError, UnicodeDecodeError) as e:
        _eprint(f"error: cannot write backup: {e}")
        return 1

    stub = f'from zss import load_dir\nload_dir("{name}.zspy")\n'
    if args.in_place:
        target = py_path
    else:
        target = py_path.with_suffix(".packed.py")
    try:
        atomic_write_text(target, stub, mode=0o644)
    except OSError as e:
        _eprint(f"error: cannot write packed source: {e}")
        return 1

    _print(f"packed archive {py_path.name} -> {out_path.name}:")
    _print(f"  entry:  {entry}")
    files_preview = ", ".join(packed_files[:5])
    if len(packed_files) > 5:
        files_preview += f", ... (+{len(packed_files) - 5} more)"
    _print(f"  files:  {len(packed_files)} ({files_preview})")
    _print(f"  layers: {n_layers}")
    _print(f"  size:   {out_path.stat().st_size} bytes")
    _print(f"  -> {target.name} (load_dir stub)")
    _print(f"  backup: {bak_path.name}")
    if not args.in_place:
        _print(f"")
        _print(f"  Run with:  zss run {target.name}")
    return 0


def cmd_pack(args):
    py_path = Path(args.file).expanduser().resolve()
    if not py_path.is_file():
        _eprint(f"error: source file not found: {py_path}")
        return 1
    if py_path.suffix != ".py":
        _eprint(f"error: expected a .py file, got {py_path.name}")
        return 1
    try:
        source = py_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        _eprint(f"error: source is not valid UTF-8: {e}")
        return 1
    try:
        arc_dirs = _arc_parse_directives(source)
    except ZssParseError as e:
        _eprint(f"error: parse failure in {py_path}: {e}")
        return 1
    if arc_dirs is None:
        return _arc_orig_cmd_pack(args)
    return _arc_cmd_pack_archive(args, py_path, arc_dirs)



_arc_orig_cmd_run = cmd_run


def _arc_run_archive_direct(zspy_path: Path, args, header) -> int:
    try:
        priv = load_private_key(PRIVATE_KEY_PATH)
    except ZssKeyError as e:
        _eprint(f"error: {e}")
        return 1
    try:
        manifest = _arc_decrypt_archive(header, priv)
    except (ZssCryptoError, ZssFormatError) as e:
        _eprint(f"error: archive decryption failed: {e}")
        return 1
    tmpdir = _arc_materialize(manifest)
    try:
        return _arc_run_entry(tmpdir, manifest.entry, list(args.arg or []))
    except ZssFormatError as e:
        _eprint(f"error: {e}")
        return 1
    except Exception as e:
        if getattr(args, "debug", False):
            raise
        _eprint(f"error: runtime exception: {type(e).__name__}: {e}")
        return 1


def _arc_run_packed_dir(py_path: Path, args) -> int:
    source = py_path.read_text(encoding="utf-8")
    namespace = {
        "__name__": "__main__",
        "__file__": str(py_path),
        "__builtins__": __builtins__,
    }
    sys.argv = [str(py_path)] + list(args.arg or [])

    script_dir = str(py_path.parent)
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

    current_module = sys.modules[__name__]
    saved_zss = sys.modules.get("zss")
    sys.modules["zss"] = current_module

    try:
        code = compile(source, str(py_path), "exec")
        exec(code, namespace)
    except SystemExit as e:
        if isinstance(e.code, int):
            return e.code
        if e.code is None:
            return 0
        return 1
    except ZssError as e:
        if getattr(args, "debug", False):
            raise
        _eprint(f"error: {e}")
        return 1
    except Exception as e:
        if getattr(args, "debug", False):
            raise
        _eprint(f"error: runtime exception: {type(e).__name__}: {e}")
        return 1
    finally:
        if saved_zss is not None:
            sys.modules["zss"] = saved_zss
        elif sys.modules.get("zss") is current_module:
            del sys.modules["zss"]
    return 0


def cmd_run(args):
    _zss_home_env_override()
    target = Path(args.file).expanduser().resolve()
    if not target.exists():
        _eprint(f"error: file not found: {target}")
        return 1

    if target.suffix == ".zspy":
        try:
            data = read_bytes(target)
            header = parse_zspy(data)
        except ZssFormatError as e:
            _eprint(f"error: {e}")
            return 1
        if not header.layer_nonces and not header.layer_tags:
            return _arc_run_archive_direct(target, args, header)
        return _arc_orig_cmd_run(args)

    if target.suffix == ".py":
        try:
            source = target.read_text(encoding="utf-8")
        except UnicodeDecodeError as e:
            _eprint(f"error: source is not valid UTF-8: {e}")
            return 1
        if "load_dir(" in source and "from zss import load_dir" in source:
            return _arc_run_packed_dir(target, args)
        return _arc_orig_cmd_run(args)

    _eprint(f"error: expected .py or .zspy, got {target.suffix}")
    return 1



_arc_orig_zspy_public_info = zspy_public_info


def zspy_public_info(header):
    info = _arc_orig_zspy_public_info(header)
    info["kind"] = (
        "archive"
        if (not header.layer_nonces and not header.layer_tags)
        else "single"
    )
    return info


_arc_orig_cmd_list = cmd_list


def cmd_list(args):
    _zss_home_env_override()
    scan_dir = (
        Path(args.dir).expanduser().resolve() if args.dir else Path.cwd()
    )
    if not scan_dir.is_dir():
        _eprint(f"error: not a directory: {scan_dir}")
        return 1

    zspy_entries: list[dict] = []
    py_entries: list[dict] = []

    try:
        for entry in sorted(scan_dir.iterdir()):
            if entry.is_file() and entry.suffix == ".zspy":
                if is_zspy_file(entry):
                    try:
                        data = read_bytes(entry)
                        header = parse_zspy(data)
                        info = zspy_public_info(header)
                        info["name"] = entry.name
                        zspy_entries.append(info)
                    except ZssFormatError as e:
                        zspy_entries.append({"name": entry.name, "error": str(e)})
            elif entry.is_file() and entry.suffix == ".py":
                try:
                    src = entry.read_text(encoding="utf-8")
                    arc = _arc_parse_directives(src)
                    if arc is not None:
                        py_entries.append({
                            "name": entry.name,
                            "kind": "archive",
                            "entry": arc[0],
                            "dir": arc[1],
                        })
                    elif has_directives(src):
                        names = find_directive_filenames(src)
                        py_entries.append({
                            "name": entry.name,
                            "kind": "single",
                            "directives": names,
                        })
                except (UnicodeDecodeError, ZssParseError):
                    pass
    except OSError as e:
        _eprint(f"error: cannot scan {scan_dir}: {e}")
        return 1

    zson_payload: Optional[dict] = None
    try:
        priv = load_private_key(PRIVATE_KEY_PATH)
        zson_payload = load_zson(priv, ZSON_PATH)
    except (ZssKeyError, ZssConfigError):
        pass

    if args.json:
        out = {
            "dir": str(scan_dir),
            "zspy": zspy_entries,
            "py_with_directives": py_entries,
            "zson_present": zson_payload is not None,
        }
        if zson_payload:
            out["zson_settings"] = zson_payload.get("settings", {})
        _print(json.dumps(out, indent=2, sort_keys=True))
        return 0

    _print(f"ZSS scan: {scan_dir}")
    _print(f"")
    if zspy_entries:
        _print(f"  .zspy files ({len(zspy_entries)}):")
        for e in zspy_entries:
            if "error" in e:
                _print(f"    {e['name']}: ERROR: {e['error']}")
            else:
                kind = e.get("kind", "?")
                _print(
                    f"    {e['name']}: [{kind}] N={e['n_layers']} "
                    f"ct={e['ciphertext_size']}B "
                    f"ts={e.get('timestamp_iso', '?')} "
                    f"zss={e['zss_version']}"
                )
    else:
        _print(f"  .zspy files: none")
    _print(f"")
    if py_entries:
        _print(f"  .py with directives ({len(py_entries)}):")
        for e in py_entries:
            kind = e.get("kind", "single")
            if kind == "archive":
                _print(
                    f"    {e['name']}: [archive] entry={e['entry']} dir={e['dir']}/"
                )
            else:
                _print(
                    f"    {e['name']}: [single] blocks -> {', '.join(e['directives'])}"
                )
    else:
        _print(f"  .py with directives: none")
    _print(f"")
    if zson_payload:
        _print(f"  .zson: {ZSON_PATH}")
        _print(f"    schema: {zson_payload['schema_version']}")
        _print(f"    created: {zson_payload.get('created_at')}")
        _print(f"    default_n_layers: {zson_payload['settings']['default_n_layers']}")
    else:
        _print(f"  .zson: not initialized (run `zss init`)")
    return 0



class TestArchive(unittest.TestCase):

    def _setup_home(self, fx):
        _ensure_dir(KEYS_DIR, mode=0o700)
        priv, pub = generate_keypair()
        save_private_key(priv, PRIVATE_KEY_PATH)
        save_public_key(pub, PUBLIC_KEY_PATH)
        init_zson(priv, ZSON_PATH)
        return priv

    def test_arc_parse_directives_basic(self):
        src = (
            "#dir-{main.py}-directory!game!\n"
            "#on{main.py}-import--files{a.py, b.py}\n"
        )
        result = _arc_parse_directives(src)
        self.assertIsNotNone(result)
        entry, name, files = result
        self.assertEqual(entry, "main.py")
        self.assertEqual(name, "game")
        self.assertEqual(files, ["a.py", "b.py"])

    def test_arc_parse_directives_empty_files(self):
        src = (
            "#dir-{main.py}-directory!game!\n"
            "#on{main.py}-import--files{}\n"
        )
        result = _arc_parse_directives(src)
        self.assertIsNotNone(result)
        entry, name, files = result
        self.assertEqual(entry, "main.py")
        self.assertEqual(name, "game")
        self.assertIsNone(files)

    def test_arc_parse_directives_none_when_no_directives(self):
        src = "print('hello')\n# just a comment\n"
        result = _arc_parse_directives(src)
        self.assertIsNone(result)

    def test_arc_parse_directives_dir_without_on_is_error(self):
        src = "#dir-{main.py}-directory!game!\n"
        with self.assertRaises(ZssParseError) as ctx:
            _arc_parse_directives(src)
        self.assertIn("without matching #on", str(ctx.exception))

    def test_arc_parse_directives_on_without_dir_is_error(self):
        src = "#on{main.py}-import--files{a.py}\n"
        with self.assertRaises(ZssParseError) as ctx:
            _arc_parse_directives(src)
        self.assertIn("without matching #dir", str(ctx.exception))

    def test_arc_parse_directives_entry_mismatch_is_error(self):
        src = (
            "#dir-{main.py}-directory!game!\n"
            "#on{other.py}-import--files{a.py}\n"
        )
        with self.assertRaises(ZssParseError) as ctx:
            _arc_parse_directives(src)
        self.assertIn("mismatch", str(ctx.exception).lower())

    def test_arc_parse_directives_duplicate_dir_is_error(self):
        src = (
            "#dir-{main.py}-directory!game!\n"
            "#dir-{main.py}-directory!game!\n"
            "#on{main.py}-import--files{a.py}\n"
        )
        with self.assertRaises(ZssParseError) as ctx:
            _arc_parse_directives(src)
        self.assertIn("duplicate #dir", str(ctx.exception))

    def test_arc_parse_directives_duplicate_on_is_error(self):
        src = (
            "#dir-{main.py}-directory!game!\n"
            "#on{main.py}-import--files{a.py}\n"
            "#on{main.py}-import--files{a.py}\n"
        )
        with self.assertRaises(ZssParseError) as ctx:
            _arc_parse_directives(src)
        self.assertIn("duplicate #on", str(ctx.exception))

    def test_arc_parse_directives_in_string_ignored(self):
        src = (
            "s = \"#dir-{main.py}-directory!game!\\n\"\n"
            "t = \"#on{main.py}-import--files{a.py}\\n\"\n"
        )
        result = _arc_parse_directives(src)
        self.assertIsNone(result)

    def test_arc_build_and_decrypt_round_trip(self):
        with _ZssHomeFixture() as fx:
            priv = self._setup_home(fx)
            pub = priv.public_key()

            game_dir = fx.tmpdir / "game"
            game_dir.mkdir()
            (game_dir / "main.py").write_text(
                "from helper import greet\nprint(greet())\n",
                encoding="utf-8",
            )
            (game_dir / "helper.py").write_text(
                "def greet():\n    return 'hello from helper'\n",
                encoding="utf-8",
            )

            blob, files = _arc_build_archive(
                py_path=fx.tmpdir / "loader.py",
                entry="main.py",
                name="game",
                files_list=None,
                n_layers=3,
                recipient_pub=pub,
                timestamp=1700000000,
            )
            self.assertIn("main.py", files)
            self.assertIn("helper.py", files)

            header = parse_zspy(blob)
            self.assertEqual(header.n_layers, 3)
            self.assertEqual([], header.layer_nonces)
            self.assertEqual([], header.layer_tags)
            manifest = _arc_decrypt_archive(header, priv)
            self.assertEqual(manifest.entry, "main.py")
            self.assertIn("main.py", manifest.files)
            self.assertIn("helper.py", manifest.files)
            self.assertIn(b"def greet", manifest.files["helper.py"])
            self.assertIn(b"from helper import greet", manifest.files["main.py"])

    def test_arc_build_rejects_missing_entry(self):
        with _ZssHomeFixture() as fx:
            priv = self._setup_home(fx)
            pub = priv.public_key()

            game_dir = fx.tmpdir / "game"
            game_dir.mkdir()
            (game_dir / "a.py").write_text("x = 1\n", encoding="utf-8")

            with self.assertRaises(ZssFormatError) as ctx:
                _arc_build_archive(
                    py_path=fx.tmpdir / "loader.py",
                    entry="main.py",
                    name="game",
                    files_list=["a.py"],
                    n_layers=3,
                    recipient_pub=pub,
                )
            self.assertIn("not in file list", str(ctx.exception))

    def test_arc_build_rejects_missing_directory(self):
        with _ZssHomeFixture() as fx:
            priv = self._setup_home(fx)
            pub = priv.public_key()

            with self.assertRaises(ZssFormatError) as ctx:
                _arc_build_archive(
                    py_path=fx.tmpdir / "loader.py",
                    entry="main.py",
                    name="nonexistent",
                    files_list=None,
                    n_layers=3,
                    recipient_pub=pub,
                )
            self.assertIn("directory not found", str(ctx.exception).lower())

    def test_arc_decrypt_tampered_outer_ct_fails(self):
        with _ZssHomeFixture() as fx:
            priv = self._setup_home(fx)
            pub = priv.public_key()

            game_dir = fx.tmpdir / "game"
            game_dir.mkdir()
            (game_dir / "main.py").write_text("print('hi')\n", encoding="utf-8")

            blob, _ = _arc_build_archive(
                py_path=fx.tmpdir / "loader.py",
                entry="main.py",
                name="game",
                files_list=None,
                n_layers=3,
                recipient_pub=pub,
            )
            header = parse_zspy(blob)
            bad_ct = bytearray(header.ciphertext)
            bad_ct[-1] ^= 0xFF
            tampered_header = ZsspyHeader(
                magic=header.magic,
                fmt_version=header.fmt_version,
                n_layers=header.n_layers,
                eph_pubkey=header.eph_pubkey,
                wrap_nonce=header.wrap_nonce,
                wrapped_master=header.wrapped_master,
                wrap_tag=header.wrap_tag,
                layer_nonces=header.layer_nonces,
                layer_tags=header.layer_tags,
                file_salt=header.file_salt,
                orig_sha256=header.orig_sha256,
                timestamp=header.timestamp,
                zss_version=header.zss_version,
                ciphertext=bytes(bad_ct),
            )
            with self.assertRaises(ZssCryptoError):
                _arc_decrypt_archive(tampered_header, priv)

    def test_arc_materialize_creates_files(self):
        manifest = _ArcManifest(
            schema=1,
            entry="main.py",
            files={"main.py": b"print('hi')\n", "sub/util.py": b"x = 1\n"},
            file_hashes={},
        )
        tmpdir = _arc_materialize(manifest)
        try:
            self.assertTrue((tmpdir / "main.py").exists())
            self.assertTrue((tmpdir / "sub" / "util.py").exists())
            self.assertEqual(
                (tmpdir / "main.py").read_bytes(), b"print('hi')\n"
            )
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_arc_end_to_end_pack_and_run_direct(self):
        with _ZssHomeFixture() as fx:
            priv = self._setup_home(fx)
            pub = priv.public_key()

            game_dir = fx.tmpdir / "game"
            game_dir.mkdir()
            (game_dir / "main.py").write_text(
                "import sys\nsys.stdout.write('arc-main-ran\\n')\nsys.exit(0)\n",
                encoding="utf-8",
            )
            (game_dir / "util.py").write_text(
                "UTIL = 'utility'\n",
                encoding="utf-8",
            )

            blob, _ = _arc_build_archive(
                py_path=fx.tmpdir / "loader.py",
                entry="main.py",
                name="game",
                files_list=None,
                n_layers=3,
                recipient_pub=pub,
            )
            zspy_path = fx.tmpdir / "game.zspy"
            atomic_write_bytes(zspy_path, blob, mode=0o644)

            args = argparse.Namespace(
                file=str(zspy_path), arg=[], debug=False
            )
            old_stdout = sys.stdout
            captured = io.StringIO()
            sys.stdout = captured
            try:
                rc = cmd_run(args)
            finally:
                sys.stdout = old_stdout
            self.assertEqual(rc, 0)
            self.assertIn("arc-main-ran", captured.getvalue())

    def test_arc_end_to_end_via_cmd_pack_and_run(self):
        with _ZssHomeFixture() as fx:
            priv = self._setup_home(fx)
            pub = priv.public_key()

            game_dir = fx.tmpdir / "game"
            game_dir.mkdir()
            (game_dir / "main.py").write_text(
                "import sys\nsys.stdout.write('packed-arc-ok\\n')\nsys.exit(0)\n",
                encoding="utf-8",
            )

            loader_path = fx.tmpdir / "loader.py"
            loader_path.write_text(
                "#dir-{main.py}-directory!game!\n"
                "#on{main.py}-import--files{}\n",
                encoding="utf-8",
            )

            pack_args = argparse.Namespace(
                file=str(loader_path),
                layers=3,
                in_place=True,
                no_clobber=False,
            )
            rc = cmd_pack(pack_args)
            self.assertEqual(rc, 0)
            self.assertTrue((fx.tmpdir / "game.zspy").exists())
            self.assertTrue((fx.tmpdir / "loader.py.bak").exists())
            packed = loader_path.read_text(encoding="utf-8")
            self.assertIn("from zss import load_dir", packed)
            self.assertIn('load_dir("game.zspy")', packed)

            run_args = argparse.Namespace(
                file=str(loader_path), arg=[], debug=False
            )
            old_stdout = sys.stdout
            captured = io.StringIO()
            sys.stdout = captured
            try:
                rc = cmd_run(run_args)
            finally:
                sys.stdout = old_stdout
            self.assertEqual(rc, 0)
            self.assertIn("packed-arc-ok", captured.getvalue())

    def test_arc_old_single_file_still_works_after_patch(self):
        with _ZssHomeFixture() as fx:
            priv = self._setup_home(fx)
            pub = priv.public_key()

            src_path = fx.tmpdir / "old.py"
            src_path.write_text(
                "from zss import load\n"
                "#<zss>{write_to!secret.zspy\n"
                "VALUE = 'old-mode-works'\n"
                "#<zss>{closing!write!secret.zspy\n"
                "print(VALUE)\n",
                encoding="utf-8",
            )

            pack_args = argparse.Namespace(
                file=str(src_path),
                layers=3,
                in_place=True,
                no_clobber=False,
            )
            rc = cmd_pack(pack_args)
            self.assertEqual(rc, 0)
            self.assertTrue((fx.tmpdir / "secret.zspy").exists())

            run_args = argparse.Namespace(
                file=str(src_path), arg=[], debug=False
            )
            old_stdout = sys.stdout
            captured = io.StringIO()
            sys.stdout = captured
            try:
                rc = cmd_run(run_args)
            finally:
                sys.stdout = old_stdout
            self.assertEqual(rc, 0)
            self.assertIn("old-mode-works", captured.getvalue())

    def test_arc_zspy_public_info_has_kind(self):
        with _ZssHomeFixture() as fx:
            priv = self._setup_home(fx)
            pub = priv.public_key()

            master = _secure_random(MASTER_KEY_SIZE)
            try:
                single_blob = build_zspy(b"print('x')\n", master, 3, pub)
            finally:
                zero_fill(bytearray(master))
            single_header = parse_zspy(single_blob)
            single_info = zspy_public_info(single_header)
            self.assertEqual(single_info["kind"], "single")

            game_dir = fx.tmpdir / "game"
            game_dir.mkdir()
            (game_dir / "main.py").write_text("print('x')\n", encoding="utf-8")
            arc_blob, _ = _arc_build_archive(
                py_path=fx.tmpdir / "loader.py",
                entry="main.py",
                name="game",
                files_list=None,
                n_layers=3,
                recipient_pub=pub,
            )
            arc_header = parse_zspy(arc_blob)
            arc_info = zspy_public_info(arc_header)
            self.assertEqual(arc_info["kind"], "archive")



import secrets as _share_secrets
import string as _share_string
import subprocess as _share_subprocess
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC as _share_PBKDF2HMAC

_SHARE_PASSWORD_INFO = b"zss:share:v1"
_SHARE_PBKDF2_ITERATIONS = 600000
_SHARE_PASSWORD_LEN = 16


_SHARE_MINI_ENGINE_CODE = '''#!/usr/bin/env python3
"""ZSS shared bundle. Password required. Built with ZSS __ZSS_VERSION__."""
import os, sys, json, zlib, struct, base64, hashlib, tempfile, runpy, atexit, shutil, inspect, getpass, warnings
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Suppress getpass warning when stdin is not a TTY (e.g. piped password)
warnings.filterwarnings("ignore", message=".*Can not control echo.*")
warnings.filterwarnings("ignore", message=".*Password input may be echoed.*")


class _ZssShareError(Exception):
    pass


_MAGIC = bytes([90, 83, 83, 80, 89, 1, 0, 0])
_NONCE_SIZE = 12
_TAG_SIZE = 16
_KEY_SIZE = 32
_FILE_SALT_SIZE = 16
_INFO_LAYER_PREFIX = b"zss:layer:"
_INFO_ARCHIVE_OUTER = b"zss:archive-outer:v1"
_ARCHIVE_AAD_PREFIX = b"zss:archive:v1|salt="
_PASSWORD_INFO = b"zss:share:v1"
_PBKDF2_ITERATIONS = 600000

_cached_master = None


def _b64d(s):
    return base64.b64decode(s.encode("ascii"))


def _b64e(b):
    return base64.b64encode(b).decode("ascii")


def _sha256(b):
    return hashlib.sha256(b).digest()


def _hkdf(master, salt, info, length=32):
    if length <= 0 or length > 255 * 32:
        raise _ZssShareError("bad hkdf length")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(master)


def _layer_aad(salt, idx, total):
    return b"zss:layer-aad:v1|salt=" + salt + b"|i=" + str(idx).encode() + b"|n=" + str(total).encode()


def _aead_decrypt(key, nonce, ct_with_tag, aad=b""):
    if len(key) != _KEY_SIZE:
        raise _ZssShareError("bad key size")
    if len(nonce) != _NONCE_SIZE:
        raise _ZssShareError("bad nonce size")
    if len(ct_with_tag) < _TAG_SIZE:
        raise _ZssShareError("ciphertext too short")
    aead = ChaCha20Poly1305(key)
    try:
        return aead.decrypt(nonce, ct_with_tag, aad)
    except InvalidTag:
        raise _ZssShareError("AEAD tag verification failed")


def _derive_layer_keys(master, n, salt):
    keys = []
    for i in range(1, n + 1):
        info = _INFO_LAYER_PREFIX + str(i).encode()
        keys.append(_hkdf(master, salt, info, _KEY_SIZE))
    return keys


def _decrypt_layers(ciphertext, nonces, tags, master, n, salt):
    keys = _derive_layer_keys(master, n, salt)
    current = ciphertext
    for i in range(n - 1, -1, -1):
        aad = _layer_aad(salt, i + 1, n)
        ct_with_tag = current + tags[i]
        try:
            current = _aead_decrypt(keys[i], nonces[i], ct_with_tag, aad)
        except _ZssShareError:
            raise _ZssShareError(f"layer {i+1}/{n} tag verification failed")
    return current


def _parse_shared_zspy(data):
    if len(data) < 14:
        raise _ZssShareError("file too short for header prefix")
    if data[:8] != _MAGIC:
        raise _ZssShareError("bad magic - not a .zspy")
    n_layers = data[10]
    reserved = data[11:14]
    if reserved[0] not in (2, 3):
        raise _ZssShareError(f"not a shared .zspy (reserved[0]={reserved[0]})")
    is_archive = (reserved[0] == 3)
    pos = 14
    if len(data) < pos + 16 + 32 + 8 + 1:
        raise _ZssShareError("truncated: missing salt/hash/ts/verlen")
    file_salt = data[pos:pos+16]; pos += 16
    orig_sha256 = data[pos:pos+32]; pos += 32
    timestamp = struct.unpack("<Q", data[pos:pos+8])[0]; pos += 8
    ver_len = data[pos]; pos += 1
    if len(data) < pos + ver_len + 4:
        raise _ZssShareError("truncated: missing version or ct_len")
    zss_version = data[pos:pos+ver_len].decode("utf-8", errors="replace")
    pos += ver_len
    ct_len = struct.unpack("<I", data[pos:pos+4])[0]; pos += 4
    if len(data) < pos + ct_len:
        raise _ZssShareError(f"truncated: ct says {ct_len} bytes, only {len(data)-pos} left")
    ct_payload = data[pos:pos+ct_len]
    if is_archive:
        if len(ct_payload) < 12:
            raise _ZssShareError("archive ct too short for outer nonce")
        outer_nonce = ct_payload[:12]
        outer_ct = ct_payload[12:]
        return {"is_archive": True, "n_layers": n_layers, "file_salt": file_salt,
                "orig_sha256": orig_sha256, "outer_nonce": outer_nonce,
                "outer_ct": outer_ct, "zss_version": zss_version}
    nonces_size = 12 * n_layers
    tags_size = 16 * n_layers
    if len(ct_payload) < nonces_size + tags_size:
        raise _ZssShareError("truncated: missing layer nonces/tags")
    layer_nonces = [ct_payload[i*12:(i+1)*12] for i in range(n_layers)]
    layer_tags = [ct_payload[nonces_size + i*16: nonces_size + (i+1)*16] for i in range(n_layers)]
    ciphertext = ct_payload[nonces_size + tags_size:]
    return {"is_archive": False, "n_layers": n_layers, "file_salt": file_salt,
            "orig_sha256": orig_sha256, "layer_nonces": layer_nonces,
            "layer_tags": layer_tags, "ciphertext": ciphertext,
            "zss_version": zss_version}


def _get_password_master():
    global _cached_master
    if _cached_master is not None:
        return _cached_master
    try:
        pw = getpass.getpass("ZSS password: ")
    except EOFError:
        raise _ZssShareError("no password entered (EOF)")
    if not pw:
        raise _ZssShareError("no password entered")
    salt = _b64d(EMBEDDED_PASSWORD_SALT)
    if len(salt) != 16:
        raise _ZssShareError("bad embedded password salt")
    nonce = _b64d(EMBEDDED_PASSWORD_NONCE)
    if len(nonce) != 12:
        raise _ZssShareError("bad embedded password nonce")
    wrapped = _b64d(EMBEDDED_WRAPPED_MASTER)
    if len(wrapped) != 48:
        raise _ZssShareError("bad embedded wrapped master")
    pbkdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=_PBKDF2_ITERATIONS)
    wrap_key = pbkdf.derive(pw.encode("utf-8"))
    aead = ChaCha20Poly1305(wrap_key)
    try:
        master = aead.decrypt(nonce, wrapped, _PASSWORD_INFO)
    except InvalidTag:
        raise _ZssShareError("wrong password (or corrupt bundle)")
    _cached_master = master
    return master


def _decrypt_shared_zspy(name):
    if name not in EMBEDDED_ZSPY:
        raise _ZssShareError(f"unknown embedded zspy: {name}")
    data = _b64d(EMBEDDED_ZSPY[name])
    header = _parse_shared_zspy(data)
    master = _get_password_master()
    if header["is_archive"]:
        outer_key = _hkdf(master, header["file_salt"], _INFO_ARCHIVE_OUTER, _KEY_SIZE)
        aad = _ARCHIVE_AAD_PREFIX + header["file_salt"]
        try:
            compressed = _aead_decrypt(outer_key, header["outer_nonce"], header["outer_ct"], aad)
        finally:
            outer_key = bytes(32)
        try:
            manifest_bytes = zlib.decompress(compressed)
        except zlib.error as e:
            raise _ZssShareError(f"zlib decompress failed: {e}")
        if _sha256(manifest_bytes) != header["orig_sha256"]:
            raise _ZssShareError("archive manifest hash mismatch")
        return header, manifest_bytes
    plaintext = _decrypt_layers(
        header["ciphertext"], header["layer_nonces"], header["layer_tags"],
        master, header["n_layers"], header["file_salt"])
    if _sha256(plaintext) != header["orig_sha256"]:
        raise _ZssShareError("plaintext hash mismatch - corrupt")
    return header, plaintext


def _zss_embedded_load(name):
    header, plaintext = _decrypt_shared_zspy(name)
    if header["is_archive"]:
        raise _ZssShareError(f"{name} is an archive; use load_dir() instead")
    try:
        code_str = plaintext.decode("utf-8")
    except UnicodeDecodeError as e:
        raise _ZssShareError(f"decrypted source is not UTF-8: {e}")
    frame = inspect.currentframe().f_back
    if frame is None:
        raise _ZssShareError("cannot determine caller frame")
    caller_globals = frame.f_globals
    code = compile(code_str, name, "exec")
    exec(code, caller_globals)


def _zss_embedded_load_dir(name):
    header, manifest_bytes = _decrypt_shared_zspy(name)
    if not header["is_archive"]:
        raise _ZssShareError(f"{name} is single-file; use load() instead")
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise _ZssShareError(f"manifest is not valid JSON: {e}")
    if manifest.get("schema") != 1:
        raise _ZssShareError(f"unsupported manifest schema: {manifest.get('schema')}")
    entry = manifest["entry"]
    files_b64 = manifest["files"]
    file_hashes = manifest["file_hashes"]
    master = _get_password_master()
    n_layers = header["n_layers"]
    tmpdir = Path(tempfile.mkdtemp(prefix="zss-share-"))
    try:
        for fname, blob_b64 in files_b64.items():
            blob = _b64d(blob_b64)
            min_len = _FILE_SALT_SIZE + 12 * n_layers + 16 * n_layers
            if len(blob) < min_len:
                raise _ZssShareError(f"file blob too short: {fname}")
            pos = 0
            salt = blob[pos:pos+16]; pos += 16
            nonces = []
            for _ in range(n_layers):
                nonces.append(blob[pos:pos+12]); pos += 12
            tags = []
            for _ in range(n_layers):
                tags.append(blob[pos:pos+16]); pos += 16
            ct = blob[pos:]
            plaintext = _decrypt_layers(ct, nonces, tags, master, n_layers, salt)
            expected = file_hashes.get(fname)
            if expected is None:
                raise _ZssShareError(f"missing hash for {fname}")
            if _sha256(plaintext).hex() != expected:
                raise _ZssShareError(f"hash mismatch for {fname}")
            fpath = tmpdir / fname
            fpath.parent.mkdir(parents=True, exist_ok=True)
            fpath.write_bytes(plaintext)
    except Exception:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise
    atexit.register(shutil.rmtree, str(tmpdir), True)
    entry_path = tmpdir / entry
    if not entry_path.is_file():
        raise _ZssShareError(f"entry not found in archive: {entry}")
    if str(tmpdir) not in sys.path:
        sys.path.insert(0, str(tmpdir))
    sys.argv = [str(entry_path)] + sys.argv[1:]
    runpy.run_path(str(entry_path), run_name="__main__")


# EMBEDDED constants (filled at share time)
EMBEDDED_ZSPY = __EMBEDDED_ZSPY__
EMBEDDED_PASSWORD_SALT = "__EMBEDDED_PASSWORD_SALT__"
EMBEDDED_PASSWORD_NONCE = "__EMBEDDED_PASSWORD_NONCE__"
EMBEDDED_WRAPPED_MASTER = "__EMBEDDED_WRAPPED_MASTER__"

load = _zss_embedded_load
load_dir = _zss_embedded_load_dir

# === original user code below ===
'''



def _share_find_zspy_refs(source: str) -> dict:
    refs: dict[str, str] = {}

    try:
        tree = _v050_ast.parse(source)
        for node in _v050_ast.walk(tree):
            if not isinstance(node, _v050_ast.Call):
                continue
            func = node.func
            kind = None
            if (
                isinstance(func, _v050_ast.Attribute)
                and isinstance(func.value, _v050_ast.Name)
                and func.value.id == "zss"
            ):
                if func.attr == "load":
                    kind = "single"
                elif func.attr == "load_dir":
                    kind = "archive"
            elif isinstance(func, _v050_ast.Name):
                if func.id == "load":
                    kind = "single"
                elif func.id == "load_dir":
                    kind = "archive"
            if kind is None:
                continue
            if not node.args:
                continue
            try:
                name = _v050_ast.literal_eval(node.args[0])
            except Exception:
                continue
            if not isinstance(name, str) or not name.endswith(".zspy"):
                continue
            if name not in refs:
                refs[name] = kind
        if refs:
            return refs
    except SyntaxError:
        pass

    for m in re.finditer(r'(?<![\w.])load_dir\(\s*["\']([^"\']+\.zspy)["\']\s*\)', source):
        name = m.group(1)
        if name not in refs:
            refs[name] = "archive"
    for m in re.finditer(r'(?<![\w.])load\(\s*["\']([^"\']+\.zspy)["\']\s*\)', source):
        name = m.group(1)
        if name not in refs:
            refs[name] = "single"
    return refs


def _share_get_password(args) -> str:
    if args.password is not None:
        return args.password
    if args.password_file is not None:
        data = Path(args.password_file).read_text(encoding="utf-8")
        return data.strip()
    alphabet = _share_string.ascii_letters + _share_string.digits
    return "".join(_share_secrets.choice(alphabet) for _ in range(_SHARE_PASSWORD_LEN))


def _share_repack_single(plaintext: bytes, master_embedded: bytes, n_layers: int) -> bytes:
    file_salt = _secure_random(ZSSPY_FILE_SALT_SIZE)
    layered = encrypt_layers(plaintext, master_embedded, n_layers, file_salt)
    orig_hash = sha256(plaintext)

    import time
    timestamp = int(time.time())
    zss_ver_bytes = ZSS_VERSION.encode("utf-8")

    out = bytearray()
    out += ZSSPY_MAGIC
    out += struct.pack("<H", ZSSPY_FORMAT_VERSION)
    out += struct.pack("<B", n_layers)
    out += bytes([2, 0, 0])
    out += file_salt
    out += orig_hash
    out += struct.pack("<Q", timestamp)
    out += struct.pack("<B", len(zss_ver_bytes))
    out += zss_ver_bytes
    ct_payload = b"".join(layered.nonces) + b"".join(layered.tags) + layered.ciphertext
    out += struct.pack("<I", len(ct_payload))
    out += ct_payload
    return bytes(out)


def _share_repack_archive(manifest: "_ArcManifest", master_embedded: bytes, n_layers: int) -> bytes:
    files_b64: dict[str, str] = {}
    for fname, content in manifest.files.items():
        salt = _secure_random(ZSSPY_FILE_SALT_SIZE)
        layered = encrypt_layers(content, master_embedded, n_layers, salt)
        blob = bytearray()
        blob += salt
        for n in layered.nonces:
            blob += n
        for t in layered.tags:
            blob += t
        blob += layered.ciphertext
        files_b64[fname] = _b64e(bytes(blob))

    manifest_dict = {
        "schema": 1,
        "entry": manifest.entry,
        "files": files_b64,
        "file_hashes": manifest.file_hashes,
    }
    manifest_bytes = json.dumps(manifest_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")
    compressed = zlib.compress(manifest_bytes, 9)

    file_salt = _secure_random(ZSSPY_FILE_SALT_SIZE)
    outer_key = hkdf_derive(master_embedded, file_salt, _ARC_OUTER_INFO, KEY_SIZE)
    outer_nonce = _secure_random(NONCE_SIZE)
    outer_aad = _ARC_OUTER_AAD_PREFIX + file_salt
    aead = ChaCha20Poly1305(outer_key)
    outer_ct = aead.encrypt(outer_nonce, compressed, outer_aad)
    zero_fill(bytearray(outer_key))

    import time
    timestamp = int(time.time())
    zss_ver_bytes = ZSS_VERSION.encode("utf-8")

    out = bytearray()
    out += ZSSPY_MAGIC
    out += struct.pack("<H", ZSSPY_FORMAT_VERSION)
    out += struct.pack("<B", n_layers)
    out += bytes([3, 0, 0])
    out += file_salt
    out += sha256(manifest_bytes)
    out += struct.pack("<Q", timestamp)
    out += struct.pack("<B", len(zss_ver_bytes))
    out += zss_ver_bytes
    ct_payload = outer_nonce + outer_ct
    out += struct.pack("<I", len(ct_payload))
    out += ct_payload
    return bytes(out)


def cmd_share(args: argparse.Namespace) -> int:
    _zss_home_env_override()
    py_path = Path(args.file).expanduser().resolve()
    if not py_path.is_file():
        _eprint(f"error: source file not found: {py_path}")
        return 1
    if py_path.suffix != ".py":
        _eprint(f"error: expected a .py file, got {py_path.name}")
        return 1

    try:
        source = py_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        _eprint(f"error: source is not valid UTF-8: {e}")
        return 1

    refs = _share_find_zspy_refs(source)
    if not refs:
        _eprint(f"error: no load()/load_dir() stubs found in {py_path}")
        _eprint("share expects a packed .py. Run `zss pack` first.")
        return 1

    password = _share_get_password(args)
    if not password:
        _eprint("error: empty password")
        return 1

    try:
        priv = load_private_key(PRIVATE_KEY_PATH)
    except ZssKeyError as e:
        _eprint(f"error: {e}")
        return 1

    master_embedded = _secure_random(MASTER_KEY_SIZE)
    embedded_zspy: dict[str, str] = {}

    for name, kind in refs.items():
        zspy_path = py_path.parent / name
        if not zspy_path.exists():
            _eprint(f"error: {name} not found at {zspy_path}")
            return 1
        data = read_bytes(zspy_path)
        try:
            header = parse_zspy(data)
        except ZssFormatError as e:
            _eprint(f"error: cannot parse {name}: {e}")
            return 1

        is_archive = (not header.layer_nonces and not header.layer_tags)

        try:
            if is_archive:
                manifest = _arc_decrypt_archive(header, priv)
                blob = _share_repack_archive(manifest, master_embedded, header.n_layers)
            else:
                plaintext = decrypt_zspy(header, priv)
                blob = _share_repack_single(plaintext, master_embedded, header.n_layers)
        except (ZssCryptoError, ZssFormatError) as e:
            _eprint(f"error: cannot decrypt {name}: {e}")
            return 1

        embedded_zspy[name] = _b64e(blob)

    password_salt = _secure_random(ZSSPY_FILE_SALT_SIZE)
    password_nonce = _secure_random(NONCE_SIZE)
    pbkdf = _share_PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=password_salt,
        iterations=_SHARE_PBKDF2_ITERATIONS,
    )
    wrap_key = pbkdf.derive(password.encode("utf-8"))
    aead = ChaCha20Poly1305(wrap_key)
    wrapped_master = aead.encrypt(password_nonce, master_embedded, _SHARE_PASSWORD_INFO)
    zero_fill(bytearray(wrap_key))
    zero_fill(bytearray(master_embedded))

    if len(wrapped_master) != MASTER_KEY_SIZE + TAG_SIZE:
        _eprint("error: internal — wrapped master has unexpected length")
        return 1

    modified = source.replace("from zss import load_dir", "load_dir = _zss_embedded_load_dir")
    modified = modified.replace("from zss import load", "load = _zss_embedded_load")

    out_path = Path(args.out) if args.out else py_path.with_suffix(".share.py")
    content = _SHARE_MINI_ENGINE_CODE
    content = content.replace("__ZSS_VERSION__", ZSS_VERSION)
    content = content.replace("__EMBEDDED_ZSPY__", json.dumps(embedded_zspy))
    content = content.replace("__EMBEDDED_PASSWORD_SALT__", _b64e(password_salt))
    content = content.replace("__EMBEDDED_PASSWORD_NONCE__", _b64e(password_nonce))
    content = content.replace("__EMBEDDED_WRAPPED_MASTER__", _b64e(wrapped_master))
    content += modified

    try:
        atomic_write_text(out_path, content, mode=0o644)
    except OSError as e:
        _eprint(f"error: cannot write {out_path}: {e}")
        return 1

    _print(f"shared bundle created: {out_path}")
    _print(f"  embedded .zspy: {len(embedded_zspy)}")
    for name in embedded_zspy:
        _print(f"    - {name}")
    _print(f"  total size:     {out_path.stat().st_size} bytes")
    _print(f"  password:       {password}")
    _print(f"")
    _print(f"  WARNING: transmit the password via a SEPARATE channel.")
    _print(f"  The password is NOT stored in {out_path}.")
    _print(f"  Without the password, the bundle is unreadable.")
    return 0



_share_orig_build_arg_parser = build_arg_parser


def build_arg_parser() -> argparse.ArgumentParser:
    parser = _share_orig_build_arg_parser()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            p_share = action.add_parser(
                "share",
                help="bundle .py + .zspy into a single self-contained file",
            )
            p_share.add_argument("file", help="packed .py with load()/load_dir() stubs")
            p_share.add_argument("--out", default=None,
                                 help="output path (default: <file>.share.py)")
            p_share.add_argument("--password", default=None,
                                 help="password (default: random 16 chars)")
            p_share.add_argument("--password-file", default=None,
                                 help="read password from file")
            p_share.set_defaults(func=cmd_share)
            break
    return parser



class TestShare(unittest.TestCase):

    def _setup_home(self, fx):
        _ensure_dir(KEYS_DIR, mode=0o700)
        priv, pub = generate_keypair()
        save_private_key(priv, PRIVATE_KEY_PATH)
        save_public_key(pub, PUBLIC_KEY_PATH)
        init_zson(priv, ZSON_PATH)
        return priv

    def test_share_find_zspy_refs_single(self):
        src = 'from zss import load; load("a.zspy")\nprint("hi")\n'
        refs = _share_find_zspy_refs(src)
        self.assertEqual(refs, {"a.zspy": "single"})

    def test_share_find_zspy_refs_archive(self):
        src = 'from zss import load_dir\nload_dir("game.zspy")\n'
        refs = _share_find_zspy_refs(src)
        self.assertEqual(refs, {"game.zspy": "archive"})

    def test_share_find_zspy_refs_mixed(self):
        src = (
            'from zss import load; load("a.zspy")\n'
            'from zss import load_dir\nload_dir("b.zspy")\n'
        )
        refs = _share_find_zspy_refs(src)
        self.assertEqual(refs, {"a.zspy": "single", "b.zspy": "archive"})

    def test_share_find_zspy_refs_none(self):
        src = 'print("hello")\n'
        refs = _share_find_zspy_refs(src)
        self.assertEqual(refs, {})

    def test_share_find_zspy_refs_ignores_substring(self):
        src = "myload('x.zspy')\n"
        refs = _share_find_zspy_refs(src)
        self.assertEqual(refs, {})

    def test_share_find_zspy_refs_zss_dot_load(self):
        src = 'import zss\nzss.load("x.zspy")\n'
        refs = _share_find_zspy_refs(src)
        self.assertEqual(refs, {"x.zspy": "single"})

    def test_share_find_zspy_refs_zss_dot_load_dir(self):
        src = 'import zss\nzss.load_dir("arc.zspy")\n'
        refs = _share_find_zspy_refs(src)
        self.assertEqual(refs, {"arc.zspy": "archive"})

    def test_share_find_zspy_refs_fstring_skipped(self):
        src = 'name = "x.zspy"\nzss.load(f"{name}")\n'
        refs = _share_find_zspy_refs(src)
        self.assertEqual(refs, {})

    def test_share_find_zspy_refs_variable_skipped(self):
        src = 'name = "x.zspy"\nzss.load(name)\n'
        refs = _share_find_zspy_refs(src)
        self.assertEqual(refs, {})

    def test_share_creates_file(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            src_path = fx.tmpdir / "app.py"
            src_path.write_text(
                "#<zss>{write_to!secret.zspy\n"
                "VALUE = 'shared-secret'\n"
                "#<zss>{closing!write!secret.zspy\n"
                "print(VALUE)\n",
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(src_path), layers=3, in_place=True, no_clobber=False,
            )
            self.assertEqual(cmd_pack(pack_args), 0)

            out_path = fx.tmpdir / "app.share.py"
            share_args = argparse.Namespace(
                file=str(src_path), out=str(out_path),
                password="testpass123", password_file=None,
            )
            self.assertEqual(cmd_share(share_args), 0)
            self.assertTrue(out_path.exists())
            content = out_path.read_text(encoding="utf-8")
            self.assertIn("EMBEDDED_ZSPY", content)
            self.assertIn("secret.zspy", content)
            self.assertIn("_zss_embedded_load", content)

    def test_share_runs_without_zss(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            src_path = fx.tmpdir / "app.py"
            src_path.write_text(
                "#<zss>{write_to!secret.zspy\n"
                "import sys\nsys.stdout.write('shared-ok\\n')\n"
                "#<zss>{closing!write!secret.zspy\n",
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(src_path), layers=3, in_place=True, no_clobber=False,
            )
            self.assertEqual(cmd_pack(pack_args), 0)

            out_path = fx.tmpdir / "app.share.py"
            share_args = argparse.Namespace(
                file=str(src_path), out=str(out_path),
                password="testpass123", password_file=None,
            )
            self.assertEqual(cmd_share(share_args), 0)

            result = _share_subprocess.run(
                [sys.executable, str(out_path)],
                input="testpass123\n",
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(result.returncode, 0,
                             f"stdout={result.stdout!r} stderr={result.stderr!r}")
            self.assertIn("shared-ok", result.stdout)

    def test_share_wrong_password_fails(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            src_path = fx.tmpdir / "app.py"
            src_path.write_text(
                "#<zss>{write_to!secret.zspy\n"
                "import sys\nsys.stdout.write('should-not-appear\\n')\n"
                "#<zss>{closing!write!secret.zspy\n",
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(src_path), layers=3, in_place=True, no_clobber=False,
            )
            self.assertEqual(cmd_pack(pack_args), 0)

            out_path = fx.tmpdir / "app.share.py"
            share_args = argparse.Namespace(
                file=str(src_path), out=str(out_path),
                password="correct-pass", password_file=None,
            )
            self.assertEqual(cmd_share(share_args), 0)

            result = _share_subprocess.run(
                [sys.executable, str(out_path)],
                input="wrong-pass\n",
                capture_output=True, text=True, timeout=60,
            )
            self.assertNotEqual(result.returncode, 0)
            combined = result.stdout + result.stderr
            self.assertIn("wrong password", combined.lower())

    def test_share_no_password_fails(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            src_path = fx.tmpdir / "app.py"
            src_path.write_text(
                "#<zss>{write_to!secret.zspy\n"
                "import sys\nsys.stdout.write('should-not-appear\\n')\n"
                "#<zss>{closing!write!secret.zspy\n",
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(src_path), layers=3, in_place=True, no_clobber=False,
            )
            self.assertEqual(cmd_pack(pack_args), 0)

            out_path = fx.tmpdir / "app.share.py"
            share_args = argparse.Namespace(
                file=str(src_path), out=str(out_path),
                password="somepass", password_file=None,
            )
            self.assertEqual(cmd_share(share_args), 0)

            result = _share_subprocess.run(
                [sys.executable, str(out_path)],
                input="",
                capture_output=True, text=True, timeout=60,
            )
            self.assertNotEqual(result.returncode, 0)

    def test_share_archive_mode(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            game_dir = fx.tmpdir / "game"
            game_dir.mkdir()
            (game_dir / "main.py").write_text(
                "import sys\nsys.stdout.write('shared-arc-ok\\n')\nsys.exit(0)\n",
                encoding="utf-8",
            )
            loader_path = fx.tmpdir / "loader.py"
            loader_path.write_text(
                "#dir-{main.py}-directory!game!\n"
                "#on{main.py}-import--files{}\n",
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(loader_path), layers=3, in_place=True, no_clobber=False,
            )
            self.assertEqual(cmd_pack(pack_args), 0)

            out_path = fx.tmpdir / "loader.share.py"
            share_args = argparse.Namespace(
                file=str(loader_path), out=str(out_path),
                password="arcpass", password_file=None,
            )
            self.assertEqual(cmd_share(share_args), 0)

            result = _share_subprocess.run(
                [sys.executable, str(out_path)],
                input="arcpass\n",
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(result.returncode, 0,
                             f"stdout={result.stdout!r} stderr={result.stderr!r}")
            self.assertIn("shared-arc-ok", result.stdout)

    def test_share_does_not_embed_private_key(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            src_path = fx.tmpdir / "app.py"
            src_path.write_text(
                "#<zss>{write_to!secret.zspy\n"
                "X = 1\n"
                "#<zss>{closing!write!secret.zspy\n",
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(src_path), layers=3, in_place=True, no_clobber=False,
            )
            self.assertEqual(cmd_pack(pack_args), 0)

            out_path = fx.tmpdir / "app.share.py"
            share_args = argparse.Namespace(
                file=str(src_path), out=str(out_path),
                password="testpass", password_file=None,
            )
            self.assertEqual(cmd_share(share_args), 0)

            content = out_path.read_text(encoding="utf-8")

            priv_bytes = read_bytes(PRIVATE_KEY_PATH)
            priv_b64 = _b64e(priv_bytes)
            self.assertNotIn(priv_b64, content)
            self.assertNotIn(repr(priv_bytes), content)

            self.assertNotIn("master.x25519", content)
            self.assertNotIn("eph_pubkey", content)

            self.assertNotIn("from zss import", content)

    def test_share_old_single_mode_works(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            src_path = fx.tmpdir / "old.py"
            src_path.write_text(
                "#<zss>{write_to!old.zspy\n"
                "import sys\nsys.stdout.write('old-share-ok\\n')\n"
                "#<zss>{closing!write!old.zspy\n",
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(src_path), layers=3, in_place=True, no_clobber=False,
            )
            self.assertEqual(cmd_pack(pack_args), 0)

            out_path = fx.tmpdir / "old.share.py"
            share_args = argparse.Namespace(
                file=str(src_path), out=str(out_path),
                password="oldpass", password_file=None,
            )
            self.assertEqual(cmd_share(share_args), 0)

            result = _share_subprocess.run(
                [sys.executable, str(out_path)],
                input="oldpass\n",
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(result.returncode, 0,
                             f"stdout={result.stdout!r} stderr={result.stderr!r}")
            self.assertIn("old-share-ok", result.stdout)

    def test_share_password_file(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            src_path = fx.tmpdir / "app.py"
            src_path.write_text(
                "#<zss>{write_to!secret.zspy\n"
                "import sys\nsys.stdout.write('pwfile-ok\\n')\n"
                "#<zss>{closing!write!secret.zspy\n",
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(src_path), layers=3, in_place=True, no_clobber=False,
            )
            self.assertEqual(cmd_pack(pack_args), 0)

            pw_file = fx.tmpdir / "pw.txt"
            pw_file.write_text("filepass\n", encoding="utf-8")

            out_path = fx.tmpdir / "app.share.py"
            share_args = argparse.Namespace(
                file=str(src_path), out=str(out_path),
                password=None, password_file=str(pw_file),
            )
            self.assertEqual(cmd_share(share_args), 0)

            result = _share_subprocess.run(
                [sys.executable, str(out_path)],
                input="filepass\n",
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(result.returncode, 0,
                             f"stdout={result.stdout!r} stderr={result.stderr!r}")
            self.assertIn("pwfile-ok", result.stdout)



import ast as _v050_ast
import functools as _v050_functools
import textwrap as _v050_textwrap
import threading as _v050_threading
import types as _v050_types
from contextlib import contextmanager as _v050_contextmanager


_LOAD_CACHE: dict = {}
_IMPORT_CACHE: dict = {}
_SECRET_CACHE: dict = {}
_CONST_CACHE: dict = {}
_STATE_CACHE: Optional[dict] = None
_STATE_DIRTY: bool = False
_CACHE_LOCK = _v050_threading.RLock()
_STATE_LOCK = _v050_threading.RLock()



def _detect_python_env() -> dict:
    import platform
    return {
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "machine": platform.machine(),
        "is_termux": "com.termux" in os.environ.get("PREFIX", ""),
        "is_windows": sys.platform.startswith("win"),
    }


def _verify_zspy(path, priv) -> tuple:
    try:
        data = read_bytes(path)
        header = parse_zspy(data)
        if not header.layer_nonces and not header.layer_tags:
            return False, "archive format, use _verify_archive"
        decrypt_zspy(header, priv)
        return True, f"ok ({header.n_layers} layers, {len(header.ciphertext)}B ct)"
    except ZssError as e:
        return False, str(e)
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def _verify_archive(path, priv) -> tuple:
    try:
        data = read_bytes(path)
        header = parse_zspy(data)
        if header.layer_nonces or header.layer_tags:
            return False, "single-file format, use _verify_zspy"
        manifest = _arc_decrypt_archive(header, priv)
        return True, f"ok ({len(manifest.files)} files, entry={manifest.entry})"
    except ZssError as e:
        return False, str(e)
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def _read_password(args) -> str:
    if getattr(args, "password", None) is not None:
        return args.password
    if getattr(args, "password_file", None) is not None:
        return Path(args.password_file).read_text(encoding="utf-8").strip()
    import secrets as _sec
    import string as _str
    alphabet = _str.ascii_letters + _str.digits
    return "".join(_sec.choice(alphabet) for _ in range(16))


def _require_confirmation(prompt: str, expected: str = "YES") -> bool:
    try:
        response = input(prompt)
    except (EOFError, KeyboardInterrupt):
        return False
    return response.strip() == expected


def _check_key_perms(path) -> bool:
    try:
        st = os.stat(path)
        return (st.st_mode & 0o077) == 0
    except OSError:
        return False


def _warn_if_bak_exists(py_path) -> None:
    bak = Path(py_path).with_suffix(Path(py_path).suffix + ".bak")
    if bak.exists():
        sys.stderr.write(f"warning: {bak.name} exists (previous pack backup)\n")


def _cache_get(cache: dict, key: str, mtime: float):
    entry = cache.get(key)
    if entry is None:
        return None
    if not isinstance(entry, tuple) or len(entry) != 2:
        return None
    cached_mtime, value = entry
    if cached_mtime != mtime:
        return None
    return value


def _cache_set(cache: dict, key: str, mtime: float, value) -> None:
    cache[key] = (mtime, value)


def _is_zss_call(node, name: str) -> bool:
    return (
        isinstance(node, _v050_ast.Call)
        and isinstance(node.func, _v050_ast.Attribute)
        and isinstance(node.func.value, _v050_ast.Name)
        and node.func.value.id == "zss"
        and node.func.attr == name
    )


def _get_indent(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def _extract_with_body(source: str, node) -> str:
    lines = source.splitlines(keepends=True)
    body_start = node.body[0].lineno
    body_end = node.body[-1].end_lineno
    body = "".join(lines[body_start - 1: body_end])
    return _v050_textwrap.dedent(body)


def _extract_function_body(source: str, node) -> str:
    lines = source.splitlines(keepends=True)
    body_start = node.body[0].lineno
    body_end = node.body[-1].end_lineno
    body = "".join(lines[body_start - 1: body_end])
    return _v050_textwrap.dedent(body)


def _extract_function_full(source: str, node) -> str:
    lines = source.splitlines(keepends=True)
    start = node.lineno
    end = node.end_lineno
    if node.decorator_list:
        start = min(d.lineno for d in node.decorator_list)
    return "".join(lines[start - 1: end])


def _ast_find_zss_calls(tree) -> dict:
    result = {"with_blocks": [], "secret_funcs": [], "const_assigns": []}
    for node in _v050_ast.walk(tree):
        if isinstance(node, _v050_ast.With):
            for item in node.items:
                if _is_zss_call(item.context_expr, "block"):
                    ctx = item.context_expr
                    filename = _v050_ast.literal_eval(ctx.args[0]) if ctx.args else None
                    layers = None
                    for kw in ctx.keywords:
                        if kw.arg == "layers":
                            layers = _v050_ast.literal_eval(kw.value)
                    result["with_blocks"].append({
                        "node": node, "filename": filename, "layers": layers,
                        "ctx": ctx,
                    })
                    break
        elif isinstance(node, (_v050_ast.FunctionDef, _v050_ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                if _is_zss_call(dec, "secret"):
                    filename = _v050_ast.literal_eval(dec.args[0]) if dec.args else None
                    result["secret_funcs"].append({
                        "node": node, "filename": filename, "dec": dec,
                        "func_name": node.name,
                        "is_async": isinstance(node, _v050_ast.AsyncFunctionDef),
                    })
                    break
        elif isinstance(node, _v050_ast.Assign):
            if (
                len(node.targets) == 1
                and isinstance(node.targets[0], _v050_ast.Name)
                and _is_zss_call(node.value, "const")
            ):
                call = node.value
                if len(call.args) >= 3:
                    try:
                        file = _v050_ast.literal_eval(call.args[0])
                        key = _v050_ast.literal_eval(call.args[1])
                        value = _v050_ast.literal_eval(call.args[2])
                    except Exception:
                        continue
                    result["const_assigns"].append({
                        "node": node, "file": file, "key": key,
                        "value": value, "target": node.targets[0].id,
                    })
    return result


def _ast_process_source(source: str):
    try:
        tree = _v050_ast.parse(source)
    except SyntaxError:
        return source, [], [], []

    calls = _ast_find_zss_calls(tree)
    lines = source.splitlines(keepends=True)
    replacements = []

    for wb in calls["with_blocks"]:
        node = wb["node"]
        filename = wb["filename"]
        if node.col_offset != 0:
            raise ZssParseError(
                f"with zss.block must be at module level, not inside a function/class "
                f"(line {node.lineno}). Move the block to the top level of the .py file."
            )
        body = _extract_with_body(source, node)
        wb["body"] = body
        indent = _get_indent(lines[node.lineno - 1])
        stub = f'{indent}from zss import load; load("{filename}")\n'
        replacements.append((node.lineno, node.end_lineno, stub))

    for sf in calls["secret_funcs"]:
        node = sf["node"]
        dec = sf["dec"]
        filename = sf["filename"]
        body_source = _extract_function_body(source, node)
        sf["body_source"] = body_source
        sf["func_source"] = body_source

        start_line = min(d.lineno for d in node.decorator_list)
        end_line = node.end_lineno
        dec_indent = _get_indent(lines[dec.lineno - 1])
        def_indent = _get_indent(lines[node.lineno - 1])
        body_indent = def_indent + "    "
        new_lines = []
        for i in range(start_line - 1, end_line):
            line_no = i + 1
            if line_no == dec.lineno:
                new_lines.append(f'{dec_indent}@zss._decrypt_secret("{filename}")\n')
            elif line_no < node.lineno:
                new_lines.append(lines[i])
            elif line_no == node.lineno:
                new_lines.append(lines[i])
            elif line_no == node.body[0].lineno:
                new_lines.append(f"{body_indent}pass\n")
        replacements.append((start_line, end_line, "".join(new_lines)))

    for ca in calls["const_assigns"]:
        node = ca["node"]
        indent = _get_indent(lines[node.lineno - 1])
        target = ca["target"]
        file = ca["file"]
        key = ca["key"]
        stub = f'{indent}{target} = zss._decrypt_const("{file}", "{key}")\n'
        replacements.append((node.lineno, node.end_lineno, stub))

    replacements.sort(key=lambda r: -r[0])
    new_lines = list(lines)
    for start, end, new_text in replacements:
        new_lines[start - 1: end] = [new_text]

    rewritten = "".join(new_lines)
    return rewritten, calls["with_blocks"], calls["secret_funcs"], calls["const_assigns"]



def _state_load() -> dict:
    global _STATE_CACHE
    with _STATE_LOCK:
        if _STATE_CACHE is not None:
            return _STATE_CACHE
        try:
            priv = load_private_key(PRIVATE_KEY_PATH)
            payload = load_zson(priv, ZSON_PATH)
            _STATE_CACHE = payload.get("state", {})
        except (ZssKeyError, ZssConfigError):
            _STATE_CACHE = {}
        return _STATE_CACHE


def state_get(namespace: str, key: str, default=None):
    with _STATE_LOCK:
        cache = _state_load()
        return cache.get(namespace, {}).get(key, default)


def state_set(namespace: str, key: str, value) -> None:
    global _STATE_DIRTY
    with _STATE_LOCK:
        cache = _state_load()
        cache.setdefault(namespace, {})[key] = value
        _STATE_DIRTY = True


def state_save() -> None:
    global _STATE_DIRTY
    with _STATE_LOCK:
        if not _STATE_DIRTY:
            return
        if not zson_exists(ZSON_PATH):
            _STATE_DIRTY = False
            return
        try:
            priv = load_private_key(PRIVATE_KEY_PATH)
            payload = load_zson(priv, ZSON_PATH)
            payload["state"] = _STATE_CACHE
            save_zson(payload, priv, ZSON_PATH)
            _STATE_DIRTY = False
        except ZssKeyError:
            _STATE_DIRTY = False
        except ZssConfigError as e:
            sys.stderr.write(f"warning: cannot save state: {e}\n")


def state_reset(namespace: str = None) -> None:
    global _STATE_DIRTY
    with _STATE_LOCK:
        cache = _state_load()
        if namespace is None:
            cache.clear()
        else:
            cache.pop(namespace, None)
        _STATE_DIRTY = True



@_v050_contextmanager
def block(name: str, layers: int = None):
    yield


def import_(name: str, *, _caller_file: Optional[str] = None):
    if _caller_file is None:
        caller = sys._getframe(1)
        caller_file = caller.f_globals.get("__file__", "")
    else:
        caller_file = _caller_file
    if not caller_file:
        raise ZssError("import_() called without __file__ in caller globals")
    zspy_path = _resolve_zspy_path(caller_file, name)
    if not zspy_path.exists():
        raise ZssFormatError(f".zspy not found: {zspy_path}")
    mtime = zspy_path.stat().st_mtime
    cache_key = str(zspy_path)
    with _CACHE_LOCK:
        cached = _cache_get(_IMPORT_CACHE, cache_key, mtime)
    if cached is not None:
        return cached
    data = read_bytes(zspy_path)
    header = parse_zspy(data)
    priv = load_private_key()
    plaintext = decrypt_zspy(header, priv)
    mod = _v050_types.ModuleType(name)
    mod.__file__ = str(zspy_path)
    code = compile(plaintext.decode("utf-8"), str(zspy_path), "exec")
    exec(code, mod.__dict__)
    with _CACHE_LOCK:
        cached = _cache_get(_IMPORT_CACHE, cache_key, mtime)
        if cached is not None:
            return cached
        _cache_set(_IMPORT_CACHE, cache_key, mtime, mod)
    return mod


def _decrypt_secret(filename: str):
    caller_file = sys._getframe(1).f_globals.get("__file__", "")
    caller_globals = sys._getframe(1).f_globals

    def decorator(orig_func):
        cache = {"key": None, "func": None}

        import inspect as _ins
        is_async = _ins.iscoroutinefunction(orig_func)
        try:
            sig = _ins.signature(orig_func)
        except (ValueError, TypeError):
            sig = None
        param_names: list = []
        if sig is not None:
            for pname, param in sig.parameters.items():
                if param.kind in (
                    _ins.Parameter.POSITIONAL_ONLY,
                    _ins.Parameter.POSITIONAL_OR_KEYWORD,
                    _ins.Parameter.KEYWORD_ONLY,
                ):
                    param_names.append(pname)

        def _build_func():
            zspy_path = _resolve_zspy_path(caller_file, filename)
            if not zspy_path.exists():
                raise ZssFormatError(f".zspy not found: {zspy_path}")
            mtime = zspy_path.stat().st_mtime
            cache_key = (str(zspy_path), mtime)
            if cache["key"] == cache_key and cache["func"] is not None:
                return cache["func"]
            data = read_bytes(zspy_path)
            header = parse_zspy(data)
            priv = load_private_key()
            plaintext = decrypt_zspy(header, priv)
            body_source = plaintext.decode("utf-8")
            sig_str = ", ".join(param_names) if param_names else ""
            func_name = f"_zss_real_{orig_func.__name__}_{id(orig_func):x}"
            if is_async:
                func_code = f"async def {func_name}({sig_str}):\n"
            else:
                func_code = f"def {func_name}({sig_str}):\n"
            for line in body_source.splitlines():
                func_code += f"    {line}\n"
            if not body_source.strip():
                func_code += "    pass\n"
            ns = {"__builtins__": __builtins__}
            for k, v in caller_globals.items():
                if not k.startswith("__"):
                    ns.setdefault(k, v)
            exec(func_code, ns)
            found = ns.get(func_name)
            if found is None:
                raise ZssError(f"failed to build function from {filename}")
            cache["key"] = cache_key
            cache["func"] = found
            return found

        if is_async:
            @_v050_functools.wraps(orig_func)
            async def wrapper(*args, **kwargs):
                func = _build_func()
                return await func(*args, **kwargs)
        else:
            @_v050_functools.wraps(orig_func)
            def wrapper(*args, **kwargs):
                func = _build_func()
                return func(*args, **kwargs)
        return wrapper
    return decorator


def _decrypt_const(filename: str, key: str):
    caller_file = sys._getframe(1).f_globals.get("__file__", "")
    zspy_path = _resolve_zspy_path(caller_file, filename)
    if not zspy_path.exists():
        raise ZssFormatError(f".zspy not found: {zspy_path}")
    mtime = zspy_path.stat().st_mtime
    cache_key = str(zspy_path)
    with _CACHE_LOCK:
        cached = _cache_get(_CONST_CACHE, cache_key, mtime)
    if cached is not None:
        return cached.get(key)
    data = read_bytes(zspy_path)
    header = parse_zspy(data)
    priv = load_private_key()
    plaintext = decrypt_zspy(header, priv)
    try:
        d = json.loads(plaintext.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ZssFormatError(f"const file is not valid JSON: {e}") from e
    with _CACHE_LOCK:
        cached = _cache_get(_CONST_CACHE, cache_key, mtime)
        if cached is not None:
            return cached.get(key)
        _cache_set(_CONST_CACHE, cache_key, mtime, d)
    return d.get(key)


def guard() -> None:
    caller = sys._getframe(1)
    caller_file = caller.f_globals.get("__file__", "")
    if not caller_file:
        return
    py_path = Path(caller_file).resolve()
    if not py_path.exists():
        return
    try:
        priv = load_private_key()
    except ZssKeyError:
        sys.stderr.write("zss.guard: private key not available\n")
        sys.exit(1)
    stored_hash = state_get("guard", str(py_path))
    if stored_hash is not None:
        current_hash = sha256(py_path.read_bytes()).hex()
        if current_hash != stored_hash:
            sys.stderr.write(f"zss.guard: {py_path.name} modified since last pack\n")
            sys.exit(1)
    try:
        source = py_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return
    refs = _share_find_zspy_refs(source)
    try:
        old_parsed = parse_source_with_directives(source)
        for b in old_parsed.blocks:
            refs.setdefault(b.filename, "single")
    except ZssParseError:
        pass
    for name in refs:
        zspy_path = py_path.parent / name
        if not zspy_path.exists():
            sys.stderr.write(f"zss.guard: missing {name}\n")
            sys.exit(1)
        try:
            data = read_bytes(zspy_path)
            header = parse_zspy(data)
            if not header.layer_nonces and not header.layer_tags:
                _arc_decrypt_archive(header, priv)
            else:
                decrypt_zspy(header, priv)
        except ZssError as e:
            sys.stderr.write(f"zss.guard: {name}: {e}\n")
            sys.exit(1)



_v050_orig_load = load


def load(name: str, *, _caller_frame_depth: int = 1) -> Any:
    import inspect
    frame = inspect.currentframe()
    try:
        for _ in range(_caller_frame_depth):
            if frame is None:
                raise ZssError("cannot determine caller frame for load()")
            frame = frame.f_back
        if frame is None:
            raise ZssError("cannot determine caller frame for load()")
        caller_file = frame.f_globals.get("__file__", "")
        caller_globals = frame.f_globals
    finally:
        del frame
    if not caller_file:
        raise ZssError("load() called without __file__ in caller globals")
    mod = import_(name, _caller_file=caller_file)
    for k, v in mod.__dict__.items():
        if not k.startswith("__"):
            caller_globals[k] = v



_v050_orig_cmd_init = cmd_init


def cmd_init(args: argparse.Namespace) -> int:
    _zss_home_env_override()
    if getattr(args, "force", False) and PRIVATE_KEY_PATH.exists():
        if not _require_confirmation(
            f"This will OVERWRITE existing keys in {ZSS_HOME}.\n"
            f"All .zspy files encrypted with the old key will become UNREADABLE.\n"
            f"Type YES to continue: "
        ):
            _eprint("Aborted.")
            return 1
    _eprint("generating keypair...")
    rc = _v050_orig_cmd_init(args)
    if rc == 0:
        _eprint("installing zss command... (beta: manual install)")
        _print("")
        _print("Quick start:")
        _print("  1. zss pack yourfile.py")
        _print("  2. zss run yourfile.packed.py")
        _print("  3. zss list")
    return rc



_v050_orig_cmd_pack = cmd_pack


def _v050_watch_pack(args, py_path):
    _eprint(f"Watching {py_path.name} for changes (Ctrl+C to stop)...")
    last_mtime = py_path.stat().st_mtime
    while True:
        try:
            import time as _t
            _t.sleep(1)
            try:
                current_mtime = py_path.stat().st_mtime
            except OSError:
                continue
            if current_mtime == last_mtime:
                continue
            last_mtime = current_mtime
            _eprint(f"\n[{_t.strftime('%H:%M:%S')}] Change detected, repacking...")
            watch_args = argparse.Namespace(**vars(args))
            watch_args.watch = False
            try:
                cmd_pack(watch_args)
            except Exception as e:
                _eprint(f"pack error: {e}")
        except KeyboardInterrupt:
            _eprint("\nStopped.")
            return 0


def cmd_pack(args: argparse.Namespace) -> int:
    _zss_home_env_override()
    py_path = Path(args.file).expanduser().resolve()
    if not py_path.is_file():
        _eprint(f"error: source file not found: {py_path}")
        return 1
    if py_path.suffix != ".py":
        _eprint(f"error: expected a .py file, got {py_path.name}")
        return 1
    try:
        source = py_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        _eprint(f"error: source is not valid UTF-8: {e}")
        return 1

    try:
        arc_dirs = _arc_parse_directives(source)
    except ZssParseError as e:
        _eprint(f"error: {e}")
        return 1
    if arc_dirs is not None:
        return _v050_orig_cmd_pack(args)

    try:
        old_parsed = parse_source_with_directives(source)
    except ZssParseError as e:
        _eprint(f"error: {e}")
        return 1

    try:
        rewritten, with_blocks, secret_funcs, const_assigns = _ast_process_source(
            old_parsed.rewritten
        )
    except Exception as e:
        _eprint(f"error: AST parse: {e}")
        return 1

    all_blocks = []
    for b in old_parsed.blocks:
        all_blocks.append((b.filename, b.body.encode("utf-8"), None))
    for wb in with_blocks:
        all_blocks.append((wb["filename"], wb["body"].encode("utf-8"), wb.get("layers")))
    for sf in secret_funcs:
        all_blocks.append((sf["filename"], sf["func_source"].encode("utf-8"), None))
    const_by_file = {}
    for ca in const_assigns:
        const_by_file.setdefault(ca["file"], {})[ca["key"]] = ca["value"]
    for fname, kv in const_by_file.items():
        all_blocks.append((fname, json.dumps(kv).encode("utf-8"), None))

    if not all_blocks:
        return _v050_orig_cmd_pack(args)

    seen = set()
    for name, _, _ in all_blocks:
        if name in seen:
            _eprint(f"error: duplicate .zspy filename: {name}")
            return 1
        seen.add(name)

    if getattr(args, "dry_run", False):
        _print(f"Dry run for {py_path.name}:")
        for name, content, layers in all_blocks:
            extra = f", layers={layers}" if layers else ""
            _print(f"  {name}: {len(content)} bytes{extra}")
        return 0

    if getattr(args, "watch", False):
        return _v050_watch_pack(args, py_path)

    try:
        priv = load_private_key(PRIVATE_KEY_PATH)
    except ZssKeyError as e:
        _eprint(f"error: {e}")
        return 1
    pub = priv.public_key()

    n_layers = args.layers
    if n_layers is None:
        try:
            payload = load_zson(priv, ZSON_PATH)
            n_layers = int(get_zson_setting(payload, "default_n_layers", DEFAULT_N_LAYERS))
        except ZssConfigError:
            n_layers = DEFAULT_N_LAYERS
    if not (MIN_N_LAYERS <= n_layers <= MAX_N_LAYERS):
        _eprint(f"error: --layers must be in [{MIN_N_LAYERS}..{MAX_N_LAYERS}], got {n_layers}")
        return 1

    out_dir = py_path.parent
    written = []
    for name, content, block_layers in all_blocks:
        eff = block_layers if (block_layers and MIN_N_LAYERS <= block_layers <= MAX_N_LAYERS) else n_layers
        master = _secure_random(MASTER_KEY_SIZE)
        try:
            blob = build_zspy(content, master, eff, pub)
        finally:
            zero_fill(bytearray(master))
        out_path = out_dir / name
        atomic_write_bytes(out_path, blob, mode=0o644)
        written.append((name, out_path.stat().st_size, eff))

    bak_path = py_path.with_suffix(py_path.suffix + ".bak")
    if bak_path.exists() and getattr(args, "no_clobber", False):
        _eprint(f"error: backup exists: {bak_path}")
        return 1
    try:
        atomic_write_text(bak_path, source, mode=0o600)
    except OSError as e:
        _eprint(f"error: cannot write backup: {e}")
        return 1

    target = py_path if getattr(args, "in_place", False) else py_path.with_suffix(".packed.py")
    try:
        atomic_write_text(target, rewritten, mode=0o644)
    except OSError as e:
        _eprint(f"error: cannot write {target}: {e}")
        return 1

    try:
        target_bytes = target.read_bytes()
    except OSError as e:
        _eprint(f"error: cannot read back {target}: {e}")
        return 1
    state_set("guard", str(target.resolve()), sha256(target_bytes).hex())
    state_save()

    _print(f"packed {py_path.name}:")
    _print(f"  {'name':<30} {'size':>8} {'layers':>6}")
    _print(f"  {'-'*30} {'-'*8} {'-'*6}")
    for name, size, layers in written:
        _print(f"  {name:<30} {size:>8} {layers:>6}")
    _print(f"  -> {target.name}")
    _print(f"  backup: {bak_path.name}")
    return 0



_v050_orig_cmd_run = cmd_run


def cmd_run(args: argparse.Namespace) -> int:
    _zss_home_env_override()
    trace = getattr(args, "trace", False)
    timer = getattr(args, "time", False)
    if trace:
        _eprint(f"[trace] zss run {args.file}")
    import time as _t
    t0 = _t.perf_counter() if timer else 0

    target = Path(args.file).expanduser().resolve()
    if target.suffix == ".py" and target.exists():
        try:
            source = target.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            source = ""
        needs_zss = (
            "zss." in source
            or "import zss" in source
            or "from zss" in source
        )
        if needs_zss:
            rc = _v050_run_packed_with_zss(target, args, source)
            if timer:
                _eprint(f"[time] total: {_t.perf_counter() - t0:.3f}s")
            if trace:
                _eprint(f"[trace] exit code: {rc}")
            return rc

    rc = _v050_orig_cmd_run(args)
    if timer:
        elapsed = _t.perf_counter() - t0
        _eprint(f"[time] total: {elapsed:.3f}s")
    if trace:
        _eprint(f"[trace] exit code: {rc}")
    return rc


def _v050_run_packed_with_zss(py_path: Path, args, source: str) -> int:
    namespace = {
        "__name__": "__main__",
        "__file__": str(py_path),
        "__builtins__": __builtins__,
    }
    sys.argv = [str(py_path)] + list(args.arg or [])

    script_dir = str(py_path.parent)
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

    current_module = sys.modules[__name__]
    saved_zss = sys.modules.get("zss")
    sys.modules["zss"] = current_module
    namespace["zss"] = current_module

    try:
        code = compile(source, str(py_path), "exec")
        exec(code, namespace)
    except SystemExit as e:
        if isinstance(e.code, int):
            return e.code
        if e.code is None:
            return 0
        return 1
    except ZssError as e:
        if getattr(args, "debug", False):
            raise
        _eprint(f"error: {e}")
        return 1
    except Exception as e:
        if getattr(args, "debug", False):
            raise
        _eprint(f"error: runtime exception: {type(e).__name__}: {e}")
        return 1
    finally:
        if saved_zss is not None:
            sys.modules["zss"] = saved_zss
        elif sys.modules.get("zss") is current_module:
            del sys.modules["zss"]
    return 0



_v050_orig_cmd_list = cmd_list


def cmd_list(args: argparse.Namespace) -> int:
    return _v050_orig_cmd_list(args)



def cmd_doctor(args: argparse.Namespace) -> int:
    _zss_home_env_override()
    env = _detect_python_env()
    _print("ZSS doctor — environment check")
    _print(f"  Python:       {env['python']}")
    try:
        import cryptography as _crypt
        _print(f"  cryptography: {_crypt.__version__}")
    except Exception:
        _print(f"  cryptography: NOT INSTALLED (pip install cryptography)")
    _print(f"  platform:     {env['platform']}")
    if env["is_termux"]:
        _print(f"  note:         Termux detected")
    if env["is_windows"]:
        _print(f"  note:         Windows detected")
    _print(f"  ZSS_HOME:     {ZSS_HOME}")
    _print("")
    _print("  Keys:")
    if PRIVATE_KEY_PATH.exists():
        ok = _check_key_perms(PRIVATE_KEY_PATH)
        perms = oct(os.stat(PRIVATE_KEY_PATH).st_mode & 0o777)
        _print(f"    private: {PRIVATE_KEY_PATH}")
        _print(f"    perms:   {perms} ({'OK' if ok else 'BAD — should be 0600'})")
    else:
        _print(f"    private: NOT FOUND (run zss init)")
    if PUBLIC_KEY_PATH.exists():
        _print(f"    public:  {PUBLIC_KEY_PATH}")
    _print("")
    _print("  State:")
    if zson_exists(ZSON_PATH):
        _print(f"    .zson:   {ZSON_PATH} (exists)")
    else:
        _print(f"    .zson:   NOT FOUND (run zss init)")
    _print("")
    which = shutil.which("zss")
    _print(f"  zss in PATH: {which or 'not found'}")
    _print("")
    _print("  Recommendations:")
    if not PRIVATE_KEY_PATH.exists():
        _print("    - Run `zss init` to generate keys")
    elif not _check_key_perms(PRIVATE_KEY_PATH):
        _print(f"    - chmod 600 {PRIVATE_KEY_PATH}")
    if not zson_exists(ZSON_PATH):
        _print("    - Run `zss init` to create .zson")
    if PRIVATE_KEY_PATH.exists() and zson_exists(ZSON_PATH) and _check_key_perms(PRIVATE_KEY_PATH):
        _print("    - Environment looks OK")
    return 0



def cmd_verify(args: argparse.Namespace) -> int:
    _zss_home_env_override()
    target = Path(args.file).expanduser().resolve()
    if not target.exists():
        _eprint(f"error: not found: {target}")
        return 1
    try:
        priv = load_private_key(PRIVATE_KEY_PATH)
    except ZssKeyError as e:
        _eprint(f"error: {e}")
        return 1

    if target.suffix == ".zspy":
        data = read_bytes(target)
        if len(data) >= 14 and data[:8] == ZSSPY_MAGIC:
            reserved0 = data[11]
            if reserved0 in (2, 3):
                kind = "share-single" if reserved0 == 2 else "share-archive"
                n_layers = data[10]
                _print(f"OK: {target.name} — {kind} format ({n_layers} layers, "
                       f"password required to verify content, structure valid)")
                return 0
        try:
            header = parse_zspy(data)
        except ZssFormatError as e:
            _eprint(f"FAIL: {e}")
            return 1
        if not header.layer_nonces and not header.layer_tags:
            ok, msg = _verify_archive(target, priv)
        else:
            ok, msg = _verify_zspy(target, priv)
        if ok:
            _print(f"OK: {target.name} — {msg}")
            return 0
        _eprint(f"FAIL: {target.name} — {msg}")
        return 1

    if target.suffix == ".py":
        try:
            source = target.read_text(encoding="utf-8")
        except UnicodeDecodeError as e:
            _eprint(f"error: {e}")
            return 1
        refs = _share_find_zspy_refs(source)
        try:
            old_parsed = parse_source_with_directives(source)
            for b in old_parsed.blocks:
                refs.setdefault(b.filename, "single")
        except ZssParseError:
            pass
        if not refs:
            _eprint(f"no .zspy references in {target.name}")
            return 1
        all_ok = True
        for name in refs:
            zspy_path = target.parent / name
            if not zspy_path.exists():
                _eprint(f"FAIL: {name} not found")
                all_ok = False
                continue
            data = read_bytes(zspy_path)
            try:
                header = parse_zspy(data)
                if not header.layer_nonces and not header.layer_tags:
                    _arc_decrypt_archive(header, priv)
                else:
                    decrypt_zspy(header, priv)
                _print(f"OK: {name}")
            except ZssError as e:
                _eprint(f"FAIL: {name} — {e}")
                all_ok = False
        return 0 if all_ok else 1

    _eprint(f"error: expected .py or .zspy")
    return 1



def cmd_lint(args: argparse.Namespace) -> int:
    _zss_home_env_override()
    scan_dir = Path(getattr(args, "dir", None) or ".").expanduser().resolve()
    if not scan_dir.is_dir():
        _eprint(f"error: not a directory: {scan_dir}")
        return 1
    issues = []

    for p in scan_dir.rglob("*.bak"):
        issues.append(("bak", str(p)))

    if PRIVATE_KEY_PATH.exists() and not _check_key_perms(PRIVATE_KEY_PATH):
        issues.append(("key_perms", str(PRIVATE_KEY_PATH)))

    zspy_files = {p.name: p for p in scan_dir.glob("*.zspy")}
    referenced = set()
    py_files = {p.name: p for p in scan_dir.glob("*.py")}
    for p in scan_dir.glob("*.py"):
        try:
            src = p.read_text(encoding="utf-8")
            refs = _share_find_zspy_refs(src)
            referenced.update(refs.keys())
            try:
                parsed = parse_source_with_directives(src)
                for b in parsed.blocks:
                    referenced.add(b.filename)
            except ZssParseError:
                pass
            for name in (refs.keys() if hasattr(refs, "keys") else []):
                zspy_path = p.parent / name
                if zspy_path.exists():
                    zspy_mtime = zspy_path.stat().st_mtime
                    py_mtime = p.stat().st_mtime
                    if zspy_mtime < py_mtime:
                        issues.append(("stale", f"{name} older than {p.name}"))
        except UnicodeDecodeError:
            pass

    for name, zspy_path in zspy_files.items():
        try:
            data = read_bytes(zspy_path)
            header = parse_zspy(data)
            if header.n_layers == 1:
                issues.append(("weak_layers", f"{name} (N=1)"))
        except ZssFormatError:
            issues.append(("corrupt", name))

    for name in set(zspy_files.keys()) - referenced:
        issues.append(("orphan", name))

    if not issues:
        _print("No issues found.")
        return 0

    _print(f"Found {len(issues)} issue(s):")
    for kind, target in issues:
        _print(f"  [{kind}] {target}")

    if getattr(args, "fix", False):
        for kind, target in issues:
            if kind == "bak":
                Path(target).unlink(missing_ok=True)
                _print(f"  fixed: removed {target}")
            elif kind == "key_perms":
                try:
                    os.chmod(target, 0o600)
                    _print(f"  fixed: chmod 0600 {target}")
                except OSError as e:
                    _eprint(f"  cannot fix {target}: {e}")
    return 1



def cmd_status(args: argparse.Namespace) -> int:
    _zss_home_env_override()
    _print("ZSS status")
    _print(f"  version:     {ZSS_VERSION}")
    _print(f"  ZSS_HOME:    {ZSS_HOME}")
    if PRIVATE_KEY_PATH.exists():
        st = PRIVATE_KEY_PATH.stat()
        import datetime
        created = datetime.datetime.fromtimestamp(st.st_ctime).isoformat()
        _print(f"  private key: {PRIVATE_KEY_PATH}")
        _print(f"    created:   {created}")
        _print(f"    perms:     {oct(st.st_mode & 0o777)}")
    else:
        _print(f"  private key: NOT FOUND")

    cwd = Path.cwd()
    zspy_count = 0
    total_size = 0
    for p in cwd.glob("*.zspy"):
        zspy_count += 1
        total_size += p.stat().st_size
    _print(f"  .zspy in cwd: {zspy_count} ({total_size} bytes)")
    py_count = len(list(cwd.glob("*.py")))
    _print(f"  .py in cwd:   {py_count}")
    return 0



def _v050_rebuild_archive(manifest, n_layers, recipient_pub) -> bytes:
    master = _secure_random(MASTER_KEY_SIZE)
    try:
        files_b64: dict[str, str] = {}
        file_hashes: dict[str, str] = {}
        for fname, content in manifest.files.items():
            salt = _secure_random(ZSSPY_FILE_SALT_SIZE)
            layered = encrypt_layers(content, master, n_layers, salt)
            blob = bytearray()
            blob += salt
            for n in layered.nonces:
                blob += n
            for t in layered.tags:
                blob += t
            blob += layered.ciphertext
            files_b64[fname] = _b64e(bytes(blob))
            file_hashes[fname] = sha256(content).hex()

        manifest_dict = {
            "schema": 1,
            "entry": manifest.entry,
            "files": files_b64,
            "file_hashes": file_hashes,
        }
        manifest_bytes = json.dumps(
            manifest_dict, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        compressed = zlib.compress(manifest_bytes, 9)

        file_salt = _secure_random(ZSSPY_FILE_SALT_SIZE)
        outer_key = hkdf_derive(master, file_salt, _ARC_OUTER_INFO, KEY_SIZE)
        outer_nonce = _secure_random(NONCE_SIZE)
        outer_aad = _ARC_OUTER_AAD_PREFIX + file_salt
        aead = ChaCha20Poly1305(outer_key)
        outer_ct = aead.encrypt(outer_nonce, compressed, outer_aad)
        zero_fill(bytearray(outer_key))

        wrap = wrap_master_key(master, recipient_pub)
        if len(wrap.wrapped) != MASTER_KEY_SIZE + TAG_SIZE:
            raise ZssCryptoError("internal: wrapped has unexpected length")
        wrapped_master = wrap.wrapped[:MASTER_KEY_SIZE]
        wrap_tag = wrap.wrapped[MASTER_KEY_SIZE:]

        import time
        timestamp = int(time.time())
        zss_ver_bytes = ZSS_VERSION.encode("utf-8")
        ct_payload = outer_nonce + outer_ct

        out = bytearray()
        out += ZSSPY_MAGIC
        out += struct.pack("<H", ZSSPY_FORMAT_VERSION)
        out += struct.pack("<B", n_layers)
        out += bytes([1, 0, 0])
        out += wrap.eph_pubkey
        out += wrap.wrap_nonce
        out += wrapped_master
        out += wrap_tag
        out += file_salt
        out += sha256(manifest_bytes)
        out += struct.pack("<Q", timestamp)
        out += struct.pack("<B", len(zss_ver_bytes))
        out += zss_ver_bytes
        out += struct.pack("<I", len(ct_payload))
        out += ct_payload
        return bytes(out)
    finally:
        zero_fill(bytearray(master))


def cmd_rekey(args: argparse.Namespace) -> int:
    _zss_home_env_override()
    old_key_path = Path(args.old_key).expanduser().resolve()
    new_key_path = Path(args.new_key).expanduser().resolve()
    target_dir = Path(getattr(args, "dir", None) or ".").expanduser().resolve()
    if not old_key_path.exists():
        _eprint(f"error: old key not found: {old_key_path}")
        return 1
    if not new_key_path.exists():
        _eprint(f"error: new key not found: {new_key_path}")
        return 1
    old_priv = deserialize_private_key(read_bytes(old_key_path))
    new_priv = deserialize_private_key(read_bytes(new_key_path))
    new_pub = new_priv.public_key()

    zspy_files = sorted(target_dir.glob("*.zspy"))
    if not zspy_files:
        _print(f"No .zspy files in {target_dir}")
        return 0

    _print(f"Rekeying {len(zspy_files)} file(s)...")
    errors = 0
    for zspy_path in zspy_files:
        try:
            data = read_bytes(zspy_path)
            header = parse_zspy(data)
            if args.backup:
                bak = zspy_path.with_suffix(zspy_path.suffix + ".old")
                atomic_write_bytes(bak, data, mode=0o600)
            if not header.layer_nonces and not header.layer_tags:
                manifest = _arc_decrypt_archive(header, old_priv)
                blob = _v050_rebuild_archive(manifest, header.n_layers, new_pub)
            else:
                plaintext = decrypt_zspy(header, old_priv)
                master = _secure_random(MASTER_KEY_SIZE)
                try:
                    blob = build_zspy(plaintext, master, header.n_layers, new_pub)
                finally:
                    zero_fill(bytearray(master))
            atomic_write_bytes(zspy_path, blob, mode=0o644)
            _print(f"  rekeyed: {zspy_path.name}")
        except Exception as e:
            _eprint(f"  error: {zspy_path.name}: {e}")
            errors += 1
    return 0 if errors == 0 else 1



def cmd_demo(args: argparse.Namespace) -> int:
    mode = getattr(args, "mode", "single")
    tmpdir = Path(tempfile.mkdtemp(prefix="zss-demo-"))
    atexit.register(shutil.rmtree, str(tmpdir), True)
    saved_env = os.environ.get("ZSS_HOME")
    saved_paths = {
        "ZSS_HOME": ZSS_HOME,
        "KEYS_DIR": KEYS_DIR,
        "ZSON_PATH": ZSON_PATH,
        "PRIVATE_KEY_PATH": PRIVATE_KEY_PATH,
        "PUBLIC_KEY_PATH": PUBLIC_KEY_PATH,
    }
    try:
        os.environ["ZSS_HOME"] = str(tmpdir / ".zss")
        _zss_home_env_override()
        _ensure_dir(KEYS_DIR, mode=0o700)
        priv, pub = generate_keypair()
        save_private_key(priv, PRIVATE_KEY_PATH)
        save_public_key(pub, PUBLIC_KEY_PATH)
        init_zson(priv, ZSON_PATH)

        if mode == "single":
            src = tmpdir / "demo.py"
            src.write_text(
                'import zss\n'
                'with zss.block("secret.zspy", layers=3):\n'
                '    MSG = "hello from zss demo"\n'
                'print(MSG)\n',
                encoding="utf-8",
            )
        else:
            (tmpdir / "game").mkdir()
            (tmpdir / "game" / "main.py").write_text(
                "print('archive demo ok')\n", encoding="utf-8",
            )
            src = tmpdir / "demo.py"
            src.write_text(
                '#dir-{main.py}-directory!game!\n'
                '#on{main.py}-import--files{}\n',
                encoding="utf-8",
            )

        _print(f"=== Demo ({mode} mode) ===")
        _print(f"Source: {src}")
        _print(f"--- Packing ---")
        pack_args = argparse.Namespace(
            file=str(src), layers=3, in_place=True, no_clobber=False,
            dry_run=False, watch=False,
        )
        rc = cmd_pack(pack_args)
        if rc != 0:
            return rc
        _print(f"--- Running ---")
        run_args = argparse.Namespace(
            file=str(src), arg=[], debug=False, trace=False, time=False,
        )
        return cmd_run(run_args)
    except Exception as e:
        _eprint(f"demo error: {e}")
        if getattr(args, "debug", False):
            raise
        return 1
    finally:
        if saved_env is not None:
            os.environ["ZSS_HOME"] = saved_env
        else:
            os.environ.pop("ZSS_HOME", None)
        import zss as _self_module
        for k, v in saved_paths.items():
            setattr(_self_module, k, v)



_v050_orig_build_arg_parser = build_arg_parser


def build_arg_parser() -> argparse.ArgumentParser:
    parser = _v050_orig_build_arg_parser()
    parser.epilog = (
        "Examples:\n"
        "  zss init                              # generate keys + .zson\n"
        "  zss pack app.py --in-place            # pack single-file .py\n"
        "  zss pack loader.py --layers 7         # pack with custom layer count\n"
        "  zss pack app.py --watch               # auto-repack on changes\n"
        "  zss run app.py                        # run packed .py\n"
        "  zss run app.zspy                      # run .zspy directly\n"
        "  zss share app.py --password SECRET    # create self-contained bundle\n"
        "  zss verify app.py                     # verify integrity\n"
        "  zss doctor                            # check environment\n"
        "  zss lint --fix                        # find and fix issues\n"
        "  zss rekey --old-key old --new-key new # rotate master key\n"
    )
    parser.formatter_class = argparse.RawDescriptionHelpFormatter
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            action.add_parser("doctor", help="check environment").set_defaults(func=cmd_doctor)
            p_verify = action.add_parser("verify", help="verify integrity without running")
            p_verify.add_argument("file", help=".py or .zspy to verify")
            p_verify.set_defaults(func=cmd_verify)
            p_lint = action.add_parser("lint", help="find common issues")
            p_lint.add_argument("--dir", default=None)
            p_lint.add_argument("--fix", action="store_true")
            p_lint.set_defaults(func=cmd_lint)
            action.add_parser("status", help="show summary").set_defaults(func=cmd_status)
            p_rekey = action.add_parser("rekey", help="change master key")
            p_rekey.add_argument("--old-key", required=True)
            p_rekey.add_argument("--new-key", required=True)
            p_rekey.add_argument("--dir", default=None)
            p_rekey.add_argument("--backup", action="store_true")
            p_rekey.set_defaults(func=cmd_rekey)
            p_demo = action.add_parser("demo", help="create and run a demo")
            p_demo.add_argument("--mode", choices=["single", "archive"], default="single")
            p_demo.set_defaults(func=cmd_demo)
            p_help = action.add_parser("help", help="show help for a command")
            p_help.add_argument("command", nargs="?", default=None,
                                help="command to show help for")
            p_help.set_defaults(func=_cmd_help_alias)

            for name, subparser in action.choices.items():
                if name == "pack":
                    existing = {a.option_strings[0] for a in subparser._actions if a.option_strings}
                    if "--dry-run" not in existing:
                        subparser.add_argument("--dry-run", action="store_true", help="show what would be packed")
                    if "--watch" not in existing:
                        subparser.add_argument("--watch", action="store_true", help="auto-repack on change")
                elif name == "run":
                    existing = {a.option_strings[0] for a in subparser._actions if a.option_strings}
                    if "--trace" not in existing:
                        subparser.add_argument("--trace", action="store_true", help="print execution steps")
                    if "--time" not in existing:
                        subparser.add_argument("--time", action="store_true", help="measure timing")
            break
    return parser


def _cmd_help_alias(args: argparse.Namespace) -> int:
    parser = build_arg_parser()
    if not args.command:
        parser.print_help()
        return 0
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            if args.command in action.choices:
                action.choices[args.command].print_help()
                return 0
            _eprint(f"error: unknown command: {args.command}")
            _eprint(f"available: {', '.join(action.choices.keys())}")
            return 2
    _eprint(f"error: unknown command: {args.command}")
    return 2





class TestNewSyntax(unittest.TestCase):

    def _setup_home(self, fx):
        _ensure_dir(KEYS_DIR, mode=0o700)
        priv, pub = generate_keypair()
        save_private_key(priv, PRIVATE_KEY_PATH)
        save_public_key(pub, PUBLIC_KEY_PATH)
        init_zson(priv, ZSON_PATH)
        return priv

    def test_ast_finds_with_block(self):
        src = (
            'import zss\n'
            'with zss.block("x.zspy", layers=3):\n'
            '    X = 1\n'
        )
        tree = _v050_ast.parse(src)
        calls = _ast_find_zss_calls(tree)
        self.assertEqual(len(calls["with_blocks"]), 1)
        self.assertEqual(calls["with_blocks"][0]["filename"], "x.zspy")
        self.assertEqual(calls["with_blocks"][0]["layers"], 3)

    def test_ast_finds_secret_func(self):
        src = (
            'import zss\n'
            '@zss.secret("lic.zspy")\n'
            'def check(x):\n    return x == 1\n'
        )
        tree = _v050_ast.parse(src)
        calls = _ast_find_zss_calls(tree)
        self.assertEqual(len(calls["secret_funcs"]), 1)
        self.assertEqual(calls["secret_funcs"][0]["filename"], "lic.zspy")
        self.assertEqual(calls["secret_funcs"][0]["func_name"], "check")

    def test_ast_finds_const_assign(self):
        src = 'import zss\nAPI = zss.const("c.zspy", "API", "secret-val")\n'
        tree = _v050_ast.parse(src)
        calls = _ast_find_zss_calls(tree)
        self.assertEqual(len(calls["const_assigns"]), 1)
        self.assertEqual(calls["const_assigns"][0]["file"], "c.zspy")
        self.assertEqual(calls["const_assigns"][0]["key"], "API")
        self.assertEqual(calls["const_assigns"][0]["value"], "secret-val")

    def test_ast_process_replaces_with_block(self):
        src = (
            'import zss\n'
            'with zss.block("x.zspy"):\n'
            '    X = 1\n'
        )
        rewritten, wbs, sfs, cas = _ast_process_source(src)
        self.assertEqual(len(wbs), 1)
        self.assertIn("X = 1", wbs[0]["body"])
        self.assertIn('from zss import load; load("x.zspy")', rewritten)
        self.assertNotIn("with zss.block", rewritten)

    def test_ast_with_block_in_function_is_error(self):
        src = (
            'import zss\n'
            'def f():\n'
            '    with zss.block("x.zspy"):\n'
            '        X = 1\n'
            '    return X\n'
        )
        with self.assertRaises(ZssParseError) as ctx:
            _ast_process_source(src)
        self.assertIn("module level", str(ctx.exception).lower())

    def test_ast_with_block_in_method_is_error(self):
        src = (
            'import zss\n'
            'class C:\n'
            '    def m(self):\n'
            '        with zss.block("x.zspy"):\n'
            '            return 1\n'
        )
        with self.assertRaises(ZssParseError):
            _ast_process_source(src)

    def test_ast_process_replaces_secret_func(self):
        src = (
            'import zss\n'
            '@zss.secret("lic.zspy")\n'
            'def check(x):\n    return x == 1\n'
        )
        rewritten, wbs, sfs, cas = _ast_process_source(src)
        self.assertEqual(len(sfs), 1)
        self.assertIn("return x == 1", sfs[0]["func_source"])
        self.assertIn('@zss._decrypt_secret("lic.zspy")', rewritten)
        self.assertIn("    pass", rewritten)

    def test_ast_process_replaces_const(self):
        src = 'import zss\nAPI = zss.const("c.zspy", "API", "val")\n'
        rewritten, wbs, sfs, cas = _ast_process_source(src)
        self.assertEqual(len(cas), 1)
        self.assertIn('zss._decrypt_const("c.zspy", "API")', rewritten)
        self.assertNotIn('"val"', rewritten)

    def test_with_block_pack_and_run(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            src_path = fx.tmpdir / "app.py"
            src_path.write_text(
                'import zss\n'
                'with zss.block("secret.zspy", layers=3):\n'
                '    VALUE = "block-secret"\n'
                'print(VALUE)\n',
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(src_path), layers=3, in_place=True, no_clobber=False,
                dry_run=False, watch=False,
            )
            self.assertEqual(cmd_pack(pack_args), 0)
            self.assertTrue((fx.tmpdir / "secret.zspy").exists())
            packed = src_path.read_text(encoding="utf-8")
            self.assertIn('load("secret.zspy")', packed)
            self.assertNotIn("block-secret", packed)

            run_args = argparse.Namespace(
                file=str(src_path), arg=[], debug=False, trace=False, time=False,
            )
            old = sys.stdout
            cap = io.StringIO()
            sys.stdout = cap
            try:
                rc = cmd_run(run_args)
            finally:
                sys.stdout = old
            self.assertEqual(rc, 0, f"stdout={cap.getvalue()!r}")
            self.assertIn("block-secret", cap.getvalue())

    def test_secret_func_pack_and_run(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            src_path = fx.tmpdir / "app.py"
            src_path.write_text(
                'import zss\n'
                '@zss.secret("lic.zspy")\n'
                'def check_license(token):\n'
                '    return token == "valid"\n'
                'print(check_license("valid"))\n'
                'print(check_license("bad"))\n',
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(src_path), layers=3, in_place=True, no_clobber=False,
                dry_run=False, watch=False,
            )
            self.assertEqual(cmd_pack(pack_args), 0)
            self.assertTrue((fx.tmpdir / "lic.zspy").exists())

            run_args = argparse.Namespace(
                file=str(src_path), arg=[], debug=False, trace=False, time=False,
            )
            old = sys.stdout
            cap = io.StringIO()
            sys.stdout = cap
            try:
                rc = cmd_run(run_args)
            finally:
                sys.stdout = old
            self.assertEqual(rc, 0, f"stdout={cap.getvalue()!r}")
            self.assertIn("True", cap.getvalue())
            self.assertIn("False", cap.getvalue())

    def test_secret_func_on_method(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            src_path = fx.tmpdir / "app.py"
            src_path.write_text(
                'import zss\n'
                'class Service:\n'
                '    @zss.secret("m.zspy")\n'
                '    def compute(self, x):\n'
                '        return x * 2\n'
                's = Service()\n'
                'print(s.compute(21))\n',
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(src_path), layers=3, in_place=True, no_clobber=False,
                dry_run=False, watch=False,
            )
            self.assertEqual(cmd_pack(pack_args), 0)
            run_args = argparse.Namespace(
                file=str(src_path), arg=[], debug=False, trace=False, time=False,
            )
            old = sys.stdout
            cap = io.StringIO()
            sys.stdout = cap
            try:
                rc = cmd_run(run_args)
            finally:
                sys.stdout = old
            self.assertEqual(rc, 0, f"stdout={cap.getvalue()!r}")
            self.assertIn("42", cap.getvalue())

    def test_secret_func_with_annotations(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            src_path = fx.tmpdir / "app.py"
            src_path.write_text(
                'import zss\n'
                '@zss.secret("ann.zspy")\n'
                'def add(a: int, b: int) -> int:\n'
                '    return a + b\n'
                'print(add(2, 3))\n',
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(src_path), layers=3, in_place=True, no_clobber=False,
                dry_run=False, watch=False,
            )
            self.assertEqual(cmd_pack(pack_args), 0)
            run_args = argparse.Namespace(
                file=str(src_path), arg=[], debug=False, trace=False, time=False,
            )
            old = sys.stdout
            cap = io.StringIO()
            sys.stdout = cap
            try:
                rc = cmd_run(run_args)
            finally:
                sys.stdout = old
            self.assertEqual(rc, 0, f"stdout={cap.getvalue()!r}")
            self.assertIn("5", cap.getvalue())

    def test_secret_func_async(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            src_path = fx.tmpdir / "app.py"
            src_path.write_text(
                'import zss, asyncio\n'
                '@zss.secret("async.zspy")\n'
                'async def fetch():\n'
                '    return "async-result"\n'
                'print(asyncio.run(fetch()))\n',
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(src_path), layers=3, in_place=True, no_clobber=False,
                dry_run=False, watch=False,
            )
            self.assertEqual(cmd_pack(pack_args), 0)
            run_args = argparse.Namespace(
                file=str(src_path), arg=[], debug=False, trace=False, time=False,
            )
            old = sys.stdout
            cap = io.StringIO()
            sys.stdout = cap
            try:
                rc = cmd_run(run_args)
            finally:
                sys.stdout = old
            self.assertEqual(rc, 0, f"stdout={cap.getvalue()!r}")
            self.assertIn("async-result", cap.getvalue())

    def test_const_pack_and_run(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            src_path = fx.tmpdir / "app.py"
            src_path.write_text(
                'import zss\n'
                'API_KEY = zss.const("config.zspy", "API_KEY", "sk-12345")\n'
                'print(API_KEY)\n',
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(src_path), layers=3, in_place=True, no_clobber=False,
                dry_run=False, watch=False,
            )
            self.assertEqual(cmd_pack(pack_args), 0)
            self.assertTrue((fx.tmpdir / "config.zspy").exists())
            packed = src_path.read_text(encoding="utf-8")
            self.assertIn('_decrypt_const("config.zspy", "API_KEY")', packed)
            self.assertNotIn("sk-12345", packed)

            run_args = argparse.Namespace(
                file=str(src_path), arg=[], debug=False, trace=False, time=False,
            )
            old = sys.stdout
            cap = io.StringIO()
            sys.stdout = cap
            try:
                rc = cmd_run(run_args)
            finally:
                sys.stdout = old
            self.assertEqual(rc, 0, f"stdout={cap.getvalue()!r}")
            self.assertIn("sk-12345", cap.getvalue())

    def test_import_returns_module(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            src_path = fx.tmpdir / "app.py"
            src_path.write_text(
                '#<zss>{write_to!mod.zspy\n'
                'X = 42\n'
                'def get():\n    return X\n'
                '#<zss>{closing!write!mod.zspy\n'
                'mod = zss.import_("mod.zspy")\n'
                'print(type(mod).__name__)\n'
                'print(mod.X, mod.get())\n',
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(src_path), layers=3, in_place=True, no_clobber=False,
                dry_run=False, watch=False,
            )
            self.assertEqual(cmd_pack(pack_args), 0)

            run_args = argparse.Namespace(
                file=str(src_path), arg=[], debug=False, trace=False, time=False,
            )
            old = sys.stdout
            cap = io.StringIO()
            sys.stdout = cap
            try:
                rc = cmd_run(run_args)
            finally:
                sys.stdout = old
            self.assertEqual(rc, 0, f"stdout={cap.getvalue()!r}")
            self.assertIn("module", cap.getvalue())
            self.assertIn("42 42", cap.getvalue())

    def test_guard_ok(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            src_path = fx.tmpdir / "app.py"
            src_path.write_text(
                '#<zss>{write_to!s.zspy\n'
                'X = 1\n'
                '#<zss>{closing!write!s.zspy\n'
                'import zss\n'
                'zss.guard()\n'
                'print("guard-ok")\n',
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(src_path), layers=3, in_place=True, no_clobber=False,
                dry_run=False, watch=False,
            )
            self.assertEqual(cmd_pack(pack_args), 0)

            run_args = argparse.Namespace(
                file=str(src_path), arg=[], debug=False, trace=False, time=False,
            )
            old = sys.stdout
            cap = io.StringIO()
            sys.stdout = cap
            try:
                rc = cmd_run(run_args)
            finally:
                sys.stdout = old
            self.assertEqual(rc, 0, f"stdout={cap.getvalue()!r}")
            self.assertIn("guard-ok", cap.getvalue())

    def test_guard_detects_modified_py(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            src_path = fx.tmpdir / "app.py"
            src_path.write_text(
                '#<zss>{write_to!s.zspy\n'
                'X = 1\n'
                '#<zss>{closing!write!s.zspy\n'
                'import zss\n'
                'zss.guard()\n'
                'print("guard-ok")\n',
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(src_path), layers=3, in_place=True, no_clobber=False,
                dry_run=False, watch=False,
            )
            self.assertEqual(cmd_pack(pack_args), 0)

            packed = src_path.read_text(encoding="utf-8")
            src_path.write_text(packed + " \n", encoding="utf-8")

            run_args = argparse.Namespace(
                file=str(src_path), arg=[], debug=False, trace=False, time=False,
            )
            old = sys.stdout
            old_err = sys.stderr
            cap = io.StringIO()
            cap_err = io.StringIO()
            sys.stdout = cap
            sys.stderr = cap_err
            try:
                rc = cmd_run(run_args)
            finally:
                sys.stdout = old
                sys.stderr = old_err
            self.assertEqual(rc, 1)
            self.assertIn("modified", cap_err.getvalue().lower())
            self.assertNotIn("guard-ok", cap.getvalue())

    def test_guard_detects_missing_zspy(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            src_path = fx.tmpdir / "app.py"
            src_path.write_text(
                'from zss import load; load("nonexistent.zspy")\n',
                encoding="utf-8",
            )
            import types as _types
            fake_mod = _types.ModuleType("fake")
            fake_mod.__file__ = str(src_path)
            fake_mod.f_globals = fake_mod.__dict__
            old_exit = sys.exit
            exit_code = [None]
            def fake_exit(code=0):
                exit_code[0] = code
                raise SystemExit(code)
            sys.exit = fake_exit
            old_stderr = sys.stderr
            cap_err = io.StringIO()
            sys.stderr = cap_err
            import inspect
            frame = inspect.currentframe()
            try:
                orig_file = frame.f_globals.get("__file__")
                frame.f_globals["__file__"] = str(src_path)
                try:
                    guard()
                except SystemExit:
                    pass
                finally:
                    if orig_file is not None:
                        frame.f_globals["__file__"] = orig_file
                    else:
                        frame.f_globals.pop("__file__", None)
            finally:
                sys.exit = old_exit
                sys.stderr = old_stderr
                del frame
            self.assertEqual(exit_code[0], 1)
            self.assertIn("missing", cap_err.getvalue().lower())

    def test_dry_run_does_not_write(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            src_path = fx.tmpdir / "app.py"
            src_path.write_text(
                'import zss\n'
                'with zss.block("s.zspy"):\n'
                '    X = 1\n',
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(src_path), layers=3, in_place=True, no_clobber=False,
                dry_run=True, watch=False,
            )
            old = sys.stdout
            cap = io.StringIO()
            sys.stdout = cap
            try:
                rc = cmd_pack(pack_args)
            finally:
                sys.stdout = old
            self.assertEqual(rc, 0)
            self.assertIn("Dry run", cap.getvalue())
            self.assertFalse((fx.tmpdir / "s.zspy").exists())


class TestNewCLI(unittest.TestCase):

    def _setup_home(self, fx):
        _ensure_dir(KEYS_DIR, mode=0o700)
        priv, pub = generate_keypair()
        save_private_key(priv, PRIVATE_KEY_PATH)
        save_public_key(pub, PUBLIC_KEY_PATH)
        init_zson(priv, ZSON_PATH)
        return priv

    def test_doctor_returns_0(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            old = sys.stdout
            cap = io.StringIO()
            sys.stdout = cap
            try:
                rc = cmd_doctor(argparse.Namespace())
            finally:
                sys.stdout = old
            self.assertEqual(rc, 0)
            self.assertIn("doctor", cap.getvalue().lower())

    def test_verify_ok(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            src_path = fx.tmpdir / "app.py"
            src_path.write_text(
                '#<zss>{write_to!s.zspy\nX=1\n#<zss>{closing!write!s.zspy\n',
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(src_path), layers=3, in_place=True, no_clobber=False,
                dry_run=False, watch=False,
            )
            self.assertEqual(cmd_pack(pack_args), 0)
            old = sys.stdout
            cap = io.StringIO()
            sys.stdout = cap
            try:
                rc = cmd_verify(argparse.Namespace(file=str(src_path), dir=None))
            finally:
                sys.stdout = old
            self.assertEqual(rc, 0)
            self.assertIn("OK", cap.getvalue())

    def test_verify_detects_corrupt(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            src_path = fx.tmpdir / "app.py"
            src_path.write_text(
                '#<zss>{write_to!s.zspy\nX=1\n#<zss>{closing!write!s.zspy\n',
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(src_path), layers=3, in_place=True, no_clobber=False,
                dry_run=False, watch=False,
            )
            self.assertEqual(cmd_pack(pack_args), 0)
            zspy_path = fx.tmpdir / "s.zspy"
            bad = bytearray(zspy_path.read_bytes())
            bad[-1] ^= 0xFF
            atomic_write_bytes(zspy_path, bytes(bad), mode=0o644)
            old = sys.stdout
            old_err = sys.stderr
            cap = io.StringIO()
            cap_err = io.StringIO()
            sys.stdout = cap
            sys.stderr = cap_err
            try:
                rc = cmd_verify(argparse.Namespace(file=str(src_path), dir=None))
            finally:
                sys.stdout = old
                sys.stderr = old_err
            self.assertEqual(rc, 1)

    def test_lint_finds_bak(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            (fx.tmpdir / "foo.py.bak").write_text("backup", encoding="utf-8")
            old = sys.stdout
            cap = io.StringIO()
            sys.stdout = cap
            try:
                rc = cmd_lint(argparse.Namespace(dir=str(fx.tmpdir), fix=False))
            finally:
                sys.stdout = old
            self.assertEqual(rc, 1)
            self.assertIn("bak", cap.getvalue())

    def test_lint_fix_removes_bak(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            bak = fx.tmpdir / "foo.py.bak"
            bak.write_text("backup", encoding="utf-8")
            self.assertTrue(bak.exists())
            old = sys.stdout
            cap = io.StringIO()
            sys.stdout = cap
            try:
                cmd_lint(argparse.Namespace(dir=str(fx.tmpdir), fix=True))
            finally:
                sys.stdout = old
            self.assertFalse(bak.exists())

    def test_status_returns_0(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            old = sys.stdout
            cap = io.StringIO()
            sys.stdout = cap
            try:
                rc = cmd_status(argparse.Namespace())
            finally:
                sys.stdout = old
            self.assertEqual(rc, 0)
            self.assertIn("status", cap.getvalue().lower())

    def test_rekey_changes_key(self):
        with _ZssHomeFixture() as fx:
            priv = self._setup_home(fx)
            src_path = fx.tmpdir / "app.py"
            src_path.write_text(
                '#<zss>{write_to!s.zspy\nX=1\n#<zss>{closing!write!s.zspy\n',
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(src_path), layers=3, in_place=True, no_clobber=False,
                dry_run=False, watch=False,
            )
            self.assertEqual(cmd_pack(pack_args), 0)
            self.assertTrue((fx.tmpdir / "s.zspy").exists())

            new_priv, new_pub = generate_keypair()
            new_key_path = fx.tmpdir / "new.key"
            atomic_write_bytes(new_key_path, serialize_private_key(new_priv), mode=0o600)
            old_key_path = fx.tmpdir / "old.key"
            atomic_write_bytes(old_key_path, serialize_private_key(priv), mode=0o600)

            old = sys.stdout
            cap = io.StringIO()
            sys.stdout = cap
            try:
                rc = cmd_rekey(argparse.Namespace(
                    old_key=str(old_key_path), new_key=str(new_key_path),
                    dir=str(fx.tmpdir), backup=False,
                ))
            finally:
                sys.stdout = old
            self.assertEqual(rc, 0)

            save_private_key(new_priv, PRIVATE_KEY_PATH)

            rc = cmd_verify(argparse.Namespace(file=str(src_path), dir=None))
            self.assertEqual(rc, 0)

    def test_demo_single(self):
        with _ZssHomeFixture():
            old = sys.stdout
            cap = io.StringIO()
            sys.stdout = cap
            try:
                rc = cmd_demo(argparse.Namespace(mode="single", debug=False))
            finally:
                sys.stdout = old
            self.assertEqual(rc, 0, f"stdout={cap.getvalue()!r}")
            self.assertIn("hello from zss demo", cap.getvalue())

    def test_demo_archive(self):
        with _ZssHomeFixture():
            old = sys.stdout
            cap = io.StringIO()
            sys.stdout = cap
            try:
                rc = cmd_demo(argparse.Namespace(mode="archive", debug=False))
            finally:
                sys.stdout = old
            self.assertEqual(rc, 0, f"stdout={cap.getvalue()!r}")
            self.assertIn("archive demo ok", cap.getvalue())


class TestState(unittest.TestCase):

    def setUp(self):
        global _STATE_CACHE, _STATE_DIRTY
        _STATE_CACHE = None
        _STATE_DIRTY = False

    def test_set_get(self):
        state_set("ns1", "key1", "val1")
        self.assertEqual(state_get("ns1", "key1"), "val1")

    def test_get_default(self):
        self.assertIsNone(state_get("nope", "nope"))
        self.assertEqual(state_get("nope", "nope", "def"), "def")

    def test_namespaces_isolated(self):
        state_set("ns1", "k", "v1")
        state_set("ns2", "k", "v2")
        self.assertEqual(state_get("ns1", "k"), "v1")
        self.assertEqual(state_get("ns2", "k"), "v2")

    def test_reset_namespace(self):
        state_set("ns1", "k", "v")
        state_set("ns2", "k", "v")
        state_reset("ns1")
        self.assertIsNone(state_get("ns1", "k"))
        self.assertEqual(state_get("ns2", "k"), "v")

    def test_reset_all(self):
        state_set("ns1", "k", "v")
        state_set("ns2", "k", "v")
        state_reset()
        self.assertIsNone(state_get("ns1", "k"))
        self.assertIsNone(state_get("ns2", "k"))

    def test_state_save_no_warning_when_no_zson(self):
        with _ZssHomeFixture() as fx:
            state_set("ns", "k", "v")
            old_err = sys.stderr
            cap_err = io.StringIO()
            sys.stderr = cap_err
            try:
                state_save()
            finally:
                sys.stderr = old_err
            self.assertEqual(cap_err.getvalue(), "")
            state_reset()


class TestCaches(unittest.TestCase):

    def setUp(self):
        _LOAD_CACHE.clear()
        _IMPORT_CACHE.clear()

    def test_cache_get_set(self):
        _cache_set(_LOAD_CACHE, "key", 1.0, {"X": 1})
        result = _cache_get(_LOAD_CACHE, "key", 1.0)
        self.assertEqual(result, {"X": 1})

    def test_cache_invalidated_on_mtime(self):
        _cache_set(_LOAD_CACHE, "key", 1.0, {"X": 1})
        result = _cache_get(_LOAD_CACHE, "key", 2.0)
        self.assertIsNone(result)

    def test_cache_miss(self):
        result = _cache_get(_LOAD_CACHE, "nonexistent", 1.0)
        self.assertIsNone(result)


class TestZeroFillCtypes(unittest.TestCase):

    def test_zero_fill_bytearray_zeros(self):
        b = bytearray(b"\x01\x02\x03\x04\x05")
        zero_fill(b)
        self.assertEqual(bytes(b), b"\x00\x00\x00\x00\x00")

    def test_zero_fill_empty(self):
        b = bytearray()
        zero_fill(b)
        self.assertEqual(len(b), 0)

    def test_zero_fill_none(self):
        zero_fill(None)

    def test_zero_fill_large(self):
        b = bytearray(os.urandom(1024))
        zero_fill(b)
        self.assertEqual(bytes(b), b"\x00" * 1024)


class TestImprovements(unittest.TestCase):

    def _setup_home(self, fx):
        _ensure_dir(KEYS_DIR, mode=0o700)
        priv, pub = generate_keypair()
        save_private_key(priv, PRIVATE_KEY_PATH)
        save_public_key(pub, PUBLIC_KEY_PATH)
        init_zson(priv, ZSON_PATH)
        return priv

    def test_packed_py_with_from_zss_import_only(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            src_path = fx.tmpdir / "app.py"
            src_path.write_text(
                '#<zss>{write_to!s.zspy\n'
                'import sys\nsys.stdout.write("from-import-ok\\n")\n'
                '#<zss>{closing!write!s.zspy\n',
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(src_path), layers=3, in_place=True, no_clobber=False,
                dry_run=False, watch=False,
            )
            self.assertEqual(cmd_pack(pack_args), 0)
            packed = src_path.read_text(encoding="utf-8")
            self.assertIn("from zss import load", packed)
            run_args = argparse.Namespace(
                file=str(src_path), arg=[], debug=False, trace=False, time=False,
            )
            old = sys.stdout
            cap = io.StringIO()
            sys.stdout = cap
            try:
                rc = cmd_run(run_args)
            finally:
                sys.stdout = old
            self.assertEqual(rc, 0, f"stdout={cap.getvalue()!r}")
            self.assertIn("from-import-ok", cap.getvalue())

    def test_help_alias_top_level(self):
        parser = build_arg_parser()
        old = sys.stdout
        cap = io.StringIO()
        sys.stdout = cap
        try:
            rc = _cmd_help_alias(argparse.Namespace(command=None))
        finally:
            sys.stdout = old
        self.assertEqual(rc, 0)
        self.assertIn("usage:", cap.getvalue())

    def test_help_alias_specific_command(self):
        old = sys.stdout
        cap = io.StringIO()
        sys.stdout = cap
        try:
            rc = _cmd_help_alias(argparse.Namespace(command="pack"))
        finally:
            sys.stdout = old
        self.assertEqual(rc, 0)
        self.assertIn("pack", cap.getvalue())

    def test_help_alias_unknown_command(self):
        rc = _cmd_help_alias(argparse.Namespace(command="nonexistent"))
        self.assertEqual(rc, 2)

    def test_lint_detects_weak_layers(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            src = fx.tmpdir / "app.py"
            src.write_text(
                '#<zss>{write_to!s.zspy\nX=1\n#<zss>{closing!write!s.zspy\n',
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(src), layers=1, in_place=True, no_clobber=False,
                dry_run=False, watch=False,
            )
            self.assertEqual(cmd_pack(pack_args), 0)
            old = sys.stdout
            cap = io.StringIO()
            sys.stdout = cap
            try:
                cmd_lint(argparse.Namespace(dir=str(fx.tmpdir), fix=False))
            finally:
                sys.stdout = old
            self.assertIn("weak_layers", cap.getvalue())

    def test_lint_detects_stale_zspy(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            src = fx.tmpdir / "app.py"
            src.write_text(
                '#<zss>{write_to!s.zspy\nX=1\n#<zss>{closing!write!s.zspy\n',
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(src), layers=3, in_place=True, no_clobber=False,
                dry_run=False, watch=False,
            )
            self.assertEqual(cmd_pack(pack_args), 0)
            import time as _t
            zspy_path = fx.tmpdir / "s.zspy"
            _t.sleep(0.05)
            os.utime(src, None)
            old = sys.stdout
            cap = io.StringIO()
            sys.stdout = cap
            try:
                cmd_lint(argparse.Namespace(dir=str(fx.tmpdir), fix=False))
            finally:
                sys.stdout = old
            self.assertIn("stale", cap.getvalue())

    def test_thread_safe_state_concurrent(self):
        import threading
        state_reset()
        errors = []
        def worker(tid):
            try:
                for i in range(50):
                    state_set(f"ns{tid}", f"key{i}", i)
                    v = state_get(f"ns{tid}", f"key{i}")
                    assert v == i, f"thread {tid}: expected {i}, got {v}"
            except Exception as e:
                errors.append(e)
        threads = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        for tid in range(4):
            self.assertEqual(state_get(f"ns{tid}", "key0"), 0)
            self.assertEqual(state_get(f"ns{tid}", "key49"), 49)
        state_reset()

    def test_decrypt_const_invalidated_on_mtime(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            src = fx.tmpdir / "app.py"
            src.write_text(
                'import zss\n'
                'V = zss.const("c.zspy", "V", "v1")\n'
                'print(V)\n',
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(src), layers=3, in_place=True, no_clobber=False,
                dry_run=False, watch=False,
            )
            self.assertEqual(cmd_pack(pack_args), 0)
            run_args = argparse.Namespace(
                file=str(src), arg=[], debug=False, trace=False, time=False,
            )
            old = sys.stdout
            cap1 = io.StringIO()
            sys.stdout = cap1
            try:
                cmd_run(run_args)
            finally:
                sys.stdout = old
            self.assertIn("v1", cap1.getvalue())
            _CONST_CACHE.clear()
            src.write_text(
                'import zss\n'
                'V = zss.const("c.zspy", "V", "v2")\n'
                'print(V)\n',
                encoding="utf-8",
            )
            self.assertEqual(cmd_pack(pack_args), 0)
            cap2 = io.StringIO()
            sys.stdout = cap2
            try:
                cmd_run(run_args)
            finally:
                sys.stdout = old
            self.assertIn("v2", cap2.getvalue())

    def test_verify_share_format_zspy(self):
        with _ZssHomeFixture() as fx:
            self._setup_home(fx)
            src = fx.tmpdir / "app.py"
            src.write_text(
                '#<zss>{write_to!s.zspy\nX=1\n#<zss>{closing!write!s.zspy\n',
                encoding="utf-8",
            )
            pack_args = argparse.Namespace(
                file=str(src), layers=3, in_place=True, no_clobber=False,
                dry_run=False, watch=False,
            )
            self.assertEqual(cmd_pack(pack_args), 0)
            out = fx.tmpdir / "share.py"
            share_args = argparse.Namespace(
                file=str(src), out=str(out),
                password="pw", password_file=None,
            )
            self.assertEqual(cmd_share(share_args), 0)
            content = out.read_text(encoding="utf-8")
            import re as _re
            m = _re.search(r'EMBEDDED_ZSPY\s*=\s*(\{[^}]+\})', content)
            self.assertIsNotNone(m)
            embedded = json.loads(m.group(1))
            self.assertIn("s.zspy", embedded)
            share_zspy = fx.tmpdir / "shared.zspy"
            share_zspy.write_bytes(_b64d(embedded["s.zspy"]))
            old = sys.stdout
            cap = io.StringIO()
            sys.stdout = cap
            try:
                rc = cmd_verify(argparse.Namespace(file=str(share_zspy), dir=None))
            finally:
                sys.stdout = old
            self.assertEqual(rc, 0)
            self.assertIn("share-single", cap.getvalue())
            self.assertIn("password required", cap.getvalue())


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--test":
        sys.argv = [sys.argv[0], "test"] + sys.argv[2:]
    sys.exit(main())
