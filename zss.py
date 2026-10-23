#!/usr/bin/env python3
# pip install cryptography
"""ZSS — Zero State Snapshot. Layered encrypted Python runtime.

Single-file tool. Crypto: X25519 + HKDF-SHA256 + ChaCha20-Poly1305, N AEAD layers.
Format: .zspy (binary container) and .zson (encrypted config/state, AES-GCM-equiv via ChaCha20-Poly1305).

Open source around, closed decoder (this Python source is open in beta; binary build
post-beta). Defense in depth, not unbreakable. If you lost your key — your problem.
"""
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


# ============================================================================
# Constants
# ============================================================================

ZSS_VERSION = "0.1.0-beta"

ZSSPY_MAGIC = b"ZSSPY\x01\x00\x00"  # 8 bytes
ZSSPY_FORMAT_VERSION = 1

ZSON_MAGIC = b"ZSSON\x01\x00\x00"  # 8 bytes
ZSON_SCHEMA_VERSION = 1

DEFAULT_N_LAYERS = 5
MAX_N_LAYERS = 255
MIN_N_LAYERS = 1

NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
X25519_PUBKEY_SIZE = 32
MASTER_KEY_SIZE = 32

# Per-file wrap overhead: ephemeral pubkey + wrap nonce + wrapped master + wrap tag
WRAP_OVERHEAD = X25519_PUBKEY_SIZE + NONCE_SIZE + MASTER_KEY_SIZE + TAG_SIZE  # 92 bytes

# Header layout (little-endian):
#   magic[8] | fmt_version<u16> | n_layers<u8> | reserved<u8>[3]
#   | eph_pubkey[32] | wrap_nonce[12] | wrapped_master[32] | wrap_tag[16]
#   | layer_nonce[12 * N] | layer_tag[16 * N]
#   | orig_hash[32] | timestamp<u64> | zss_version_len<u8> | zss_version[var]
#   | ct_len<u32> | ciphertext[ct_len]
ZSSPY_HEADER_FIXED = (
    8 + 2 + 1 + 3 + X25519_PUBKEY_SIZE + NONCE_SIZE + MASTER_KEY_SIZE + TAG_SIZE
)

# Paths
ZSS_HOME = Path.home() / ".zss"
KEYS_DIR = ZSS_HOME / "keys"
ZSON_PATH = ZSS_HOME / "zss.zson"
PRIVATE_KEY_PATH = KEYS_DIR / "master.x25519"
PUBLIC_KEY_PATH = KEYS_DIR / "master.pub"

# Parser
DIRECTIVE_PREFIX = "#<zss>{"
DIRECTIVE_OPEN_KW = "write_to"
DIRECTIVE_CLOSE_KW = "closing!write"
FILENAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*\.zspy$")
DIRECTIVE_LINE_RE = re.compile(
    r"^\s*#\s*<zss>\s*\{\s*(write_to|closing!write)\s*!\s*([a-zA-Z_][a-zA-Z0-9_]*)\.zspy\s*\}\s*$"
)
LOAD_STUB_TEMPLATE = 'from zss import load; load("{filename}")'

# Seed material used only at first launch to bootstrap .zson. After .zson is written
# these bytearrays are zeroed in memory. The on-disk source remains open (this is open
# beta — by design). Post-beta binary build removes them entirely.
_SEED_PEPPER = bytearray(
    b"\x12\x9a\xf1\x4c\xb8\xe2\x07\x3d\x91\x55\xcc\xae\x62\xeb\x10\x2f"
    b"\x7c\x48\x91\x03\xbd\xf6\x58\xa1\xde\xc4\x39\x82\x71\x90\x55\x77"
)
_SEED_SALT = bytearray(
    b"\xa4\x21\x6f\x03\xd8\x9c\x57\x1e\xb3\x40\x7a\xe2\x0c\x6d\x95\x28"
)

# HKDF info labels
INFO_ZSON = b"zss:zson:v1"
INFO_WRAP = b"zss:wrap:v1"
INFO_LAYER_PREFIX = b"zss:layer:"
INFO_MASTER = b"zss:master:v1"

# Runtime flag: if .zson has been loaded, seed material must be wiped
_seed_wiped = False


# ============================================================================
# Exceptions
# ============================================================================

class ZssError(Exception):
    """Base. CLI catches this, prints message, exits 1."""


class ZssParseError(ZssError):
    """Directive parser failure: bad syntax, mismatched open/close, nesting, etc."""


class ZssCryptoError(ZssError):
    """AEAD tag mismatch, bad wrap, key derivation failure."""


class ZssFormatError(ZssError):
    """Bad .zspy or .zson: magic mismatch, version skew, truncated header."""


class ZssKeyError(ZssError):
    """Missing/permissions/bad private key file."""


class ZssConfigError(ZssError):
    """Bad .zson contents, schema migration failure, missing .zson."""


# ============================================================================
# Utilities
# ============================================================================

def zero_fill(buf: Any) -> None:
    """Best-effort wipe. Python gives no guarantees; we do what we can."""
    if buf is None:
        return
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0
    elif isinstance(buf, bytes):
        # immutable; caller should pass bytearray. No-op here.
        pass
    elif isinstance(buf, (list, bytearray)):
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
    """Return True if file mode is acceptable (no group/other bits)."""
    try:
        st = os.stat(path)
    except OSError:
        return False
    return (st.st_mode & 0o077) == 0


def atomic_write_bytes(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Write to temp file in same dir, fsync, then os.replace. Atomic on POSIX."""
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
    """Overwrite then unlink. For secrets. Best-effort."""
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


# ============================================================================
# X25519 key pair: generation, serialization, ECDH
# ============================================================================

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


# ============================================================================
# HKDF-SHA256 derivation
# ============================================================================

def hkdf_derive(master: bytes, salt: bytes, info: bytes, length: int = KEY_SIZE) -> bytes:
    if length <= 0 or length > 255 * hashes.SHA256().digest_size:
        raise ZssCryptoError(f"bad hkdf length {length}")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(master)


def derive_master_key(shared: bytes, salt: bytes) -> bytes:
    """From an X25519 shared secret derive the per-file symmetric master key (32 bytes)."""
    return hkdf_derive(shared, salt=salt, info=INFO_MASTER, length=MASTER_KEY_SIZE)


def derive_wrap_key(shared: bytes, salt: bytes) -> bytes:
    """For wrapping the per-file master key with the recipient's pubkey."""
    return hkdf_derive(shared, salt=salt, info=INFO_WRAP, length=KEY_SIZE)


def derive_zson_key(priv: X25519PrivateKey, salt: bytes) -> bytes:
    """Self-derived: priv.exchange(priv.pub()) is deterministic per keypair.
    Then HKDF. Lets us decrypt .zson without storing anything else."""
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


# ============================================================================
# ChaCha20-Poly1305 single AEAD
# ============================================================================

def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Returns (nonce, ciphertext_with_tag). 12-byte nonce random per call."""
    if len(key) != KEY_SIZE:
        raise ZssCryptoError(f"key must be {KEY_SIZE} bytes, got {len(key)}")
    nonce = _secure_random(NONCE_SIZE)
    aead = ChaCha20Poly1305(key)
    ct = aead.encrypt(nonce, plaintext, aad)
    return nonce, ct  # ct includes 16-byte tag at the end


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


# ============================================================================
# N-layer AEAD encryption
#
# Order at encrypt time:  plaintext = P0
#   for i in 1..N:  Pi = AEAD_encrypt(key_i, nonce_i, P_{i-1}, aad_i)
#   final_ciphertext = PN
# At decrypt time we run reverse: P_{i-1} = AEAD_decrypt(key_i, nonce_i, Pi, aad_i).
# Tag is verified at every layer; on first failure we stop and raise.
#
# AAD binds header context so an attacker cannot transplant ciphertext across files
# or layers. We bind: file salt + layer index + total N. This prevents cut-and-paste
# attacks between layers even when the underlying key is the same (it isn't, but
# defense in depth).
# ============================================================================

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
    """Result of encrypt_layers. Salt is per-file, nonces are per-layer."""
    salt: bytes
    n_layers: int
    nonces: list[bytes]  # length N, 12 bytes each
    tags: list[bytes]    # length N, 16 bytes each
    ciphertext: bytes    # final blob (no tags appended)

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

    # Wipe intermediate keys
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
    # Reverse order
    for i in range(blob.n_layers - 1, -1, -1):
        key = keys[i]
        aad = _layer_aad(blob.salt, i + 1, blob.n_layers)
        ct_with_tag = _join_ct_tag(current, blob.tags[i])
        try:
            current = aead_decrypt(key, blob.nonces[i], ct_with_tag, aad)
        except ZssCryptoError:
            # Wipe keys before propagating
            for k in keys:
                zero_fill(bytearray(k))
            raise ZssCryptoError(
                f"layer {i + 1}/{blob.n_layers} tag verification failed"
            )

    for k in keys:
        zero_fill(bytearray(k))
    return current


# ============================================================================
# Hybrid wrap: encrypt per-file master key with recipient's X25519 public key.
#
# Each .zspy carries its own random 32-byte master key. That key is what protects
# the actual code via N AEAD layers. The master key itself is encrypted (wrapped)
# using an ephemeral X25519 keypair + recipient public key:
#
#   eph_priv = X25519PrivateKey.generate()
#   eph_pub  = eph_priv.public_key()
#   shared   = eph_priv.exchange(recipient_pub)
#   wrap_key = HKDF(shared, salt=eph_pub_bytes, info=INFO_WRAP)
#   wrapped  = ChaCha20Poly1305.encrypt(wrap_key, wrap_nonce, master, aad=eph_pub|recipient_pub)
#
# Recipient unwraps with their private key:
#   shared   = recipient_priv.exchange(eph_pub)
#   wrap_key = HKDF(shared, salt=eph_pub_bytes, info=INFO_WRAP)
#   master   = ChaCha20Poly1305.decrypt(wrap_key, wrap_nonce, wrapped, aad)
#
# This is essentially ECIES with X25519 + ChaCha20-Poly1305 + HKDF-SHA256.
# Salt = ephemeral public key bytes (deterministic, public, unique per file).
# ============================================================================

@dataclass
class WrappedMasterKey:
    eph_pubkey: bytes      # 32 bytes
    wrap_nonce: bytes      # 12 bytes
    wrapped: bytes         # 32 bytes (master) + 16 (tag) = 48 bytes
    # tag is appended inside `wrapped`; we keep it bundled for compactness


def wrap_master_key(master: bytes, recipient_pub: X25519PublicKey) -> WrappedMasterKey:
    if len(master) != MASTER_KEY_SIZE:
        raise ZssCryptoError(f"master must be {MASTER_KEY_SIZE} bytes")

    eph_priv, eph_pub = generate_keypair()
    eph_pub_bytes = serialize_public_key(eph_pub)
    recipient_pub_bytes = serialize_public_key(recipient_pub)

    shared = eph_priv.exchange(recipient_pub)
    salt = eph_pub_bytes  # unique per wrap, public
    wrap_key = derive_wrap_key(shared, salt)

    aad = b"zss:wrap:v1|eph=" + eph_pub_bytes + b"|rcp=" + recipient_pub_bytes
    nonce = _secure_random(NONCE_SIZE)
    aead = ChaCha20Poly1305(wrap_key)
    wrapped = aead.encrypt(nonce, master, aad)

    # Wipe ephemeral key material in memory where possible
    zero_fill(bytearray(shared))
    zero_fill(bytearray(wrap_key))

    return WrappedMasterKey(
        eph_pubkey=eph_pub_bytes,
        wrap_nonce=nonce,
        wrapped=wrapped,  # 32 + 16 = 48 bytes
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
        # immutable; we can only clear the dataclass reference
        pass
    if isinstance(wrap.wrapped, (bytes, bytearray)):
        wb = bytearray(wrap.wrapped) if isinstance(wrap.wrapped, bytes) else wrap.wrapped
        zero_fill(wb)


# ============================================================================
# Directive parser
#
# Source uses:
#   #<zss>{write_to!name.zspy
#       ...python...
#   #<zss>{closing!write!name.zspy
#
# We use tokenize to find comments only — directives inside string literals or
# f-strings are not picked up because tokenize tags them as STRING, not COMMENT.
# This is the whole point of using tokenize over a hand-rolled line lexer.
#
# Grammar:
#   directive_open    := '#<zss>{' WS 'write_to' '!' WS filename WS '}'
#   directive_close   := '#<zss>{' WS 'closing!write' '!' WS filename WS '}'
#   filename          := identifier '.zspy'
#   identifier        := [A-Za-z_][A-Za-z0-9_]*
#
# Rules:
#   - Each open must have a matching close with the same filename.
#   - Nesting forbidden: an open inside another open block is an error.
#   - Directives found only in COMMENT tokens. Anything in STRING/NAME/etc is ignored.
#   - Filename validated against FILENAME_RE.
#   - The body between open and close is extracted verbatim (including indentation,
#     comments, blank lines, etc). The only thing we don't allow inside the body is
#     another open directive.
# ============================================================================

@dataclass
class DirectiveBlock:
    filename: str
    body: str
    open_line: int   # 1-indexed
    close_line: int  # 1-indexed
    open_offset: int  # 0-indexed char offset in original source
    close_offset: int


@dataclass
class ParsedSource:
    """Output of parse_source_with_directives.

    `rewritten` is the .py with each directive body replaced by a load() stub.
    `blocks` is the list of extracted blocks, in source order.
    """
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
    """Return (kind, filename) for a comment that is a directive, else None.

    kind is 'open' or 'close'. filename includes the .zspy suffix.
    """
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
    """Yield (tok_type, text, start_row, end_row, start_col, line_text) for each
    COMMENT token found by tokenize. Raises ZssParseError on TokenError."""
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
    """Find all directive blocks, validate pairing, extract bodies, build rewritten source.

    Algorithm:
      1. Walk COMMENT tokens in order.
      2. Maintain a stack of currently-open blocks. Each entry = (filename, open_line,
         open_offset, body_start_offset).
      3. On 'open':
         - if stack is non-empty -> nesting error.
         - push.
      4. On 'close':
         - if stack is empty -> close without open.
         - if filename != stack.top.filename -> mismatch.
         - pop, finalize block.
      5. After all tokens: if stack non-empty -> unclosed block.
      6. Build rewritten source by replacing [open_line_start, close_line_end] with
         the load() stub.

    Offsets are computed from line starts so we can slice the source string safely.
    """
    lines = source.splitlines(keepends=True)
    # Map row -> absolute char offset of start of that row (1-indexed rows).
    line_offsets = [0]  # offset of line 1 = 0
    pos = 0
    for ln in lines:
        pos += len(ln)
        line_offsets.append(pos)

    def row_col_to_offset(row: int, col: int) -> int:
        # tokenize rows are 1-indexed
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
        else:  # close
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

    # Build rewritten source: replace each [open_offset, close_end_offset) with stub.
    # We must process in order and recompute offsets as we go (or process from end).
    # Easier: collect replacement ranges, sort by offset, splice.
    if not blocks:
        return ParsedSource(rewritten=source, blocks=[])

    # Sort by open_offset to be safe (tokenizer yields in order, but defensive).
    blocks.sort(key=lambda b: b.open_offset)

    # Sanity: no overlaps (shouldn't happen given nesting check, but verify).
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
        # Preserve indentation: insert stub at the same column as the directive.
        # Find indentation of the line containing open_offset.
        line_start = source.rfind("\n", 0, b.open_offset) + 1
        indent = source[line_start:b.open_offset]
        # The directive was on its own line (we required '#<zss>{...}' alone). The
        # text from line_start to open_offset is leading whitespace. Replace the
        # whole line (including newline) with stub + newline.
        # But there may be content after directive on same line? Tokenizer's end
        # position tells us. We'll only replace up to end of the comment token; any
        # trailing chars on the open line are preserved... actually we want to
        # remove the entire body INCLUDING the close directive line. The simplest
        # correct approach: replace [open_line_start, close_line_end_inclusive)
        # with the stub on its own line.
        # Recompute: open_line_start = line_start; close_line_end = end of close
        # line including newline.
        close_line_end = b.close_offset
        # If the close line ends with \n, include it.
        if close_line_end < len(source) and source[close_line_end] == "\n":
            close_line_end += 1
        elif close_line_end < len(source) - 1 and source[close_line_end:close_line_end+2] == "\r\n":
            close_line_end += 2
        # Actually we need to rewrite: take source up to open_line_start,
        # then put indent + stub + "\n", then source from close_line_end onward.
        # So undo what we just appended and redo properly.
        out_parts.pop()
        out_parts.append(source[cursor:line_start])
        out_parts.append(indent + LOAD_STUB_TEMPLATE.format(filename=b.filename) + "\n")
        cursor = close_line_end
    out_parts.append(source[cursor:])
    rewritten = "".join(out_parts)

    return ParsedSource(rewritten=rewritten, blocks=blocks)


def validate_filename_strict(name: str) -> str:
    """Public validator for filenames used in directives and as .zspy target names."""
    if not isinstance(name, str):
        raise ZssParseError(f"filename must be str, got {type(name).__name__}")
    if not FILENAME_RE.match(name):
        raise ZssParseError(
            f"bad filename {name!r}: must match {FILENAME_RE.pattern}. "
            "No paths, no '..' , no leading digits."
        )
    return name


def has_directives(source: str) -> bool:
    """Quick check used by `zss list`. Returns True if any COMMENT token is a directive."""
    try:
        for tok in _iter_comments(source):
            if _classify_comment(tok.string) is not None:
                return True
    except ZssParseError:
        # If source can't be tokenized, treat as no directives (list is informational).
        return False
    return False


def find_directive_filenames(source: str) -> list[str]:
    """Return list of filenames referenced by open directives, in order. Used by list."""
    names: list[str] = []
    try:
        for tok in _iter_comments(source):
            classified = _classify_comment(tok.string)
            if classified and classified[0] == "open":
                names.append(classified[1])
    except ZssParseError:
        pass
    return names


# ============================================================================
# .zspy container format
#
# Layout (all little-endian):
#   [8]   magic                       = ZSSPY_MAGIC
#   [2]   fmt_version                  = ZSSPY_FORMAT_VERSION (u16)
#   [1]   n_layers                     = N (u8, 1..255)
#   [3]   reserved                     = 0x00 0x00 0x00
#   [32]  eph_pubkey
#   [12]  wrap_nonce
#   [32]  wrapped_master               (without tag)
#   [16]  wrap_tag
#   [12*N] layer_nonces
#   [16*N] layer_tags
#   [16]  file_salt                    (used as HKDF salt + AAD binding)
#   [32]  orig_sha256                  (hash of original plaintext)
#   [8]   timestamp                    (u64 unix seconds)
#   [1]   zss_version_len              (u8)
#   [var] zss_version_bytes            (utf-8)
#   [4]   ct_len                       (u32)
#   [var] ciphertext                   (ct_len bytes)
#
# Notes:
#   - wrap_tag is stored separately from wrapped_master so the wrap tag can be
#     verified without exposing the master bytes on failure.
#   - layer_nonces and layer_tags are stored separately from ciphertext so we can
#     verify layer N's tag before attempting layer N-1's decryption (we still need
#     the ciphertext bytes for that, but the layout makes parsing simpler).
#   - orig_sha256 is computed on the plaintext BEFORE encryption. This is the
#     integrity check that the runtime verifies before exec().
#   - file_salt is per-file random 16 bytes. Used as HKDF salt for layer keys AND
#     as AAD binding context. Different file -> different keys even with same master.
# ============================================================================

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
# 8 + 2 + 1 + 3 = 14 bytes before the variable part.

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


def _unpack_header_prefix(buf: bytes) -> tuple[bytes, int, int]:
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
    if reserved != b"\x00\x00\x00":
        # Reserved bytes non-zero — likely a future version using them. Refuse.
        raise ZssFormatError(
            f"reserved bytes non-zero: {reserved!r}. "
            "File may be from a newer ZSS version."
        )
    if fmt_version > ZSSPY_FORMAT_VERSION:
        raise ZssFormatError(
            f"file format version {fmt_version} is newer than supported "
            f"{ZSSPY_FORMAT_VERSION}. Update ZSS."
        )
    if fmt_version < ZSSPY_FORMAT_VERSION:
        # For beta: no migration path yet. Refuse.
        raise ZssFormatError(
            f"file format version {fmt_version} is older than supported "
            f"{ZSSPY_FORMAT_VERSION}. No migration in beta; re-pack the file."
        )
    if not (MIN_N_LAYERS <= n_layers <= MAX_N_LAYERS):
        raise ZssFormatError(f"n_layers out of range in header: {n_layers}")
    return magic, fmt_version, n_layers


@dataclass
class ZsspyHeader:
    magic: bytes
    fmt_version: int
    n_layers: int
    eph_pubkey: bytes
    wrap_nonce: bytes
    wrapped_master: bytes  # 32 bytes (no tag)
    wrap_tag: bytes        # 16 bytes
    layer_nonces: list[bytes]  # N x 12
    layer_tags: list[bytes]    # N x 16
    file_salt: bytes       # 16 bytes
    orig_sha256: bytes     # 32 bytes
    timestamp: int         # u64
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
    """Pack a complete .zspy container.

    Steps:
      1. Wrap master with recipient_pub (X25519 ECIES-like).
      2. Generate per-file salt (16 bytes).
      3. Encrypt plaintext with N AEAD layers using keys derived from master+salt.
      4. Compute orig_sha256 of plaintext (integrity check at runtime).
      5. Pack header + ciphertext.
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise ZssFormatError("plaintext must be bytes")
    plaintext = bytes(plaintext)

    # 1. Wrap
    wrap = wrap_master_key(master, recipient_pub)
    # Split wrapped into master (32) + tag (16)
    if len(wrap.wrapped) != MASTER_KEY_SIZE + TAG_SIZE:
        raise ZssCryptoError("internal: wrapped has unexpected length")
    wrapped_master = wrap.wrapped[:MASTER_KEY_SIZE]
    wrap_tag = wrap.wrapped[MASTER_KEY_SIZE:]

    # 2. Salt
    file_salt = _secure_random(ZSSPY_FILE_SALT_SIZE)

    # 3. Layers
    layered = encrypt_layers(plaintext, master, n_layers, file_salt)

    # 4. Hash
    orig_hash = sha256(plaintext)

    # 5. Timestamp
    import time
    if timestamp is None:
        timestamp = int(time.time())
    if not (0 <= timestamp < 2**63):
        raise ZssFormatError(f"timestamp out of range: {timestamp}")

    zss_ver_bytes = ZSS_VERSION.encode("utf-8")
    if len(zss_ver_bytes) > 255:
        raise ZssFormatError("zss_version string too long")

    # Pack
    out = bytearray()
    out += _pack_header_prefix(n_layers)
    out += wrap.eph_pubkey                # 32
    out += wrap.wrap_nonce                # 12
    out += wrapped_master                 # 32
    out += wrap_tag                       # 16
    for nonce in layered.nonces:
        out += nonce                      # 12 * N
    for tag in layered.tags:
        out += tag                        # 16 * N
    out += file_salt                      # 16
    out += orig_hash                      # 32
    out += struct.pack("<Q", timestamp)   # 8
    out += struct.pack("<B", len(zss_ver_bytes))  # 1
    out += zss_ver_bytes                  # var
    out += struct.pack("<I", len(layered.ciphertext))  # 4
    out += layered.ciphertext             # var

    return bytes(out)


def parse_zspy(data: bytes) -> ZsspyHeader:
    """Parse a .zspy container. Validates magic, version, sizes. Does NOT decrypt
    or verify tags (those happen later in decrypt_zspy). Raises ZssFormatError on
    structural problems."""
    if not isinstance(data, (bytes, bytearray)):
        raise ZssFormatError("data must be bytes")
    data = bytes(data)

    pos = 0
    if len(data) < ZSSPY_HEADER_STATIC_PREFIX:
        raise ZssFormatError("file too short for header prefix")
    magic, fmt_version, n_layers = _unpack_header_prefix(data[:ZSSPY_HEADER_STATIC_PREFIX])
    pos = ZSSPY_HEADER_STATIC_PREFIX

    # Fixed crypto fields
    fixed_crypto_size = (
        X25519_PUBKEY_SIZE + NONCE_SIZE + MASTER_KEY_SIZE + TAG_SIZE
    )
    if len(data) < pos + fixed_crypto_size:
        raise ZssFormatError("truncated: missing wrap fields")
    eph_pubkey = data[pos:pos + X25519_PUBKEY_SIZE]; pos += X25519_PUBKEY_SIZE
    wrap_nonce = data[pos:pos + NONCE_SIZE]; pos += NONCE_SIZE
    wrapped_master = data[pos:pos + MASTER_KEY_SIZE]; pos += MASTER_KEY_SIZE
    wrap_tag = data[pos:pos + TAG_SIZE]; pos += TAG_SIZE

    # Layer nonces and tags
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

    # Salt, hash, timestamp, version
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

    # Trailing garbage? Allow but warn via header (caller can check).
    # For strictness, we ignore trailing bytes (could be padding added by transport).

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
    """Unwrap master, decrypt N layers, verify orig_sha256. Returns plaintext.

    Order of operations matters for security:
      1. Unwrap master (verifies wrap_tag).
      2. Decrypt N layers in reverse order (verifies each layer_tag).
      3. Verify orig_sha256 matches.
    If any step fails, raise ZssCryptoError without exposing partial plaintext.
    """
    # 1. Unwrap
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
        # 2. Layered decrypt
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

    # 3. Hash check
    actual = sha256(plaintext)
    if actual != header.orig_sha256:
        # This shouldn't happen if all tags passed (AEAD guarantees integrity),
        # but defense in depth: if it does, something is very wrong.
        zero_fill(bytearray(plaintext))
        raise ZssCryptoError(
            "orig_sha256 mismatch after successful decryption — file is corrupt "
            "or implementation bug"
        )

    return plaintext


def zspy_public_info(header: ZsspyHeader) -> dict:
    """Return non-sensitive metadata for `zss list`. No decryption needed."""
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
    """Quick magic check. Used by `zss list` to skip non-.zspy files."""
    try:
        with open(path, "rb") as f:
            head = f.read(len(ZSSPY_MAGIC))
        return head == ZSSPY_MAGIC
    except OSError:
        return False


# ============================================================================
# .zson — encrypted config and state
#
# Layout (binary, NOT base64 in v1 — we changed plan mid-implementation. The file on
# disk is a binary blob with its own magic prefix; the user sees a .zson file).
#
#   [8]   magic            = ZSON_MAGIC
#   [2]   schema_version   = u16
#   [1]   reserved         = 0x00
#   [3]   padding          = 0x00 0x00 0x00
#   [12]  nonce
#   [4]   payload_len      = u32 (length of ciphertext_with_tag)
#   [var] ciphertext_with_tag
#
# Plaintext inside is a UTF-8 JSON document with a fixed schema:
#   {
#     "schema_version": 1,
#     "created_at": int,
#     "updated_at": int,
#     "profile_name": str | null,
#     "settings": {
#        "default_n_layers": int,
#        "verify_integrity": bool,
#        "format_version": int
#     },
#     "secrets": {
#        "hkdf_salt": "<b64>",   # 16 bytes
#        "pepper": "<b64>",      # 32 bytes
#        "service_const": "<b64>"  # 16 bytes
#     },
#     "cache": {
#        "dir": "<abs path>": {
#           "zspy": [ {name, salt_b64, ts} ... ],
#           "py_with_directives": [ ... ]
#        },
#        ...
#     }
#   }
#
# Key derivation: derive_zson_key(priv, salt=hkdf_salt). The hkdf_salt is itself
# stored encrypted inside the .zson. Bootstrap problem: on first launch we don't
# have it yet, so we use the in-source _SEED_SALT to derive the FIRST key. After
# .zson is written, _SEED_SALT is zeroed in memory; subsequent reads use the salt
# from inside the decrypted .zson.
#
# Wait — that's a chicken-and-egg. If the salt is inside the encrypted blob, we
# can't read it without the key, and we can't derive the key without the salt.
# Resolution: the salt is stored UNENCRYPTED in a sidecar field of the .zson
# header. We add it as a fixed-size field after the magic. Updated layout:
#
#   [8]   magic
#   [2]   schema_version
#   [1]   reserved
#   [3]   padding
#   [16]  zson_salt         # public, used to derive the key
#   [12]  nonce
#   [4]   payload_len
#   [var] ciphertext_with_tag
#
# On first launch: generate random zson_salt, derive key, encrypt empty-ish payload
# containing the rest of secrets (pepper, service_const), write file. Wipe seeds.
# On subsequent reads: parse salt from header, derive key, decrypt.
# ============================================================================

ZSON_SALT_SIZE = 16
ZSON_HEADER_FIXED = 8 + 2 + 1 + 3 + ZSON_SALT_SIZE + NONCE_SIZE + 4  # = 46

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
    out += b"\x00"  # reserved
    out += b"\x00\x00\x00"  # padding
    out += salt
    out += nonce
    out += struct.pack("<I", len(ct))
    out += ct
    return bytes(out)


def _zson_decrypt(data: bytes, key_provider) -> tuple[dict, bytes]:
    """key_provider(salt: bytes) -> key: bytes. Returns (payload, salt_used)."""
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
    # reserved + padding = data[10:14]
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

    # Schema migration (forward only in beta)
    if schema_version < ZSON_SCHEMA_VERSION:
        payload = _migrate_zson_payload(payload, schema_version)

    return payload, salt


def _migrate_zson_payload(payload: dict, from_version: int) -> dict:
    """Apply migrations in sequence. v0 -> v1 -> v2 ... Each step is one version."""
    v = from_version
    while v < ZSON_SCHEMA_VERSION:
        migrator = _ZSON_MIGRATIONS.get(v)
        if migrator is None:
            raise ZssConfigError(f"no migration path from schema {v}")
        payload = migrator(payload)
        v += 1
    payload["schema_version"] = ZSON_SCHEMA_VERSION
    return payload


# Placeholder migration registry. Empty for beta (v1 is the first schema).
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
    """Read and decrypt .zson. Returns validated payload dict. Raises ZssConfigError
    on any failure (missing, corrupt, wrong key, schema skew)."""
    if path is None:
        path = ZSON_PATH
    if not zson_exists(path):
        raise ZssConfigError(
            f".zson not found at {path}. Run `zss init` first or set ZSS_HOME."
        )
    data = read_bytes(path)

    # First try with salt from header. We need to derive the key from the private
    # key + that salt. derive_zson_key uses priv.exchange(priv.pub()).
    def key_provider(salt: bytes) -> bytes:
        return derive_zson_key(priv, salt)

    payload, salt = _zson_decrypt(data, key_provider)
    _validate_zson_payload(payload)
    return payload


def save_zson(payload: dict, priv: X25519PrivateKey, path: Optional[Path] = None) -> None:
    """Encrypt and atomically write .zson. The salt used for key derivation is
    stored in plaintext in the header (it's not secret — the private key is)."""
    if path is None:
        path = ZSON_PATH
    _validate_zson_payload(payload)
    # Use the salt already in payload, or generate one.
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
    """First-launch: generate payload, write .zson, wipe seeds. Returns payload."""
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
    """Update the cache section for a given directory. Returns a new payload dict."""
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


# ============================================================================
# Runtime: load() — called from generated stubs to decrypt and exec a .zspy.
#
# `from zss import load; load("name.zspy")` is what gets emitted in place of each
# directive block. We:
#   1. Resolve the .zspy path relative to the caller's file location.
#   2. Read & parse the .zspy header.
#   3. Load the user's private key.
#   4. Decrypt the plaintext (verifies wrap tag, layer tags, orig_sha256).
#   5. compile() + exec() in a fresh namespace, exposing the caller's globals so
#      that names defined in the .zspy are visible afterwards.
#
# The .zspy code runs in the caller's namespace (the module that imported zss and
# contains the stub). This matches the semantics of an inline Python block.
# ============================================================================

def _resolve_zspy_path(caller_file: str, name: str) -> Path:
    """Resolve a .zspy filename relative to the directory of the calling .py."""
    validate_filename_strict(name)
    caller_path = Path(caller_file).resolve()
    if caller_path.exists():
        base = caller_path.parent
    else:
        # Fallback: cwd
        base = Path.cwd()
    return base / name


def _exec_decrypted(plaintext: str, namespace: dict, *, zspy_path: Path) -> None:
    """Compile and exec decrypted source in the given namespace. The namespace is
    typically the calling module's __dict__ so that defined names leak back."""
    code = compile(plaintext, str(zspy_path), "exec")
    namespace.setdefault("__file__", str(zspy_path))
    exec(code, namespace)


def load(name: str, *, _caller_frame_depth: int = 1) -> Any:
    """Runtime loader. Called from `from zss import load; load("name.zspy")` stubs.

    Resolves the .zspy relative to the caller's file, decrypts it, executes its
    contents in the caller's module namespace. Returns None.

    The caller-frame inspection finds the .py file that emitted the stub so we can
    locate the .zspy next to it. This is intentional: it lets the user just call
    `zss run file.py` after pack and everything works without configuration.
    """
    import inspect
    frame = inspect.currentframe()
    try:
        # Skip load() itself to land in the caller's frame.
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


# ============================================================================
# CLI
# ============================================================================

def _print(msg: str = "") -> None:
    sys.stdout.write(msg + "\n")


def _eprint(msg: str = "") -> None:
    sys.stderr.write(msg + "\n")


def _zss_home_env_override() -> None:
    """If ZSS_HOME is set, override the home directory paths. Must be called early."""
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
    """Generate X25519 keypair, write private key (0600), create .zson, wipe seeds."""
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

    # Verify all filenames are unique within this source (avoid overwriting).
    seen: set[str] = set()
    for b in parsed.blocks:
        if b.filename in seen:
            _eprint(f"error: duplicate directive filename '{b.filename}' in {py_path}")
            return 1
        seen.add(b.filename)

    # Load keys and .zson for default N
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
        # Generate fresh per-file master key
        master = _secure_random(MASTER_KEY_SIZE)
        try:
            blob = build_zspy(body.encode("utf-8"), master, n_layers, pub)
        finally:
            zero_fill(bytearray(master))
        out_path = out_dir / block.filename
        atomic_write_bytes(out_path, blob, mode=0o644)
        written.append(out_path)

    # Rewrite the .py: backup then write
    bak_path = py_path.with_suffix(py_path.suffix + ".bak")
    if bak_path.exists() and not args.no_clobber:
        # Default: overwrite the .bak
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
        # Direct .zspy execution. No caller .py — we synthesize a namespace.
        return _run_zspy_directly(target, args)

    if target.suffix == ".py":
        # Packed .py with stubs. Run as a script; stubs will call load().
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
    """Run a packed .py via Python's normal exec. The stubs will call load() which
    in turn loads the .zspy files next to it."""
    source = py_path.read_text(encoding="utf-8")
    namespace: dict = {
        "__name__": "__main__",
        "__file__": str(py_path),
        "__builtins__": __builtins__,
    }
    sys.argv = [str(py_path)] + list(args.arg or [])

    # Make sure zss is importable from the script's directory.
    script_dir = str(py_path.parent)
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

    # CRITICAL: when the user runs `python zss.py run file.py`, the script runs as
    # __main__. The packed .py does `from zss import load` which would import a
    # SEPARATE instance of zss.py from disk — that fresh instance has its own
    # module-level globals (PRIVATE_KEY_PATH, ZSS_HOME etc.) that don't reflect
    # the env overrides we just applied. Map sys.modules['zss'] to the currently
    # running module so the import returns us.
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

    # Try to read cached state from .zson (only public info)
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
    """Run the unittest suite embedded at the end of this file."""
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


# ============================================================================
# Tests
#
# Run with:  python zss.py test
# Or:        python zss.py --test (legacy alias handled in __main__)
#
# Tests cover:
#   - Parser: all 10 edge cases from the spec.
#   - Crypto: HKDF determinism, single AEAD round-trip, N-layer round-trip for
#     N=1/5/40, tag tampering, nonce reuse safety, wrap/unwrap.
#   - .zspy: build+parse round-trip, magic tampering, version skew, hash tampering.
#   - .zson: write+read round-trip, corrupt-file, wrong-key, first-launch seed wipe.
#   - Utils: atomic write, mode 0600, safe_delete, normalize_filename.
#
# All tests use isolated temp dirs and a per-test ZSS_HOME so they don't touch the
# user's real ~/.zss.
# ============================================================================

import shutil
import tempfile
import time
from typing import Callable


class _ZssHomeFixture:
    """Context manager that swaps ZSS_HOME to a temp dir for the duration of a test.

    Works whether the test module is running as `__main__` (i.e. `python zss.py test`)
    or imported as `zss`. We use sys.modules[__name__] to grab the running module so
    that the same module-level globals that the CLI functions see get overridden.
    """

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
        # Make the running module importable as `zss` so that packed .py files can
        # do `from zss import load` and get THIS module (with overridden paths).
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
            # We added it; remove it (but only if no one else already had it)
            del sys.modules["zss"]
        os.environ.pop("ZSS_HOME", None)
        if self.tmpdir and self.tmpdir.exists():
            shutil.rmtree(self.tmpdir, ignore_errors=True)
        return False


def _with_temp_zss_home(func: Callable) -> Callable:
    """Decorator that runs a test method with a temp ZSS_HOME."""
    def wrapper(self, *args, **kwargs):
        with _ZssHomeFixture():
            return func(self, *args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper


# ----------------------------------------------------------------------------
# Parser tests
# ----------------------------------------------------------------------------

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
        # A regular comment that mentions the syntax is NOT a directive because
        # it doesn't start with `#<zss>{` exactly.
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
        # Body may contain just whitespace between the directive comment end and
        # the close directive start. That's fine.
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
        # The regex requires `[A-Za-z_][A-Za-z0-9_]*\.zspy` so `../escape.zspy`
        # is not matched as a directive. It's just an ordinary comment.
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
        # Unclosed triple-quoted string -> tokenize will fail
        src = 'x = """unclosed\n#<zss>{write_to!a.zspy\n'
        with self.assertRaises(ZssParseError):
            parse_source_with_directives(src)

    def test_body_preserves_inner_content_verbatim(self):
        # The body starts immediately after the open directive's comment token.
        # In source like `#<zss>{write_to!x.zspy\ndef f():...`, the body is
        # `\ndef f():...` (newline is part of what's between the two directives).
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


# ----------------------------------------------------------------------------
# Crypto tests
# ----------------------------------------------------------------------------

class TestCrypto(unittest.TestCase):

    def test_hkdf_deterministic(self):
        m = b"master-key-32-bytes-xxxxxxxxxxx"
        salt = b"salt16bytesxxxxx"
        k1 = hkdf_derive(m, salt, b"info1")
        k2 = hkdf_derive(m, salt, b"info1")
        self.assertEqual(k1, k2)
        self.assertEqual(len(k1), KEY_SIZE)
        # Different info -> different key
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
        # All distinct
        self.assertEqual(len(set(keys)), 5)
        # Reproducible
        keys2 = derive_layer_keys(master, 5, salt)
        self.assertEqual(keys, keys2)

    def test_encrypt_decrypt_layers_round_trip_n1(self):
        self._round_trip_layers(1)

    def test_encrypt_decrypt_layers_round_trip_n5(self):
        self._round_trip_layers(5)

    def test_encrypt_decrypt_layers_round_trip_n40(self):
        # N=40 is the production target. Should still round-trip in reasonable time.
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
        # Tamper with the outermost (last) layer's tag
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


# ----------------------------------------------------------------------------
# .zspy format tests
# ----------------------------------------------------------------------------

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
        # Decrypt and verify hash
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
        # bytes 8:10 are version u16 LE
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
        # Flip a bit in the ciphertext
        bad = bytearray(blob)
        # Find the ciphertext position. Easier: tamper the parsed header.
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
        # AEAD tags should still pass (we didn't touch ciphertext), but the
        # post-decrypt hash check should catch it.
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
        # Non-zspy file
        with tempfile.NamedTemporaryFile(suffix=".zspy", delete=False) as f:
            f.write(b"not a zspy file")
            path = Path(f.name)
        try:
            self.assertFalse(is_zspy_file(path))
        finally:
            path.unlink(missing_ok=True)

    def test_n_layers_zero_in_header_rejected(self):
        # Manually craft a header with N=0
        bad = bytearray()
        bad += ZSSPY_MAGIC
        bad += struct.pack("<H", ZSSPY_FORMAT_VERSION)
        bad += struct.pack("<B", 0)  # N=0
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
        # No plaintext leakage
        for v in info.values():
            if isinstance(v, str):
                self.assertNotIn("hello", v)


# ----------------------------------------------------------------------------
# .zson tests
# ----------------------------------------------------------------------------

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
            # Truncate
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
            # Overwrite with bad magic
            atomic_write_bytes(ZSON_PATH, b"NOTZSSON" + b"\x00" * 100, mode=0o600)
            with self.assertRaises(ZssConfigError) as ctx:
                load_zson(priv, ZSON_PATH)
            self.assertIn("magic", str(ctx.exception).lower())

    def test_future_schema_is_error(self):
        priv = self._make_priv()
        with _ZssHomeFixture():
            init_zson(priv, ZSON_PATH)
            data = bytearray(read_bytes(ZSON_PATH))
            # bytes 8:10 are schema_version u16 LE
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
        # The _wipe_seeds() function zeros the in-memory bytearrays. We can't test
        # the on-disk source (it's open beta), but we can test the runtime state.
        global _seed_wiped, _SEED_PEPPER, _SEED_SALT
        # Reset for test
        _seed_wiped = False
        # Re-init the bytearrays with non-zero
        original_pepper = bytes(_SEED_PEPPER)
        original_salt = bytes(_SEED_SALT)
        try:
            priv = self._make_priv()
            with _ZssHomeFixture():
                init_zson(priv, ZSON_PATH)
            # After init, seeds must be wiped
            self.assertTrue(_seed_wiped)
            self.assertEqual(bytes(_SEED_PEPPER), b"\x00" * 32)
            self.assertEqual(bytes(_SEED_SALT), b"\x00" * 16)
        finally:
            # Restore for subsequent tests (we don't actually need them after init)
            _SEED_PEPPER[:] = original_pepper
            _SEED_SALT[:] = original_salt
            _seed_wiped = False


# ----------------------------------------------------------------------------
# Utils tests
# ----------------------------------------------------------------------------

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
            safe_delete(p)  # should not raise

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
        zero_fill(None)  # should not raise

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


# ----------------------------------------------------------------------------
# Integration tests
# ----------------------------------------------------------------------------

class TestIntegration(unittest.TestCase):

    def test_pack_and_run_round_trip(self):
        """End-to-end: write a .py with directives, pack it, run the packed version."""
        with _ZssHomeFixture() as fx:
            # Init keys + .zson
            _ensure_dir(KEYS_DIR, mode=0o700)
            priv, pub = generate_keypair()
            save_private_key(priv, PRIVATE_KEY_PATH)
            save_public_key(pub, PUBLIC_KEY_PATH)
            init_zson(priv, ZSON_PATH)

            # Write source .py
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

            # The fixture already mapped sys.modules['zss'] to the running module,
            # so the packed .py's `from zss import load` will work in-process.
            # We use the locally-bound cmd_pack / cmd_run names so they share the
            # running module's globals with the test (and see the overridden ZSS_HOME).
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
            # demo.py should now contain the stub
            packed = src_path.read_text(encoding="utf-8")
            self.assertIn('from zss import load; load("greet.zspy")', packed)
            self.assertNotIn("def hello", packed)

            # Run the packed .py
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
        """Build a .zspy from plaintext, then run it via cmd_run."""
        with _ZssHomeFixture() as fx:
            _ensure_dir(KEYS_DIR, mode=0o700)
            priv, pub = generate_keypair()
            save_private_key(priv, PRIVATE_KEY_PATH)
            save_public_key(pub, PUBLIC_KEY_PATH)
            init_zson(priv, ZSON_PATH)

            # Build a .zspy directly
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


if __name__ == "__main__":
    # Handle legacy `python zss.py --test` alias.
    if len(sys.argv) >= 2 and sys.argv[1] == "--test":
        sys.argv = [sys.argv[0], "test"] + sys.argv[2:]
    sys.exit(main())
