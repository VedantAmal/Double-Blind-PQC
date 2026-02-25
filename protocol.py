"""
Double-Blind Post-Quantum Communication Ecosystem
===================================================
Protocol — Wire-level message encoding / decoding.

All messages between peers are serialized as:
  [2B type][4B length][payload...]

Message types handle both the PQC handshake and encrypted data.
"""

import struct
import json
import time
import logging
from enum import IntEnum
from typing import Tuple, Optional

logger = logging.getLogger("protocol")


class MsgType(IntEnum):
    """Message type identifiers."""
    # Layer 1 — VPN Sidecar handshake
    L1_HANDSHAKE_INIT  = 0x01
    L1_HANDSHAKE_RESP  = 0x02
    L1_DATA            = 0x03
    L1_REKEY           = 0x04

    # Layer 2 — Messenger handshake
    L2_HANDSHAKE_INIT  = 0x11
    L2_HANDSHAKE_RESP  = 0x12
    L2_CHAT_MSG        = 0x13
    L2_PRESENCE        = 0x14
    L2_REKEY           = 0x15

    # Control
    PING               = 0xF0
    PONG               = 0xF1
    ERROR              = 0xFF


# ---------------------------------------------------------------------------
#  Wire encoding
# ---------------------------------------------------------------------------

HEADER_FMT = "!HI"  # type (2B) + length (4B)
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 6 bytes


def encode_message(msg_type: MsgType, payload: bytes) -> bytes:
    """
    Encode a message with type + length header.
    Returns the complete wire-format bytes.
    """
    header = struct.pack(HEADER_FMT, int(msg_type), len(payload))
    return header + payload


def decode_header(data: bytes) -> Tuple[MsgType, int]:
    """
    Decode just the header from data.
    Returns (msg_type, payload_length).
    """
    if len(data) < HEADER_SIZE:
        raise ProtocolError(f"Data too short for header ({len(data)} < {HEADER_SIZE})")
    raw_type, length = struct.unpack(HEADER_FMT, data[:HEADER_SIZE])
    try:
        msg_type = MsgType(raw_type)
    except ValueError:
        raise ProtocolError(f"Unknown message type: {raw_type:#06x}")
    return msg_type, length


def decode_message(data: bytes) -> Tuple[MsgType, bytes]:
    """
    Decode a complete message.
    Returns (msg_type, payload).
    """
    msg_type, length = decode_header(data)
    if len(data) < HEADER_SIZE + length:
        raise ProtocolError(
            f"Payload truncated: expected {length}B, got {len(data) - HEADER_SIZE}B"
        )
    payload = data[HEADER_SIZE:HEADER_SIZE + length]
    return msg_type, payload


# ---------------------------------------------------------------------------
#  Handshake message serialization (binary, not JSON — to keep sizes tight)
# ---------------------------------------------------------------------------

def encode_handshake_init(kem_pk: bytes, sig_pk: bytes, sig: bytes) -> bytes:
    """
    Encode a handshake_init payload:
      [2B kem_pk_len][kem_pk][2B sig_pk_len][sig_pk][2B sig_len][sig][8B timestamp]
    """
    ts = struct.pack("!d", time.time())
    parts = []
    for blob in (kem_pk, sig_pk, sig):
        parts.append(struct.pack("!H", len(blob)))
        parts.append(blob)
    parts.append(ts)
    return b"".join(parts)


def decode_handshake_init(payload: bytes) -> dict:
    """Decode a handshake_init payload."""
    offset = 0

    def _read_blob():
        nonlocal offset
        blen = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 2
        blob = payload[offset:offset+blen]
        offset += blen
        return blob

    kem_pk = _read_blob()
    sig_pk = _read_blob()
    sig = _read_blob()
    ts = struct.unpack("!d", payload[offset:offset+8])[0]
    return {"kem_pk": kem_pk, "sig_pk": sig_pk, "sig": sig, "timestamp": ts}


def encode_handshake_resp(ciphertext: bytes, sig_pk: bytes, sig: bytes) -> bytes:
    """
    Encode a handshake_resp payload:
      [2B ct_len][ciphertext][2B sig_pk_len][sig_pk][2B sig_len][sig][8B timestamp]
    """
    ts = struct.pack("!d", time.time())
    parts = []
    for blob in (ciphertext, sig_pk, sig):
        parts.append(struct.pack("!H", len(blob)))
        parts.append(blob)
    parts.append(ts)
    return b"".join(parts)


def decode_handshake_resp(payload: bytes) -> dict:
    """Decode a handshake_resp payload."""
    offset = 0

    def _read_blob():
        nonlocal offset
        blen = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 2
        blob = payload[offset:offset+blen]
        offset += blen
        return blob

    ciphertext = _read_blob()
    sig_pk = _read_blob()
    sig = _read_blob()
    ts = struct.unpack("!d", payload[offset:offset+8])[0]
    return {"ciphertext": ciphertext, "sig_pk": sig_pk, "sig": sig, "timestamp": ts}


def encode_chat_message(sender: str, text: str, timestamp: Optional[float] = None) -> bytes:
    """
    Encode a chat message payload (before encryption):
      JSON { "sender": ..., "text": ..., "ts": ... }
    """
    obj = {
        "sender": sender,
        "text": text,
        "ts": timestamp or time.time(),
    }
    return json.dumps(obj).encode("utf-8")


def decode_chat_message(payload: bytes) -> dict:
    """Decode a chat message payload (after decryption)."""
    return json.loads(payload.decode("utf-8"))


# ---------------------------------------------------------------------------
#  Errors
# ---------------------------------------------------------------------------

class ProtocolError(Exception):
    """Raised for wire-protocol violations."""
    pass
