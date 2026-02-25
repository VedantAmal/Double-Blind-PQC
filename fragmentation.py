"""
Double-Blind Post-Quantum Communication Ecosystem
===================================================
Fragmentation Wrapper — Application-layer UDP fragmentation with ACK.

Solves the "Nested MTU Paradox": when PQC keys (1,184B Kyber public key +
headers) are sent through a WireGuard tunnel that already consumes ~80B of
the 1,500B MTU, large payloads get silently dropped by the network.

This wrapper:
  1. Proactively fragments any payload > FRAGMENT_THRESHOLD (default 1,000B)
  2. Implements a lightweight ACK protocol per-fragment
  3. Reassembles fragments in order at the receiver
  4. Handles retransmission on ACK timeout

Wire format for a fragment:
  [1B flags][4B msg_id][2B seq][2B total][2B payload_len][payload...]

Flags byte:
  bit 0: FRAG  (1 = fragment, 0 = whole message)
  bit 1: ACK   (1 = this is an acknowledgement)
  bit 2: FIN   (1 = final fragment — same as seq == total-1)
"""

import os
import struct
import time
import hashlib
import threading
import logging
from typing import Dict, List, Optional, Tuple, Callable

logger = logging.getLogger("fragmentation")

# ---------------------------------------------------------------------------
#  Constants
# ---------------------------------------------------------------------------

FRAGMENT_THRESHOLD = 1000   # bytes — conservative limit well under 1420B tunnel MTU
HEADER_SIZE = 11            # 1 + 4 + 2 + 2 + 2
FLAG_FRAG = 0x01
FLAG_ACK  = 0x02
FLAG_FIN  = 0x04

ACK_TIMEOUT  = 2.0    # seconds
MAX_RETRIES  = 3
REASSEMBLY_TIMEOUT = 5.0  # seconds — drop incomplete messages older than this


# ---------------------------------------------------------------------------
#  Fragment header encoding / decoding
# ---------------------------------------------------------------------------

def _pack_header(flags: int, msg_id: int, seq: int, total: int, payload_len: int) -> bytes:
    """Pack a fragment header (11 bytes)."""
    return struct.pack("!BIHHH", flags, msg_id, seq, total, payload_len)


def _unpack_header(data: bytes) -> Tuple[int, int, int, int, int]:
    """Unpack a fragment header. Returns (flags, msg_id, seq, total, payload_len)."""
    return struct.unpack("!BIHHH", data[:HEADER_SIZE])


def _make_msg_id() -> int:
    """Generate a random 32-bit message ID."""
    return int.from_bytes(os.urandom(4), "big")


# ---------------------------------------------------------------------------
#  Fragmenter — breaks large payloads into safe chunks
# ---------------------------------------------------------------------------

class Fragmenter:
    """
    Fragments outgoing payloads and reassembles incoming ones.
    Thread-safe for concurrent use by the messenger.
    """

    def __init__(self,
                 send_func: Callable[[bytes, tuple], None],
                 on_message: Callable[[bytes, tuple], None],
                 threshold: int = FRAGMENT_THRESHOLD,
                 ack_timeout: float = ACK_TIMEOUT,
                 max_retries: int = MAX_RETRIES):
        """
        send_func:   callback(data: bytes, addr: tuple) — send raw bytes to addr
        on_message:  callback(payload: bytes, addr: tuple) — complete message received
        threshold:   max payload size before fragmentation kicks in
        ack_timeout: seconds to wait for each fragment ACK
        max_retries: how many times to retransmit an un-ACKed fragment
        """
        self._send = send_func
        self._on_message = on_message
        self.threshold = threshold
        self.ack_timeout = ack_timeout
        self.max_retries = max_retries

        # Reassembly buffers: msg_id → { "fragments": {seq: bytes}, "total": int, "ts": float }
        self._reassembly: Dict[int, dict] = {}
        self._reassembly_lock = threading.Lock()

        # Pending ACKs: (msg_id, seq) → threading.Event
        self._pending_acks: Dict[Tuple[int, int], threading.Event] = {}
        self._ack_lock = threading.Lock()

        # Stats
        self.stats = {
            "fragments_sent": 0,
            "fragments_received": 0,
            "acks_sent": 0,
            "acks_received": 0,
            "messages_reassembled": 0,
            "retransmissions": 0,
            "timeouts": 0,
            "whole_messages_sent": 0,
            "whole_messages_received": 0,
        }

    # ---- Sending -------------------------------------------------------

    def send(self, payload: bytes, addr: tuple) -> bool:
        """
        Send a payload, fragmenting if necessary.
        Returns True if all fragments were ACKed, False on failure.
        """
        if len(payload) <= self.threshold:
            # Small enough — send as a whole message (no fragmentation)
            flags = 0  # no FRAG flag
            msg_id = _make_msg_id()
            header = _pack_header(flags, msg_id, 0, 1, len(payload))
            self._send(header + payload, addr)
            self.stats["whole_messages_sent"] += 1
            logger.debug(f"Sent whole message ({len(payload)}B) to {addr}")
            return True

        # Fragment the payload
        msg_id = _make_msg_id()
        chunks = self._split(payload)
        total = len(chunks)
        logger.info(f"Fragmenting {len(payload)}B into {total} chunks (msg_id={msg_id:#x})")

        for seq, chunk in enumerate(chunks):
            flags = FLAG_FRAG
            if seq == total - 1:
                flags |= FLAG_FIN
            if not self._send_fragment_reliable(flags, msg_id, seq, total, chunk, addr):
                logger.error(f"Fragment {seq}/{total} failed for msg_id={msg_id:#x}")
                return False
            self.stats["fragments_sent"] += 1

        logger.info(f"All {total} fragments ACKed for msg_id={msg_id:#x}")
        return True

    def _split(self, payload: bytes) -> List[bytes]:
        """Split payload into chunks of at most self.threshold bytes."""
        chunks = []
        for i in range(0, len(payload), self.threshold):
            chunks.append(payload[i:i + self.threshold])
        return chunks

    def _send_fragment_reliable(self, flags: int, msg_id: int, seq: int,
                                total: int, chunk: bytes, addr: tuple) -> bool:
        """Send a single fragment with retransmission until ACKed."""
        header = _pack_header(flags, msg_id, seq, total, len(chunk))
        packet = header + chunk
        ack_key = (msg_id, seq)

        event = threading.Event()
        with self._ack_lock:
            self._pending_acks[ack_key] = event

        for attempt in range(1, self.max_retries + 1):
            self._send(packet, addr)
            logger.debug(f"Sent frag {seq}/{total} (attempt {attempt}) msg_id={msg_id:#x}")

            if event.wait(timeout=self.ack_timeout):
                with self._ack_lock:
                    self._pending_acks.pop(ack_key, None)
                self.stats["acks_received"] += 1
                return True
            else:
                self.stats["retransmissions"] += 1
                logger.warning(f"ACK timeout for frag {seq}/{total}, retrying...")

        # Exhausted retries
        with self._ack_lock:
            self._pending_acks.pop(ack_key, None)
        self.stats["timeouts"] += 1
        logger.error(f"Fragment {seq}/{total} dropped after {self.max_retries} attempts")
        return False

    # ---- Receiving ----------------------------------------------------

    def receive(self, data: bytes, addr: tuple) -> None:
        """
        Process an incoming raw packet. Call this for every UDP datagram received.
        Handles ACKs, fragment reassembly, and whole messages.
        """
        if len(data) < HEADER_SIZE:
            logger.warning(f"Dropping short packet ({len(data)}B) from {addr}")
            return

        flags, msg_id, seq, total, payload_len = _unpack_header(data)
        payload = data[HEADER_SIZE:HEADER_SIZE + payload_len]

        # Is this an ACK?
        if flags & FLAG_ACK:
            self._handle_ack(msg_id, seq)
            return

        # Is this a fragment?
        if flags & FLAG_FRAG:
            self.stats["fragments_received"] += 1
            self._send_ack(msg_id, seq, addr)
            self._handle_fragment(msg_id, seq, total, payload, addr)
            return

        # Whole message (no fragmentation)
        self.stats["whole_messages_received"] += 1
        logger.debug(f"Received whole message ({len(payload)}B) from {addr}")
        self._on_message(payload, addr)

    def _send_ack(self, msg_id: int, seq: int, addr: tuple) -> None:
        """Send an ACK for a specific fragment."""
        header = _pack_header(FLAG_ACK, msg_id, seq, 0, 0)
        self._send(header, addr)
        self.stats["acks_sent"] += 1
        logger.debug(f"Sent ACK for frag {seq} of msg_id={msg_id:#x}")

    def _handle_ack(self, msg_id: int, seq: int) -> None:
        """Signal the sending thread that a fragment was ACKed."""
        ack_key = (msg_id, seq)
        with self._ack_lock:
            event = self._pending_acks.get(ack_key)
            if event:
                event.set()
                logger.debug(f"ACK received for frag {seq} of msg_id={msg_id:#x}")

    def _handle_fragment(self, msg_id: int, seq: int, total: int,
                         payload: bytes, addr: tuple) -> None:
        """Store a fragment and attempt reassembly."""
        with self._reassembly_lock:
            if msg_id not in self._reassembly:
                self._reassembly[msg_id] = {
                    "fragments": {},
                    "total": total,
                    "ts": time.time(),
                    "addr": addr,
                }

            entry = self._reassembly[msg_id]
            entry["fragments"][seq] = payload
            logger.debug(f"Stored frag {seq}/{total} for msg_id={msg_id:#x} "
                         f"({len(entry['fragments'])}/{total} received)")

            # Check if complete
            if len(entry["fragments"]) == total:
                # Reassemble in order
                full_payload = b"".join(
                    entry["fragments"][i] for i in range(total)
                )
                del self._reassembly[msg_id]
                self.stats["messages_reassembled"] += 1
                logger.info(f"Reassembled msg_id={msg_id:#x} ({len(full_payload)}B from {total} frags)")
                self._on_message(full_payload, addr)

    def cleanup_stale(self) -> int:
        """Remove stale reassembly buffers. Returns count of purged entries."""
        now = time.time()
        purged = 0
        with self._reassembly_lock:
            stale = [mid for mid, e in self._reassembly.items()
                     if now - e["ts"] > REASSEMBLY_TIMEOUT]
            for mid in stale:
                del self._reassembly[mid]
                purged += 1
        if purged:
            logger.info(f"Purged {purged} stale reassembly buffers")
        return purged

    def get_stats(self) -> dict:
        """Return a copy of the fragmentation statistics."""
        return dict(self.stats)
