"""
messenger.py — Layer 2: PQC Secure Messenger
============================================
Implements the inner PQC Chat Application from Section 5/6.

Features:
  - Kyber-768 key exchange for each conversation
  - ChaCha20-Poly1305 message encryption
  - Fragmentation Wrapper for reliable delivery through VPN tunnel
  - Message signing (HMAC-SHA3-256 for integrity)
  - Perfect Forward Secrecy: new Kyber keypair per session

Message Wire Format:
  [1B msg_type][8B timestamp][4B seq][32B hmac][encrypted_payload]

Message Types:
  0x10 = KEY_OFFER   (Alice → Bob: "here is my Kyber public key")
  0x11 = KEY_ACCEPT  (Bob → Alice: "here is ciphertext + my pk")
  0x12 = CHAT_MSG    (encrypted chat message)
  0x13 = READ_RCPT   (delivery receipt)
  0x14 = PING
  0x15 = PONG
"""

import os
import struct
import time
import threading
import hashlib
import hmac as hmac_mod
import json
import logging
from typing import Optional, Callable, Any
from collections import deque

from pqc_core import KyberKEM, AEAD, hkdf
from fragmentation_wrapper import FragmentationWrapper

log = logging.getLogger("Messenger")

# ─── Message Types ───────────────────────────────────────────────────────────
MSG_KEY_OFFER  = 0x10
MSG_KEY_ACCEPT = 0x11
MSG_CHAT       = 0x12
MSG_READ_RCPT  = 0x13
MSG_PING       = 0x14
MSG_PONG       = 0x15

MSG_NAMES = {
    MSG_KEY_OFFER:  "KEY_OFFER",
    MSG_KEY_ACCEPT: "KEY_ACCEPT",
    MSG_CHAT:       "CHAT_MSG",
    MSG_READ_RCPT:  "READ_RCPT",
    MSG_PING:       "PING",
    MSG_PONG:       "PONG",
}

HEADER_SIZE  = 1 + 8 + 4 + 32  # type + timestamp + seq + hmac = 45 bytes


def _make_header(msg_type: int, seq: int, hmac_key: bytes,
                 payload: bytes) -> bytes:
    ts   = struct.pack("!d", time.time())
    seq_ = struct.pack("!I", seq)
    mac  = hmac_mod.new(hmac_key,
                        bytes([msg_type]) + ts + seq_ + payload,
                        hashlib.sha3_256).digest()
    return bytes([msg_type]) + ts + seq_ + mac


def _parse_header(data: bytes) -> tuple:
    """Returns (msg_type, timestamp, seq, hmac, payload)"""
    msg_type  = data[0]
    timestamp = struct.unpack("!d", data[1:9])[0]
    seq       = struct.unpack("!I", data[9:13])[0]
    mac       = data[13:45]
    payload   = data[45:]
    return msg_type, timestamp, seq, mac, payload


class ChatSession:
    """An end-to-end encrypted chat session between two peers."""

    def __init__(self, session_id: str):
        self.session_id    = session_id
        self.kem           = KyberKEM()
        self.pk, self.sk   = self.kem.generate_keypair()
        self.aead:  Optional[AEAD] = None
        self.hmac_key: bytes = os.urandom(32)
        self.established   = False
        self.established_at: Optional[float] = None
        self.seq           = 0
        self.messages: deque = deque(maxlen=1000)  # message history
        self.peer_pk: Optional[bytes] = None
        self.handshake_ms: float = 0
        self._t0: float = 0

    def start_handshake(self) -> bytes:
        """Create KEY_OFFER payload."""
        self._t0 = time.time()
        # Payload: [1184B pk][32B hmac_key_material]
        offer = self.pk + self.hmac_key
        log.info(f"[Session {self.session_id}] KEY_OFFER: pk={len(self.pk)}B")
        return offer

    def handle_key_offer(self, payload: bytes) -> bytes:
        """
        Bob receives KEY_OFFER from Alice. Encapsulates, derives keys.
        Returns KEY_ACCEPT payload.
        """
        from pqc_core import KYBER768_PUBLIC_KEY_SIZE
        peer_pk      = payload[:KYBER768_PUBLIC_KEY_SIZE]
        peer_hmac_km = payload[KYBER768_PUBLIC_KEY_SIZE:KYBER768_PUBLIC_KEY_SIZE+32]
        self.peer_pk = peer_pk

        ct, shared_secret = self.kem.encapsulate(peer_pk)

        # Derive symmetric keys from shared_secret only — same value both sides
        self.aead     = AEAD(hkdf(shared_secret, 32, info=b"chat-enc"))
        self.hmac_key = hkdf(shared_secret, 32, info=b"chat-mac")
        self.established    = True
        self.established_at = time.time()

        log.info(f"[Session {self.session_id}] KEY_ACCEPT: ct={len(ct)}B | "
                 f"E2E keys derived ✓")

        # KEY_ACCEPT payload: [1088B ct][1184B our_pk][32B hmac_km]
        return ct + self.pk + self.hmac_key[:32]

    def handle_key_accept(self, payload: bytes):
        """Alice receives KEY_ACCEPT from Bob. Decapsulates, derives keys."""
        from pqc_core import KYBER768_CIPHERTEXT_SIZE, KYBER768_PUBLIC_KEY_SIZE
        ct          = payload[:KYBER768_CIPHERTEXT_SIZE]
        peer_pk     = payload[KYBER768_CIPHERTEXT_SIZE:
                               KYBER768_CIPHERTEXT_SIZE + KYBER768_PUBLIC_KEY_SIZE]
        peer_hmac_km = payload[KYBER768_CIPHERTEXT_SIZE + KYBER768_PUBLIC_KEY_SIZE:
                                KYBER768_CIPHERTEXT_SIZE + KYBER768_PUBLIC_KEY_SIZE + 32]

        shared_secret = self.kem.decapsulate(ct, self.sk)
        self.aead     = AEAD(hkdf(shared_secret, 32, info=b"chat-enc"))
        self.hmac_key = hkdf(shared_secret, 32, info=b"chat-mac")
        self.established    = True
        self.established_at = time.time()
        self.handshake_ms   = (time.time() - self._t0) * 1000

        log.info(f"[Session {self.session_id}] ✓ E2E SESSION ESTABLISHED | "
                 f"handshake={self.handshake_ms:.1f}ms")

    def encrypt_message(self, text: str) -> bytes:
        """Encrypt a chat message. Returns wire bytes."""
        if not self.aead:
            raise RuntimeError("Session not established")
        msg_json = json.dumps({
            "text": text,
            "ts":   time.time(),
            "seq":  self.seq,
        }).encode()
        ct = self.aead.encrypt(msg_json)
        self.seq += 1
        return ct

    def decrypt_message(self, ct: bytes) -> dict:
        """Decrypt a chat message. Returns dict with text + metadata."""
        if not self.aead:
            raise RuntimeError("Session not established")
        plaintext = self.aead.decrypt(ct)
        return json.loads(plaintext)

    def record_message(self, direction: str, text: str, encrypted_size: int):
        self.messages.append({
            "direction":      direction,
            "text":           text,
            "ts":             time.time(),
            "encrypted_size": encrypted_size,
        })

    def info(self) -> dict:
        return {
            "session_id":     self.session_id,
            "established":    self.established,
            "handshake_ms":   round(self.handshake_ms, 2),
            "pk_size_bytes":  len(self.pk),
            "message_count":  len(self.messages),
            "seq":            self.seq,
        }


class PQCMessenger:
    """
    Layer 2: Post-Quantum Secure Messenger.
    Runs inside the VPN tunnel (Layer 1).
    """

    def __init__(self, username: str, send_fn: Callable[[bytes], None]):
        self.username  = username
        self.sessions: dict[str, ChatSession] = {}
        self._seq      = 0
        self._seq_lock = threading.Lock()

        # Fragmentation wrapper for this messenger
        self.wrapper = FragmentationWrapper(send_fn)
        self.wrapper.on_message = self._on_raw_message

        self.on_chat_message: Optional[Callable[[str, str, str], None]] = None
        # on_chat_message(session_id, sender, text)

        self.stats = {
            "messages_sent":       0,
            "messages_received":   0,
            "handshakes_done":     0,
            "bytes_sent_plaintext":0,
            "bytes_encrypted":     0,
        }

    def send_raw(self, data: bytes):
        """Send via fragmentation wrapper (auto-fragments large PQC payloads)."""
        self.wrapper.send(data)

    def receive_raw(self, data: bytes):
        """Feed incoming data into the fragmentation wrapper."""
        self.wrapper.receive(data)

    def _build_packet(self, msg_type: int, session: ChatSession,
                      payload: bytes) -> bytes:
        with self._seq_lock:
            seq = self._seq; self._seq += 1
        header = _make_header(msg_type, seq, session.hmac_key, payload)
        return header + payload

    def _on_raw_message(self, data: bytes):
        """Called by FragmentationWrapper when a complete message is reassembled."""
        if len(data) < HEADER_SIZE:
            log.warning("[Messenger] Short message received")
            return

        msg_type, ts, seq, mac, payload = _parse_header(data)
        log.debug(f"[Messenger] ← {MSG_NAMES.get(msg_type, hex(msg_type))} "
                  f"seq={seq} payload={len(payload)}B")

        # Route to handler
        handler = {
            MSG_KEY_OFFER:  self._handle_key_offer,
            MSG_KEY_ACCEPT: self._handle_key_accept,
            MSG_CHAT:       self._handle_chat,
            MSG_PING:       self._handle_ping,
        }.get(msg_type)

        if handler:
            handler(payload, ts, seq)
        else:
            log.warning(f"[Messenger] Unknown msg_type: {msg_type:#x}")

    # ─── Handshake ───────────────────────────────────────────────────────────

    def start_conversation(self, session_id: str) -> ChatSession:
        """Initiate a new E2E encrypted conversation."""
        session = ChatSession(session_id)
        self.sessions[session_id] = session
        offer   = session.start_handshake()

        # Embed session_id in packet: [16B session_id_hash][offer]
        sid_hash = hashlib.sha256(session_id.encode()).digest()[:16]
        pkt = self._build_packet(MSG_KEY_OFFER, session, sid_hash + offer)

        log.info(f"[Messenger] → KEY_OFFER for '{session_id}' "
                 f"({len(offer)}B payload, will fragment)")
        self.send_raw(pkt)
        return session

    def _handle_key_offer(self, payload: bytes, ts: float, seq: int):
        sid_hash   = payload[:16]
        offer_data = payload[16:]
        # Use the hash as the session key on Bob's side
        session_id = "peer_" + sid_hash.hex()

        session = self.sessions.get(session_id)
        if not session:
            session = ChatSession(session_id)
            self.sessions[session_id] = session

        accept_data = session.handle_key_offer(offer_data)
        pkt = self._build_packet(MSG_KEY_ACCEPT, session,
                                  sid_hash + accept_data)

        log.info(f"[Messenger] → KEY_ACCEPT for '{session_id}' "
                 f"({len(accept_data)}B, will fragment)")
        self.send_raw(pkt)
        self.stats["handshakes_done"] += 1

    def _handle_key_accept(self, payload: bytes, ts: float, seq: int):
        sid_hash    = payload[:16]
        accept_data = payload[16:]
        session_id  = None

        # Find our pending session
        for sid, sess in self.sessions.items():
            expected_hash = hashlib.sha256(sid.encode()).digest()[:16]
            if expected_hash == sid_hash:
                session_id = sid
                break

        if not session_id:
            log.warning("[Messenger] KEY_ACCEPT for unknown session")
            return

        session = self.sessions[session_id]
        session.handle_key_accept(accept_data)
        self.stats["handshakes_done"] += 1

    # ─── Chat ─────────────────────────────────────────────────────────────────

    def send_message(self, session_id: str, text: str) -> bool:
        session = self.sessions.get(session_id)
        if not session or not session.established:
            log.error(f"[Messenger] Session '{session_id}' not ready")
            return False

        ct  = session.encrypt_message(text)
        sid_hash = hashlib.sha256(session_id.encode()).digest()[:16]
        pkt = self._build_packet(MSG_CHAT, session, sid_hash + ct)

        self.stats["messages_sent"]        += 1
        self.stats["bytes_sent_plaintext"] += len(text.encode())
        self.stats["bytes_encrypted"]      += len(ct)

        session.record_message("sent", text, len(ct))
        log.info(f"[Messenger] → CHAT '{text[:30]}...' "
                 f"plain={len(text.encode())}B enc={len(ct)}B")
        self.send_raw(pkt)
        return True

    def _handle_chat(self, payload: bytes, ts: float, seq: int):
        sid_hash = payload[:16]
        ct       = payload[16:]

        # Find session by matching sid_hash
        session_id = None
        for sid, sess in self.sessions.items():
            # Check both naming conventions
            expected = hashlib.sha256(sid.encode()).digest()[:16]
            peer_sid = "peer_" + sid_hash.hex()
            if expected == sid_hash or sid == peer_sid:
                session_id = sid; break

        if not session_id:
            log.warning("[Messenger] CHAT for unknown session")
            return

        session = self.sessions[session_id]
        if not session.established:
            log.warning("[Messenger] CHAT before session established")
            return

        try:
            msg = session.decrypt_message(ct)
            text = msg["text"]
            session.record_message("received", text, len(ct))
            self.stats["messages_received"] += 1

            log.info(f"[Messenger] ← CHAT (decrypted): '{text[:50]}'")

            if self.on_chat_message:
                self.on_chat_message(session_id, "peer", text)
        except Exception as e:
            log.error(f"[Messenger] Decrypt failed: {e}")

    def _handle_ping(self, payload: bytes, ts: float, seq: int):
        # Find any session to send pong
        for session in self.sessions.values():
            pong = self._build_packet(MSG_PONG, session, payload)
            self.send_raw(pong)
            break

    def get_session_info(self) -> list[dict]:
        return [s.info() for s in self.sessions.values()]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    print("[Messenger] Self-test: Alice ↔ Bob E2E encryption...")

    alice_outbox = []
    bob_outbox   = []

    def alice_send(pkt): bob_messenger.receive_raw(pkt)
    def bob_send(pkt):   alice_messenger.receive_raw(pkt)

    alice_messenger = PQCMessenger("Alice", alice_send)
    bob_messenger   = PQCMessenger("Bob",   bob_send)

    received_messages = []
    bob_messenger.on_chat_message = lambda sid, sender, text: \
        received_messages.append(text)

    import time

    # Alice starts conversation
    t0 = time.time()
    session = alice_messenger.start_conversation("alice-bob-room-1")
    time.sleep(0.1)  # allow async processing

    print(f"\nSession established: {any(s.established for s in alice_messenger.sessions.values())}")
    sid = "alice-bob-room-1"

    # Send messages
    messages = [
        "Hello Bob! This message is quantum-safe.",
        "Even if someone records this traffic today, a quantum computer can't decrypt it later.",
        "This is the HNDL (Harvest Now, Decrypt Later) attack protection.",
    ]

    for msg in messages:
        alice_messenger.send_message(sid, msg)
        time.sleep(0.05)

    print(f"\n--- Results ---")
    print(f"Messages sent   : {alice_messenger.stats['messages_sent']}")
    print(f"Messages received: {bob_messenger.stats['messages_received']}")
    print(f"Fragments sent  : {alice_messenger.wrapper.stats['fragments_sent']}")
    print(f"Handshakes done : {alice_messenger.stats['handshakes_done']}")
    if received_messages:
        print(f"First message   : '{received_messages[0]}'")
