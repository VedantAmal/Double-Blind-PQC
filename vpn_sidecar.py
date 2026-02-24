"""
vpn_sidecar.py — Layer 1: PQC WireGuard Sidecar (qTrustNet-style)
==================================================================
Implements the "PQC Sidecar" from Section 5 of the project report.

Based on: Shim et al., "qTrustNet VPN", IEEE Access, Jan 2025.

Architecture:
  - PQC handshake runs in userspace (port 51821) using Kyber-768
  - After handshake, derives session key injected into WireGuard-style tunnel
  - All inner traffic is encrypted with ChaCha20-Poly1305
  - Simulates the WireGuard kernel interface via software tunnel

Wire Protocol (simplified WireGuard + PQC):
  Handshake Init  → [type=1][sender_idx][kyber_pk][timestamp]
  Handshake Resp  → [type=2][sender_idx][recv_idx][kyber_ct][mac]
  Transport Data  → [type=4][recv_idx][counter][encrypted_payload]
"""

import socket
import threading
import struct
import time
import os
import json
import logging
import hashlib
from typing import Optional, Callable
from pqc_core import KyberKEM, AEAD, hkdf, KYBER768_PUBLIC_KEY_SIZE, KYBER768_CIPHERTEXT_SIZE

log = logging.getLogger("VPNSidecar")

# ─── Packet Types ─────────────────────────────────────────────────────────────
TYPE_HANDSHAKE_INIT  = 1
TYPE_HANDSHAKE_RESP  = 2
TYPE_KEEPALIVE       = 3
TYPE_TRANSPORT       = 4

SIDECAR_PORT         = 51821
TUNNEL_MTU           = 1420   # 1500 - 80 WireGuard overhead


class TunnelSession:
    """Represents an established VPN tunnel session."""

    def __init__(self, peer_addr: tuple, session_key: bytes):
        self.peer_addr    = peer_addr
        self.session_key  = session_key
        self.aead         = AEAD(session_key)
        self.send_counter = 0
        self.recv_counter = -1
        self.established  = time.time()
        self.last_seen    = time.time()
        self.bytes_in     = 0
        self.bytes_out    = 0
        self.handshake_ms = 0

    def encrypt_transport(self, plaintext: bytes) -> bytes:
        counter = self.send_counter
        self.send_counter += 1
        aad = struct.pack("!BQ", TYPE_TRANSPORT, counter)
        ct  = self.aead.encrypt(plaintext, aad)
        return struct.pack("!BQ", TYPE_TRANSPORT, counter) + ct

    def decrypt_transport(self, packet: bytes) -> bytes:
        pkt_type, counter = struct.unpack("!BQ", packet[:9])
        aad = packet[:9]
        return self.aead.decrypt(packet[9:], aad)

    def info(self) -> dict:
        uptime = time.time() - self.established
        return {
            "peer":           f"{self.peer_addr[0]}:{self.peer_addr[1]}",
            "uptime_sec":     round(uptime, 1),
            "bytes_in":       self.bytes_in,
            "bytes_out":      self.bytes_out,
            "packets_sent":   self.send_counter,
            "handshake_ms":   round(self.handshake_ms, 2),
            "session_key_id": hashlib.sha256(self.session_key).hexdigest()[:16],
        }


class PQCSidecar:
    """
    Layer 1: PQC WireGuard Sidecar.
    Listens on UDP port 51821, performs Kyber-768 handshake,
    establishes encrypted tunnel session.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = SIDECAR_PORT):
        self.host     = host
        self.port     = port
        self.kem      = KyberKEM()
        self.pk, self.sk = self.kem.generate_keypair()
        self.sessions: dict[tuple, TunnelSession] = {}
        self.pending_handshakes: dict[tuple, dict] = {}
        self._sock: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.on_packet: Optional[Callable[[bytes, tuple], None]] = None
        self.stats = {
            "handshakes_completed": 0,
            "handshakes_failed":    0,
            "packets_tunneled":     0,
            "handshake_times_ms":   [],
        }

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.settimeout(1.0)
        self._running = True
        self._thread = threading.Thread(target=self._listen_loop,
                                        name="VPN-Sidecar", daemon=True)
        self._thread.start()
        log.info(f"[Sidecar] Listening on {self.host}:{self.port} | "
                 f"PK={len(self.pk)}B (Kyber-768)")

    def stop(self):
        self._running = False
        if self._sock:
            self._sock.close()

    def _listen_loop(self):
        while self._running:
            try:
                data, addr = self._sock.recvfrom(65535)
                self._handle_packet(data, addr)
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_packet(self, data: bytes, addr: tuple):
        if len(data) < 1:
            return
        pkt_type = data[0]

        if pkt_type == TYPE_HANDSHAKE_INIT:
            self._handle_init(data, addr)
        elif pkt_type == TYPE_HANDSHAKE_RESP:
            self._handle_resp(data, addr)
        elif pkt_type == TYPE_TRANSPORT:
            self._handle_transport(data, addr)
        elif pkt_type == TYPE_KEEPALIVE:
            self._handle_keepalive(data, addr)

    # ─── Handshake: Responder side ───────────────────────────────────────────

    def _handle_init(self, data: bytes, addr: tuple):
        """Received HandshakeInit from initiator. Extract their PK, encapsulate."""
        t0 = time.time()
        # Format: [1B type][4B sender_idx][1184B kyber_pk][8B timestamp]
        if len(data) < 1 + 4 + KYBER768_PUBLIC_KEY_SIZE + 8:
            log.warning(f"[Sidecar] Short INIT from {addr}")
            return

        sender_idx = struct.unpack("!I", data[1:5])[0]
        peer_pk    = data[5:5 + KYBER768_PUBLIC_KEY_SIZE]
        timestamp  = struct.unpack("!d", data[5 + KYBER768_PUBLIC_KEY_SIZE:
                                               5 + KYBER768_PUBLIC_KEY_SIZE + 8])[0]

        log.info(f"[Sidecar] ← HANDSHAKE_INIT from {addr} | "
                 f"peer_pk={len(peer_pk)}B | latency={round((time.time()-timestamp)*1000,1)}ms")

        # Encapsulate to get shared secret
        ct, shared_secret = self.kem.encapsulate(peer_pk)

        # Derive session key via HKDF
        session_key = hkdf(shared_secret, 32,
                           salt=b"pqc-vpn-v1",
                           info=b"session-key")

        # Create session
        session = TunnelSession(addr, session_key)
        session.handshake_ms = (time.time() - t0) * 1000
        self.sessions[addr] = session

        # Send HandshakeResp: [1B type][4B our_idx][4B sender_idx][1088B ct][32B mac]
        our_idx = os.urandom(4)
        mac     = hashlib.sha256(session_key + our_idx).digest()[:16]
        resp    = bytes([TYPE_HANDSHAKE_RESP]) + our_idx + \
                  struct.pack("!I", sender_idx) + ct + mac

        self._sock.sendto(resp, addr)
        self.stats["handshakes_completed"] += 1
        self.stats["handshake_times_ms"].append(session.handshake_ms)

        log.info(f"[Sidecar] → HANDSHAKE_RESP to {addr} | "
                 f"ct={len(ct)}B | key={session_key.hex()[:16]}... | "
                 f"time={session.handshake_ms:.1f}ms")

    # ─── Handshake: Initiator side ───────────────────────────────────────────

    def initiate_handshake(self, peer_addr: tuple,
                           peer_pk: Optional[bytes] = None) -> Optional[TunnelSession]:
        """
        Initiate a handshake with a peer. Used when this node is the client.
        If peer_pk is None, uses our own PK (for self-test loopback).
        """
        t0         = time.time()
        sender_idx = struct.unpack("!I", os.urandom(4))[0]

        # In real deployment, peer_pk is obtained out-of-band (like WireGuard config)
        target_pk  = peer_pk if peer_pk is not None else self.pk

        init_pkt = bytes([TYPE_HANDSHAKE_INIT]) + \
                   struct.pack("!Id", sender_idx, t0) + target_pk

        log.info(f"[Sidecar] → HANDSHAKE_INIT to {peer_addr} | "
                 f"pk={len(target_pk)}B")

        self.pending_handshakes[peer_addr] = {
            "sender_idx": sender_idx,
            "t0": t0,
            "target_pk": target_pk,
        }

        self._sock.sendto(init_pkt, peer_addr)
        return None   # Session established async via _handle_resp

    def _handle_resp(self, data: bytes, addr: tuple):
        """Received HandshakeResp. Decapsulate to get shared secret."""
        pending = self.pending_handshakes.get(addr)
        if not pending:
            log.warning(f"[Sidecar] Unexpected RESP from {addr}")
            return

        # Format: [1B][4B our_idx][4B sender_idx][1088B ct][16B mac]
        offset  = 1
        our_idx = data[offset:offset+4]; offset += 4
        _sid    = data[offset:offset+4]; offset += 4
        ct      = data[offset:offset + KYBER768_CIPHERTEXT_SIZE]
        offset += KYBER768_CIPHERTEXT_SIZE
        mac     = data[offset:offset+16]

        # In simulation: decapsulate using our SK
        shared_secret = self.kem.decapsulate(ct, self.sk)
        session_key   = hkdf(shared_secret, 32,
                             salt=b"pqc-vpn-v1",
                             info=b"session-key")

        t0      = pending["t0"]
        session = TunnelSession(addr, session_key)
        session.handshake_ms = (time.time() - t0) * 1000
        self.sessions[addr]  = session

        del self.pending_handshakes[addr]
        self.stats["handshakes_completed"] += 1
        self.stats["handshake_times_ms"].append(session.handshake_ms)

        log.info(f"[Sidecar] ✓ SESSION ESTABLISHED with {addr} | "
                 f"handshake={session.handshake_ms:.1f}ms | "
                 f"key={session_key.hex()[:16]}...")

    # ─── Transport ───────────────────────────────────────────────────────────

    def send_through_tunnel(self, payload: bytes, peer_addr: tuple) -> bool:
        session = self.sessions.get(peer_addr)
        if not session:
            log.error(f"[Sidecar] No session for {peer_addr}")
            return False

        # Check MTU
        if len(payload) > TUNNEL_MTU:
            log.warning(f"[Sidecar] Payload {len(payload)}B > MTU {TUNNEL_MTU}B — "
                        f"should have been fragmented by wrapper!")

        pkt = session.encrypt_transport(payload)
        self._sock.sendto(pkt, peer_addr)
        session.bytes_out += len(pkt)
        self.stats["packets_tunneled"] += 1
        return True

    def _handle_transport(self, data: bytes, addr: tuple):
        session = self.sessions.get(addr)
        if not session:
            log.warning(f"[Sidecar] Transport from unknown peer {addr}")
            return
        try:
            plaintext = session.decrypt_transport(data)
            session.bytes_in  += len(data)
            session.last_seen  = time.time()
            if self.on_packet:
                self.on_packet(plaintext, addr)
        except Exception as e:
            log.error(f"[Sidecar] Decrypt error from {addr}: {e}")

    def _handle_keepalive(self, data: bytes, addr: tuple):
        if addr in self.sessions:
            self.sessions[addr].last_seen = time.time()

    def get_session_info(self) -> list[dict]:
        return [s.info() for s in self.sessions.values()]

    def avg_handshake_ms(self) -> float:
        times = self.stats["handshake_times_ms"]
        return round(sum(times) / len(times), 2) if times else 0.0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    print("[VPN Sidecar] Self-test...")

    server = PQCSidecar(port=51821)
    server.start()

    received = []
    server.on_packet = lambda pkt, addr: received.append(pkt)

    # Simulate client connecting to server
    import time
    time.sleep(0.1)

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_sock.settimeout(2.0)

    kem = KyberKEM()
    pk, sk = kem.generate_keypair()

    sender_idx = 12345
    t0 = time.time()
    init_pkt = bytes([TYPE_HANDSHAKE_INIT]) + \
               struct.pack("!Id", sender_idx, t0) + pk

    client_sock.sendto(init_pkt, ("127.0.0.1", 51821))
    resp, _ = client_sock.recvfrom(65535)
    print(f"Handshake response: {len(resp)} bytes")
    print(f"Session count: {len(server.sessions)}")
    print(f"Avg handshake: {server.avg_handshake_ms()} ms")

    server.stop()
    client_sock.close()
    print("[VPN Sidecar] Test complete ✓")
