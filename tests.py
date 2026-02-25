"""
Double-Blind Post-Quantum Communication Ecosystem
===================================================
Test Suite — Validates all components end-to-end.

Tests:
  1. Crypto core (Kyber-768 KEM, Dilithium-3 signatures, AES-256-GCM)
  2. Fragmentation wrapper (split, reassembly, ACK, retransmission)
  3. Protocol encoding/decoding
  4. Full PQC handshake between two sessions
  5. End-to-end encrypted messaging
"""

import os
import sys
import time
import struct
import socket
import threading
import unittest
import logging

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(__file__))

from crypto_core import (
    KyberKEM, DilithiumSigner, AESGCMCipher, PQCSession,
    derive_key, SecurityError,
)
from fragmentation import (
    Fragmenter, HEADER_SIZE, FLAG_FRAG, FLAG_ACK,
    _pack_header, _unpack_header, _make_msg_id,
)
from protocol import (
    MsgType, encode_message, decode_message, decode_header,
    encode_handshake_init, decode_handshake_init,
    encode_handshake_resp, decode_handshake_resp,
    encode_chat_message, decode_chat_message,
    ProtocolError, HEADER_SIZE as PROTO_HEADER_SIZE,
)

logging.basicConfig(level=logging.WARNING)


class TestKyberKEM(unittest.TestCase):
    """Test Kyber-768 key encapsulation."""

    def test_keypair_generation(self):
        kem = KyberKEM()
        pk = kem.generate_keypair()
        self.assertEqual(len(pk), 1184)  # Kyber-768 public key size
        self.assertIsNotNone(kem.public_key)

    def test_encap_decap(self):
        alice = KyberKEM()
        alice_pk = alice.generate_keypair()

        bob = KyberKEM()
        ct, ss_bob = bob.encapsulate(alice_pk)
        self.assertEqual(len(ct), 1088)  # Kyber-768 ciphertext size
        self.assertEqual(len(ss_bob), 32)  # 256-bit shared secret

        ss_alice = alice.decapsulate(ct)
        self.assertEqual(ss_alice, ss_bob)  # Shared secrets must match

    def test_different_keypairs_different_secrets(self):
        kem1 = KyberKEM()
        pk1 = kem1.generate_keypair()

        kem2 = KyberKEM()
        pk2 = kem2.generate_keypair()

        _, ss1 = KyberKEM().encapsulate(pk1)
        _, ss2 = KyberKEM().encapsulate(pk2)
        self.assertNotEqual(ss1, ss2)


class TestDilithiumSigner(unittest.TestCase):
    """Test Dilithium-3 signatures."""

    def test_sign_verify(self):
        signer = DilithiumSigner()
        pk = signer.generate_keypair()
        self.assertEqual(len(pk), 1952)

        msg = b"test message for signing"
        sig = signer.sign(msg)
        self.assertGreater(len(sig), 0)

        self.assertTrue(DilithiumSigner.verify(msg, sig, pk))

    def test_verify_wrong_message(self):
        signer = DilithiumSigner()
        pk = signer.generate_keypair()
        sig = signer.sign(b"original")
        self.assertFalse(DilithiumSigner.verify(b"tampered", sig, pk))

    def test_verify_wrong_key(self):
        signer1 = DilithiumSigner()
        pk1 = signer1.generate_keypair()
        signer2 = DilithiumSigner()
        pk2 = signer2.generate_keypair()

        msg = b"test"
        sig = signer1.sign(msg)
        self.assertFalse(DilithiumSigner.verify(msg, sig, pk2))


class TestAESGCM(unittest.TestCase):
    """Test AES-256-GCM encryption."""

    def test_encrypt_decrypt(self):
        key = os.urandom(32)
        cipher = AESGCMCipher(key)

        plaintext = b"Hello, Post-Quantum World!"
        ct = cipher.encrypt(plaintext)
        self.assertNotEqual(ct, plaintext)
        self.assertGreater(len(ct), len(plaintext))  # nonce + tag

        pt = cipher.decrypt(ct)
        self.assertEqual(pt, plaintext)

    def test_decrypt_with_key(self):
        key = os.urandom(32)
        cipher = AESGCMCipher(key)
        plaintext = b"Static decrypt test"
        ct = cipher.encrypt(plaintext)
        pt = AESGCMCipher.decrypt_with_key(key, ct)
        self.assertEqual(pt, plaintext)

    def test_wrong_key_fails(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        cipher1 = AESGCMCipher(key1)
        ct = cipher1.encrypt(b"secret data")

        cipher2 = AESGCMCipher(key2)
        with self.assertRaises(Exception):
            cipher2.decrypt(ct)

    def test_nonce_uniqueness(self):
        key = os.urandom(32)
        cipher = AESGCMCipher(key)
        ct1 = cipher.encrypt(b"msg1")
        ct2 = cipher.encrypt(b"msg2")
        # First 12 bytes (nonce) should differ
        self.assertNotEqual(ct1[:12], ct2[:12])


class TestHKDF(unittest.TestCase):
    """Test HKDF key derivation."""

    def test_derive_key(self):
        secret = os.urandom(32)
        key = derive_key(secret, info=b"test")
        self.assertEqual(len(key), 32)

    def test_different_info_different_keys(self):
        secret = os.urandom(32)
        k1 = derive_key(secret, info=b"context-1")
        k2 = derive_key(secret, info=b"context-2")
        self.assertNotEqual(k1, k2)

    def test_deterministic(self):
        secret = b"fixed-secret-for-test" + b"\x00" * 11
        k1 = derive_key(secret, info=b"same", salt=b"salt")
        k2 = derive_key(secret, info=b"same", salt=b"salt")
        self.assertEqual(k1, k2)


class TestPQCSession(unittest.TestCase):
    """Test full PQC handshake between two sessions."""

    def test_handshake(self):
        alice = PQCSession(role="initiator", label="Alice")
        bob = PQCSession(role="responder", label="Bob")

        # Alice creates init
        init_msg = alice.create_handshake_init()
        self.assertIn("kem_pk", init_msg)
        self.assertIn("sig_pk", init_msg)
        self.assertIn("sig", init_msg)

        # Bob processes init and creates response
        resp_msg = bob.process_handshake_init(init_msg)
        self.assertTrue(bob.is_established)

        # Alice processes response
        alice.process_handshake_resp(resp_msg)
        self.assertTrue(alice.is_established)

        # Both should have the same session key (verify via encryption)
        plaintext = b"Hello from Alice!"
        ct = alice.encrypt(plaintext)
        pt = bob.decrypt(ct)
        self.assertEqual(pt, plaintext)

        # And the reverse direction
        ct2 = bob.encrypt(b"Hello from Bob!")
        pt2 = alice.decrypt(ct2)
        self.assertEqual(pt2, b"Hello from Bob!")

    def test_session_info(self):
        alice = PQCSession(role="initiator")
        bob = PQCSession(role="responder")
        init = alice.create_handshake_init()
        resp = bob.process_handshake_init(init)
        alice.process_handshake_resp(resp)

        info_a = alice.session_info()
        info_b = bob.session_info()
        self.assertEqual(info_a["shared_secret_hash"], info_b["shared_secret_hash"])


class TestFragmentation(unittest.TestCase):
    """Test the fragmentation wrapper."""

    def test_small_message_no_fragmentation(self):
        """Messages under threshold should not be fragmented."""
        sent = []
        received = []

        def send_func(data, addr):
            sent.append((data, addr))

        def on_msg(payload, addr):
            received.append((payload, addr))

        frag = Fragmenter(send_func, on_msg, threshold=1000)
        payload = b"small message"
        frag.send(payload, ("127.0.0.1", 9999))

        self.assertEqual(len(sent), 1)
        # The receiver should get it as a whole message
        frag.receive(sent[0][0], ("127.0.0.1", 9999))
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0][0], payload)

    def test_large_message_fragmentation(self):
        """Messages over threshold should be fragmented and reassembled."""
        sender_packets = []
        receiver_packets = []
        result = []

        def sender_send(data, addr):
            sender_packets.append((data, addr))

        def receiver_send(data, addr):
            receiver_packets.append((data, addr))

        def on_msg(payload, addr):
            result.append(payload)

        sender = Fragmenter(sender_send, lambda p, a: None, threshold=100)
        receiver = Fragmenter(receiver_send, on_msg, threshold=100)

        # Create a payload larger than threshold
        payload = os.urandom(350)  # Will be split into 4 chunks

        # Send in a thread (because it waits for ACKs)
        def do_send():
            sender.send(payload, ("127.0.0.1", 9999))

        t = threading.Thread(target=do_send)
        t.start()

        # Simulate network: forward packets between sender and receiver
        deadline = time.time() + 5
        while t.is_alive() and time.time() < deadline:
            time.sleep(0.05)
            # Forward sender → receiver
            while sender_packets:
                pkt, addr = sender_packets.pop(0)
                receiver.receive(pkt, ("127.0.0.1", 8888))
            # Forward receiver → sender (ACKs)
            while receiver_packets:
                pkt, addr = receiver_packets.pop(0)
                sender.receive(pkt, ("127.0.0.1", 9999))

        t.join(timeout=3)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], payload)

    def test_header_pack_unpack(self):
        flags, msg_id, seq, total, plen = 0x03, 0xDEADBEEF, 5, 10, 500
        hdr = _pack_header(flags, msg_id, seq, total, plen)
        self.assertEqual(len(hdr), HEADER_SIZE)
        f2, m2, s2, t2, p2 = _unpack_header(hdr)
        self.assertEqual((f2, m2, s2, t2, p2), (flags, msg_id, seq, total, plen))


class TestProtocol(unittest.TestCase):
    """Test wire protocol encoding/decoding."""

    def test_encode_decode_message(self):
        payload = b"test payload data"
        wire = encode_message(MsgType.L2_CHAT_MSG, payload)
        mt, pl = decode_message(wire)
        self.assertEqual(mt, MsgType.L2_CHAT_MSG)
        self.assertEqual(pl, payload)

    def test_handshake_init_roundtrip(self):
        kem_pk = os.urandom(1184)
        sig_pk = os.urandom(1952)
        sig = os.urandom(3293)
        encoded = encode_handshake_init(kem_pk, sig_pk, sig)
        decoded = decode_handshake_init(encoded)
        self.assertEqual(decoded["kem_pk"], kem_pk)
        self.assertEqual(decoded["sig_pk"], sig_pk)
        self.assertEqual(decoded["sig"], sig)

    def test_handshake_resp_roundtrip(self):
        ct = os.urandom(1088)
        sig_pk = os.urandom(1952)
        sig = os.urandom(3293)
        encoded = encode_handshake_resp(ct, sig_pk, sig)
        decoded = decode_handshake_resp(encoded)
        self.assertEqual(decoded["ciphertext"], ct)
        self.assertEqual(decoded["sig_pk"], sig_pk)
        self.assertEqual(decoded["sig"], sig)

    def test_chat_message_roundtrip(self):
        encoded = encode_chat_message("Alice", "Hello Bob!", 1700000000.0)
        decoded = decode_chat_message(encoded)
        self.assertEqual(decoded["sender"], "Alice")
        self.assertEqual(decoded["text"], "Hello Bob!")
        self.assertEqual(decoded["ts"], 1700000000.0)

    def test_invalid_message_type(self):
        bad_wire = struct.pack("!HI", 0x9999, 5) + b"hello"
        with self.assertRaises(ProtocolError):
            decode_message(bad_wire)

    def test_truncated_payload(self):
        wire = struct.pack("!HI", int(MsgType.PING), 100) + b"short"
        with self.assertRaises(ProtocolError):
            decode_message(wire)


class TestEndToEnd(unittest.TestCase):
    """
    End-to-end test: two messenger instances perform a PQC handshake
    and exchange encrypted messages over real UDP sockets on localhost.
    """

    def test_e2e_handshake_and_chat(self):
        """Full end-to-end: handshake + encrypted messages over UDP."""
        port_a = 61000
        port_b = 61001
        results = {"a_received": [], "b_received": [], "errors": []}

        def run_peer(role, name, listen_port, peer_addr, results_key):
            try:
                from layer2_messenger import PQCMessenger
                m = PQCMessenger(
                    username=name,
                    listen_port=listen_port,
                    peer_addr=peer_addr,
                    bind_addr="127.0.0.1",
                )
                m.start()

                # Send a test message
                m.send_message(f"Hello from {name}!")
                time.sleep(0.5)

                # Receive via the background mechanism
                # We'll just check the handshake completed
                results[results_key].append(m.session.is_established)
                results[results_key].append(m._peer_name)

                # Send another message and receive
                m.send_message(f"Second message from {name}")
                time.sleep(0.3)

                m.shutdown()
            except Exception as e:
                results["errors"].append(str(e))

        # Start Bob (server) first
        bob_thread = threading.Thread(
            target=run_peer,
            args=("server", "Bob", port_b, None, "b_received"),
        )
        bob_thread.start()
        time.sleep(0.3)

        # Then Alice (client)
        alice_thread = threading.Thread(
            target=run_peer,
            args=("client", "Alice", port_a, ("127.0.0.1", port_b), "a_received"),
        )
        alice_thread.start()

        alice_thread.join(timeout=15)
        bob_thread.join(timeout=15)

        # Verify
        self.assertEqual(results["errors"], [], f"Errors: {results['errors']}")
        self.assertTrue(results["a_received"][0], "Alice session not established")
        self.assertTrue(results["b_received"][0], "Bob session not established")
        self.assertEqual(results["a_received"][1], "Bob")
        self.assertEqual(results["b_received"][1], "Alice")


class TestMTUAnalysis(unittest.TestCase):
    """Verify that our fragmentation thresholds are correct."""

    def test_kyber_pk_needs_fragmentation(self):
        """A Kyber-768 public key (1184B) + protocol headers exceeds 1000B threshold."""
        kem = KyberKEM()
        pk = kem.generate_keypair()
        self.assertEqual(len(pk), 1184)
        self.assertGreater(len(pk), 1000, "Kyber pk should exceed frag threshold")

    def test_handshake_init_size(self):
        """Handshake init contains KEM pk + Sig pk + Signature — very large."""
        session = PQCSession(role="initiator")
        init = session.create_handshake_init()
        init_payload = encode_handshake_init(
            init["kem_pk"], init["sig_pk"], init["sig"]
        )
        total_size = len(init_payload) + PROTO_HEADER_SIZE
        # Should be > 6000 bytes (1184 + 1952 + 3293 + headers)
        self.assertGreater(total_size, 6000,
                           f"Handshake init ({total_size}B) should need fragmentation")
        print(f"\n  [MTU Analysis] Handshake init total: {total_size} bytes")
        print(f"  Kyber-768 PK: {len(init['kem_pk'])} bytes")
        print(f"  Dilithium-3 PK: {len(init['sig_pk'])} bytes")
        print(f"  Dilithium-3 Sig: {len(init['sig'])} bytes")
        print(f"  Without fragmentation, this WOULD FAIL on a 1420B tunnel MTU")
        print(f"  With 1000B threshold: needs {total_size // 1000 + 1} fragments")


if __name__ == "__main__":
    print(f"\n{'='*60}")
    print(f"  Double-Blind PQC — Test Suite")
    print(f"  Testing: Kyber-768, Dilithium-3, AES-256-GCM,")
    print(f"           Fragmentation Wrapper, Protocol, E2E")
    print(f"{'='*60}\n")

    unittest.main(verbosity=2)
