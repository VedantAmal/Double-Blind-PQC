"""
Double-Blind Post-Quantum Communication Ecosystem
===================================================
Benchmarks — Measure handshake latency, throughput, and fragmentation overhead.
"""

import os
import sys
import time
import threading
import statistics

sys.path.insert(0, os.path.dirname(__file__))

from crypto_core import KyberKEM, DilithiumSigner, AESGCMCipher, PQCSession, derive_key
from fragmentation import Fragmenter
from protocol import encode_handshake_init, encode_message, MsgType


def benchmark_kyber():
    """Benchmark Kyber-768 operations."""
    print("\n🔑 Kyber-768 KEM Benchmark")
    print("─" * 40)

    # Keygen
    times = []
    for _ in range(50):
        kem = KyberKEM()
        t0 = time.perf_counter()
        pk = kem.generate_keypair()
        times.append((time.perf_counter() - t0) * 1000)
    print(f"  Keygen:     mean={statistics.mean(times):.2f}ms  "
          f"median={statistics.median(times):.2f}ms  "
          f"stdev={statistics.stdev(times):.2f}ms")

    # Encapsulate
    kem = KyberKEM()
    pk = kem.generate_keypair()
    times = []
    for _ in range(50):
        t0 = time.perf_counter()
        ct, ss = KyberKEM().encapsulate(pk)
        times.append((time.perf_counter() - t0) * 1000)
    print(f"  Encap:      mean={statistics.mean(times):.2f}ms  "
          f"median={statistics.median(times):.2f}ms")

    # Decapsulate
    kem2 = KyberKEM()
    pk2 = kem2.generate_keypair()
    ct, _ = KyberKEM().encapsulate(pk2)
    times = []
    for _ in range(50):
        t0 = time.perf_counter()
        kem2.decapsulate(ct)
        times.append((time.perf_counter() - t0) * 1000)
    print(f"  Decap:      mean={statistics.mean(times):.2f}ms  "
          f"median={statistics.median(times):.2f}ms")


def benchmark_dilithium():
    """Benchmark Dilithium-3 operations."""
    print("\n✍️  Dilithium-3 Signature Benchmark")
    print("─" * 40)

    signer = DilithiumSigner()
    pk = signer.generate_keypair()
    msg = os.urandom(256)

    # Sign
    times = []
    sigs = []
    for _ in range(50):
        t0 = time.perf_counter()
        sig = signer.sign(msg)
        times.append((time.perf_counter() - t0) * 1000)
        sigs.append(sig)
    print(f"  Sign:       mean={statistics.mean(times):.2f}ms  "
          f"median={statistics.median(times):.2f}ms")

    # Verify
    times = []
    for sig in sigs:
        t0 = time.perf_counter()
        DilithiumSigner.verify(msg, sig, pk)
        times.append((time.perf_counter() - t0) * 1000)
    print(f"  Verify:     mean={statistics.mean(times):.2f}ms  "
          f"median={statistics.median(times):.2f}ms")


def benchmark_aes():
    """Benchmark AES-256-GCM."""
    print("\n🔐 AES-256-GCM Benchmark")
    print("─" * 40)

    key = os.urandom(32)
    cipher = AESGCMCipher(key)

    for size in [64, 256, 1024, 4096]:
        plaintext = os.urandom(size)
        times_enc = []
        times_dec = []
        for _ in range(200):
            t0 = time.perf_counter()
            ct = cipher.encrypt(plaintext)
            times_enc.append((time.perf_counter() - t0) * 1000)

            t0 = time.perf_counter()
            cipher.decrypt(ct)
            times_dec.append((time.perf_counter() - t0) * 1000)

        print(f"  {size:>5}B encrypt: {statistics.mean(times_enc):.4f}ms  "
              f"decrypt: {statistics.mean(times_dec):.4f}ms")


def benchmark_handshake():
    """Benchmark full PQC handshake."""
    print("\n🤝 Full PQC Handshake Benchmark")
    print("─" * 40)

    times = []
    for _ in range(20):
        alice = PQCSession(role="initiator", label="bench")
        bob = PQCSession(role="responder", label="bench")

        t0 = time.perf_counter()
        init = alice.create_handshake_init()
        resp = bob.process_handshake_init(init)
        alice.process_handshake_resp(resp)
        elapsed = (time.perf_counter() - t0) * 1000
        times.append(elapsed)

    print(f"  Total:      mean={statistics.mean(times):.2f}ms  "
          f"median={statistics.median(times):.2f}ms  "
          f"min={min(times):.2f}ms  max={max(times):.2f}ms")
    print(f"  Target: <100ms  ✅" if statistics.mean(times) < 100
          else f"  Target: <100ms  ❌ ({statistics.mean(times):.0f}ms)")


def benchmark_fragmentation():
    """Benchmark fragmentation of a typical handshake init."""
    print("\n📦 Fragmentation Benchmark")
    print("─" * 40)

    session = PQCSession(role="initiator")
    init = session.create_handshake_init()
    init_payload = encode_handshake_init(
        init["kem_pk"], init["sig_pk"], init["sig"]
    )
    wire = encode_message(MsgType.L2_HANDSHAKE_INIT, init_payload)

    print(f"  Handshake init size: {len(wire)} bytes")
    print(f"  Fragment threshold:  1000 bytes")
    print(f"  Expected fragments:  {len(wire) // 1000 + 1}")

    # Measure fragmentation + reassembly through simulated network
    times = []
    for _ in range(20):
        sender_pkts = []
        receiver_pkts = []
        result = []

        def s_send(d, a): sender_pkts.append((d, a))
        def r_send(d, a): receiver_pkts.append((d, a))
        def on_msg(p, a): result.append(p)

        sender = Fragmenter(s_send, lambda p, a: None, threshold=1000)
        receiver = Fragmenter(r_send, on_msg, threshold=1000)

        t0 = time.perf_counter()

        send_thread = threading.Thread(target=sender.send, args=(wire, ("127.0.0.1", 9999)))
        send_thread.start()

        deadline = time.time() + 3
        while send_thread.is_alive() and time.time() < deadline:
            time.sleep(0.01)
            while sender_pkts:
                pkt, addr = sender_pkts.pop(0)
                receiver.receive(pkt, ("127.0.0.1", 8888))
            while receiver_pkts:
                pkt, addr = receiver_pkts.pop(0)
                sender.receive(pkt, ("127.0.0.1", 9999))

        send_thread.join(timeout=2)
        elapsed = (time.perf_counter() - t0) * 1000
        if result:
            times.append(elapsed)

    if times:
        print(f"  Fragment+Reassemble: mean={statistics.mean(times):.2f}ms  "
              f"median={statistics.median(times):.2f}ms")
        print(f"  0% packet loss: ✅")
    else:
        print(f"  ❌ Fragmentation failed!")


def main():
    print(f"\n{'='*60}")
    print(f"  Double-Blind PQC — Performance Benchmarks")
    print(f"{'='*60}")

    benchmark_kyber()
    benchmark_dilithium()
    benchmark_aes()
    benchmark_handshake()
    benchmark_fragmentation()

    print(f"\n{'='*60}")
    print(f"  Benchmarks complete!")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
