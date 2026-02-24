# Double-Blind Post-Quantum Communication Ecosystem

> Implementation of Sections 5 & 6 from the CNS Project Report  
> 23BCE1759 & 23BCE1752

---

## Quick Start

```bash
# 1. Install dependency
pip install cryptography

# 2. Run Phase 3 Validation (Section 6)
python3 ecosystem.py

# 3. Launch Web Dashboard
python3 dashboard.py
# Open: http://localhost:7860
```

---

## System Architecture

```
Client (Alice)                          Server (Bob)
┌─────────────────────┐                ┌─────────────────────┐
│   PQC Messenger (L2)│                │   PQC Messenger (L2)│
│   Kyber-768 E2E     │                │   Reassembly Buffer  │
├─────────────────────┤                ├─────────────────────┤
│ Fragmentation       │                │ Fragmentation        │
│ Wrapper (≤1000B)    │                │ Wrapper (ACK/NACK)   │
├─────────────────────┤                ├─────────────────────┤
│ WireGuard-style VPN │◄──────────────►│ WireGuard-style VPN │
│ (Kyber-768 + AEAD)  │  UDP Packets   │ (Kyber-768 + AEAD)  │
└─────────────────────┘  <1400 bytes   └─────────────────────┘
```

---

## File Structure

| File | Section | Description |
|------|---------|-------------|
| `pqc_core.py` | §3.3 | Kyber-768 KEM + ChaCha20-Poly1305 AEAD + HKDF |
| `fragmentation_wrapper.py` | §5 (Novel) | Application-layer MTU fragmentation |
| `vpn_sidecar.py` | §5 §3.1 | Layer 1 PQC WireGuard sidecar (qTrustNet) |
| `messenger.py` | §5 §6 | Layer 2 PQC Secure Messenger |
| `ecosystem.py` | §6 Phase 3 | Full system orchestrator + validation |
| `dashboard.py` | §6 | Web monitoring dashboard |

---

## Key Sizes (NIST FIPS 203 / Kyber-768)

| Component | Size | Fragments Needed |
|-----------|------|------------------|
| Public Key | **1184 bytes** | 2 (at 1000B chunks) ✓ |
| Ciphertext | **1088 bytes** | 2 (at 1000B chunks) ✓ |
| Secret Key | **2400 bytes** | 3 (at 1000B chunks) ✓ |
| Shared Secret | **32 bytes** | 1 ✓ |
| McEliece PK (rejected) | 261,120 bytes | ~262 ✗ |

---

## The Nested MTU Paradox (Section 4)

```
Physical MTU:          1500 B  ████████████████████████████████
WireGuard overhead:   −80 B
Available:            1420 B  ███████████████████████████████
IPv6 path (worst):    1280 B  ████████████████████████████
PQC key size:         1184 B  → would crash without wrapper!
Safe chunk (ours):    1000 B  █████████████████████  ← Our solution
```

The **Fragmentation Wrapper** proactively splits any payload >1000B into
numbered chunks with application-layer ACKs, resolving the crash.

---

## Privacy Model (Double-Blind)

| Adversary | Sees | VPN-Only | E2E-Only | Double-Blind |
|-----------|------|----------|----------|--------------|
| ISP | Who you talk to | ✓ Blocked | ✗ Exposed | ✓ Blocked |
| VPN Provider | Message content | ✗ Exposed | ✓ Blocked | ✓ Blocked |
| Quantum Attacker | RSA/ECDH keys | ✗ Broken | ✗ Broken | ✓ Blocked |
| HNDL Attacker | Stored traffic | ✗ Exposed | ✗ Exposed | ✓ Blocked |

---

## Validation Results (Phase 3)

```
Layer 1 (VPN) handshake:   ~4ms   ← qTrustNet: 3-5ms ✓
Layer 2 (E2E) handshake:   ~52ms  ← <100ms target ✓
Total messages delivered:  5/5    ← 0% packet loss ✓
Fragments for Kyber PK:    2      ← fits in 1000B chunks ✓
MTU tested:                1280B  ← IPv6 worst case ✓
```

---

## Production Deployment

In production, replace `pqc_core.KyberKEM` with:
```python
import oqs
kem = oqs.KeyEncapsulation("Kyber768")
```

Install liboqs:
```bash
pip install oqs  # requires liboqs C library
# See: https://github.com/open-quantum-safe/liboqs-python
```

---

## References

1. Shim, H., et al. "qTrustNet VPN: Enhancing Security in the Quantum Era." *IEEE Access*, vol. 13, Jan. 2025.
2. NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard, Aug. 2024.
