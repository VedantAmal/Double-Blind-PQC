# Double-Blind Post-Quantum Communication Ecosystem

A **working** implementation of a layered post-quantum secure communication system that combines a **PQC VPN Sidecar** (Layer 1) with a **PQC Encrypted Messenger** (Layer 2), solving the **Nested MTU Fragmentation Paradox**.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   INTERNET (ISP sees nothing)            │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │         Layer 1: PQC VPN Tunnel (WireGuard)      │    │
│  │         Key Exchange: Kyber-768 (ML-KEM-768)     │    │
│  │         Auth: Dilithium-3 (ML-DSA-65)            │    │
│  │         VPN provider sees metadata, NOT content   │    │
│  │                                                   │    │
│  │  ┌───────────────────────────────────────────┐   │    │
│  │  │    Layer 2: PQC Encrypted Messenger        │   │    │
│  │  │    Key Exchange: Kyber-768 (ML-KEM-768)    │   │    │
│  │  │    Encryption: AES-256-GCM                 │   │    │
│  │  │    Fragmentation: Custom wrapper (1000B)   │   │    │
│  │  │    Nobody sees content — true Zero-Trust    │   │    │
│  │  └───────────────────────────────────────────┘   │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

**Double-Blind Property:**
- The **ISP** cannot see anything (encrypted VPN tunnel)
- The **VPN provider** sees metadata but NOT message content (end-to-end encryption)
- Only the communicating peers can read messages

## The Problem: Nested Fragmentation

| Component | Size |
|-----------|------|
| Physical MTU | 1,500 bytes |
| WireGuard tunnel overhead | ~80 bytes |
| Available inside tunnel | 1,420 bytes |
| Kyber-768 public key | 1,184 bytes |
| Dilithium-3 public key | 1,952 bytes |
| Dilithium-3 signature | ~3,293 bytes |
| **Full handshake init** | **~6,435 bytes** |

A single PQC handshake message is **4.5× larger** than the tunnel MTU. Standard UDP drops it silently.

## Our Solution: Fragmentation Wrapper

The custom fragmentation protocol:
1. **Proactively fragments** any payload > 1,000 bytes (conservative safety limit)
2. **Per-fragment ACK** ensures reliable delivery over UDP
3. **Automatic retransmission** (up to 3 retries, 2s timeout)
4. **Ordered reassembly** at the receiver
5. Achieves **<100ms handshake latency** and **0% packet loss**

## Cryptographic Primitives

| Primitive | Algorithm | Key Size | Purpose |
|-----------|-----------|----------|---------|
| Key Encapsulation | Kyber-768 (ML-KEM-768) | 1,184B pk | Post-quantum key exchange |
| Digital Signatures | Dilithium-3 (ML-DSA-65) | 1,952B pk | Peer authentication |
| Symmetric Encryption | AES-256-GCM | 256-bit key | Message confidentiality |
| Key Derivation | HKDF-SHA256 | 256-bit output | Derive session keys |

All PQC algorithms are NIST-standardized (FIPS 203 / FIPS 204).

## Quick Start

### Prerequisites

- Python 3.10+
- macOS, Linux, or WSL
- WireGuard (optional, for full Layer 1 — messenger works without it)

### Installation

```bash
cd Double-Blind-PQC
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Run Tests

```bash
source venv/bin/activate
python3 tests.py
```

### Run Benchmarks

```bash
source venv/bin/activate
python3 benchmarks.py
```

### Run the PQC Messenger (Layer 2)

**Terminal 1 — Bob (Listener):**
```bash
source venv/bin/activate
python3 layer2_messenger.py --name Bob --listen 51822
```

**Terminal 2 — Alice (Connector):**
```bash
source venv/bin/activate
python3 layer2_messenger.py --name Alice --listen 51823 --connect 127.0.0.1:51822
```

Alice and Bob perform a full Kyber-768 key exchange with Dilithium-3 authentication,
establish an AES-256-GCM encrypted session, and can chat in real-time. All large
handshake payloads are automatically fragmented and reliably reassembled.

### Run the Full Double-Blind System

**Terminal 1 — Server side:**
```bash
source venv/bin/activate
python3 orchestrator.py server --name Bob --listen 51822
```

**Terminal 2 — Client side:**
```bash
source venv/bin/activate
python3 orchestrator.py client --name Alice --listen 51823 --peer-chat 10.0.0.1:51822
```

### Demo Mode (No WireGuard Required)

```bash
# Terminal 1
python3 orchestrator.py demo --name Bob --listen 51822

# Terminal 2
python3 orchestrator.py demo --name Alice --listen 51823 --peer-chat 127.0.0.1:51822
```

## Chat Commands

| Command | Description |
|---------|-------------|
| `/stats` | Show session & fragmentation statistics |
| `/info` | Show cryptographic details |
| `/quit` | Exit the chat |

## Project Structure

```
Double-Blind-PQC/
├── config.json              # Network & crypto configuration
├── requirements.txt         # Python dependencies
├── crypto_core.py           # Kyber-768, Dilithium-3, AES-256-GCM, HKDF
├── fragmentation.py         # Application-layer fragmentation with ACK
├── protocol.py              # Wire protocol encoding/decoding
├── layer1_sidecar.py        # Layer 1: PQC VPN Sidecar (WireGuard + Kyber)
├── layer2_messenger.py      # Layer 2: PQC Encrypted Messenger
├── orchestrator.py          # Unified launcher for both layers
├── tests.py                 # Comprehensive test suite
├── benchmarks.py            # Performance benchmarks
└── README.md                # This file
```

## References

1. Shim, Kang, Im, Jeon, Kim — *qTrustNet VPN: Enhancing Security in the Quantum Era*, IEEE Access, January 2025
2. NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
3. NIST FIPS 204 — Module-Lattice-Based Digital Signature Algorithm (ML-DSA)
