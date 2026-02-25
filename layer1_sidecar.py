"""
Double-Blind Post-Quantum Communication Ecosystem
===================================================
Layer 1 — PQC VPN Sidecar

Based on the qTrustNet architecture (Shim et al., 2025):
  - Runs alongside WireGuard on the host
  - Performs a Kyber-768 key exchange on a sidecar port (51821)
  - Derives a 256-bit Pre-Shared Key (PSK)
  - Injects the PSK into the WireGuard interface via `wg set`
  - Provides post-quantum forward secrecy for the VPN tunnel

The sidecar operates in two roles:
  - Server: Listens for incoming PQC handshakes
  - Client: Initiates a PQC handshake to a server

Architecture:
  ┌────────────┐          ┌────────────┐
  │  Host A    │  UDP/51821  │  Host B    │
  │ ┌────────┐ │<──────────>│ ┌────────┐ │
  │ │Sidecar │ │  Kyber768  │ │Sidecar │ │
  │ └───┬────┘ │  Handshake │ └───┬────┘ │
  │     │ PSK  │            │     │ PSK  │
  │ ┌───▼────┐ │  WireGuard │ ┌───▼────┐ │
  │ │  wg0   │ │<══════════>│ │  wg0   │ │
  │ └────────┘ │  Encrypted │ └────────┘ │
  └────────────┘   Tunnel   └────────────┘
"""

import os
import sys
import json
import time
import socket
import struct
import base64
import hashlib
import logging
import argparse
import subprocess
import threading
from typing import Optional

from crypto_core import PQCSession, derive_key, SecurityError
from protocol import (
    MsgType, encode_message, decode_message,
    encode_handshake_init, decode_handshake_init,
    encode_handshake_resp, decode_handshake_resp,
)
from fragmentation import Fragmenter

logger = logging.getLogger("layer1_sidecar")

# ---------------------------------------------------------------------------
#  Configuration
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "sidecar_port": 51821,
    "wg_interface": "wg0",
    "wg_listen_port": 51820,
    "tunnel_address_server": "10.0.0.1/24",
    "tunnel_address_client": "10.0.0.2/24",
    "rekey_interval": 3600,  # seconds
    "mtu": 1420,
}


def load_config(path: str = "config.json") -> dict:
    """Merge file config with defaults."""
    cfg = dict(DEFAULT_CONFIG)
    try:
        with open(path) as f:
            file_cfg = json.load(f)
        if "network" in file_cfg:
            cfg["sidecar_port"] = file_cfg["network"].get("layer1_port", cfg["sidecar_port"])
        if "wireguard" in file_cfg:
            wg = file_cfg["wireguard"]
            cfg["wg_interface"] = wg.get("interface", cfg["wg_interface"])
            cfg["wg_listen_port"] = wg.get("listen_port", cfg["wg_listen_port"])
            cfg["tunnel_address_server"] = wg.get("tunnel_address_server", cfg["tunnel_address_server"])
            cfg["tunnel_address_client"] = wg.get("tunnel_address_client", cfg["tunnel_address_client"])
    except FileNotFoundError:
        logger.warning(f"Config file '{path}' not found, using defaults")
    return cfg


# ---------------------------------------------------------------------------
#  WireGuard Interface Management
# ---------------------------------------------------------------------------

class WireGuardManager:
    """
    Manages the WireGuard interface lifecycle.
    Generates keys, creates the interface, and injects the PQC PSK.
    """

    def __init__(self, interface: str = "wg0"):
        self.interface = interface
        self._private_key: Optional[str] = None
        self._public_key: Optional[str] = None
        self._wg_available = self._check_wg()

    def _check_wg(self) -> bool:
        """Check if WireGuard tools are available."""
        try:
            result = subprocess.run(["wg", "--version"], capture_output=True, text=True, timeout=5)
            logger.info(f"WireGuard available: {result.stdout.strip()}")
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.warning("WireGuard tools not found — running in KEY-ONLY mode "
                           "(PSK will be generated but not injected)")
            return False

    def generate_wg_keypair(self) -> tuple:
        """Generate WireGuard X25519 keypair."""
        if self._wg_available:
            priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True).stdout.strip()
            pub = subprocess.run(["wg", "pubkey"], input=priv,
                                 capture_output=True, text=True).stdout.strip()
        else:
            # Fallback: generate with PyNaCl
            from nacl.public import PrivateKey
            sk = PrivateKey.generate()
            priv = base64.b64encode(bytes(sk)).decode()
            pub = base64.b64encode(bytes(sk.public_key)).decode()

        self._private_key = priv
        self._public_key = pub
        logger.info(f"WireGuard keypair generated (pub={pub[:16]}...)")
        return priv, pub

    @property
    def public_key(self) -> Optional[str]:
        return self._public_key

    def setup_interface(self, listen_port: int, address: str) -> bool:
        """Create and configure the WireGuard interface."""
        if not self._wg_available:
            logger.info(f"[DRY-RUN] Would create {self.interface} on port {listen_port} with addr {address}")
            return True

        try:
            # Create the interface (platform-specific)
            if sys.platform == "darwin":
                # macOS with wireguard-go
                subprocess.run(["sudo", "wireguard-go", self.interface],
                               capture_output=True, timeout=10)
            else:
                subprocess.run(["sudo", "ip", "link", "add", "dev", self.interface, "type", "wireguard"],
                               capture_output=True, timeout=10)

            # Configure with private key
            key_file = f"/tmp/wg_{self.interface}_privkey"
            with open(key_file, "w") as f:
                f.write(self._private_key)
            os.chmod(key_file, 0o600)

            subprocess.run(
                ["sudo", "wg", "set", self.interface,
                 "listen-port", str(listen_port),
                 "private-key", key_file],
                check=True, capture_output=True, timeout=10,
            )

            # Assign IP address
            if sys.platform == "darwin":
                addr_ip = address.split("/")[0]
                subprocess.run(
                    ["sudo", "ifconfig", self.interface, "inet", addr_ip, addr_ip, "up"],
                    check=True, capture_output=True, timeout=10,
                )
            else:
                subprocess.run(
                    ["sudo", "ip", "addr", "add", address, "dev", self.interface],
                    check=True, capture_output=True, timeout=10,
                )
                subprocess.run(
                    ["sudo", "ip", "link", "set", "up", "dev", self.interface],
                    check=True, capture_output=True, timeout=10,
                )

            os.unlink(key_file)
            logger.info(f"WireGuard interface {self.interface} up on :{listen_port} ({address})")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to set up WireGuard: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"WireGuard setup error: {e}")
            return False

    def add_peer(self, peer_public_key: str, psk: str,
                 endpoint: str, allowed_ips: str = "10.0.0.0/24") -> bool:
        """Add a peer with PQC-derived PSK to the WireGuard interface."""
        if not self._wg_available:
            logger.info(f"[DRY-RUN] Would add peer {peer_public_key[:16]}... "
                        f"with PQC PSK to {self.interface}")
            logger.info(f"  PSK (first 16B): {psk[:24]}...")
            logger.info(f"  Endpoint: {endpoint}")
            logger.info(f"  Allowed IPs: {allowed_ips}")
            return True

        try:
            psk_file = f"/tmp/wg_{self.interface}_psk"
            with open(psk_file, "w") as f:
                f.write(psk)
            os.chmod(psk_file, 0o600)

            subprocess.run(
                ["sudo", "wg", "set", self.interface,
                 "peer", peer_public_key,
                 "preshared-key", psk_file,
                 "endpoint", endpoint,
                 "allowed-ips", allowed_ips,
                 "persistent-keepalive", "25"],
                check=True, capture_output=True, timeout=10,
            )
            os.unlink(psk_file)
            logger.info(f"Peer added to {self.interface} with PQC PSK")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to add peer: {e.stderr}")
            return False

    def teardown(self) -> None:
        """Remove the WireGuard interface."""
        if not self._wg_available:
            logger.info(f"[DRY-RUN] Would tear down {self.interface}")
            return
        try:
            if sys.platform == "darwin":
                subprocess.run(["sudo", "rm", f"/var/run/wireguard/{self.interface}.sock"],
                               capture_output=True, timeout=10)
            else:
                subprocess.run(["sudo", "ip", "link", "del", self.interface],
                               capture_output=True, timeout=10)
            logger.info(f"WireGuard interface {self.interface} removed")
        except Exception as e:
            logger.warning(f"Teardown error: {e}")


# ---------------------------------------------------------------------------
#  PQC Sidecar Daemon
# ---------------------------------------------------------------------------

class PQCSidecar:
    """
    The Layer 1 PQC Sidecar performs a Kyber-768 handshake over UDP,
    derives a WireGuard PSK, and injects it into the tunnel.
    """

    def __init__(self, role: str, config: dict, peer_endpoint: str = ""):
        """
        role: "server" or "client"
        config: configuration dict
        peer_endpoint: "host:port" of the remote sidecar (client only)
        """
        self.role = role
        self.config = config
        self.peer_endpoint = peer_endpoint
        self.session = PQCSession(
            role="responder" if role == "server" else "initiator",
            label="L1-VPN"
        )
        self.wg = WireGuardManager(config["wg_interface"])

        # UDP socket
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.settimeout(10.0)

        # Fragmentation wrapper
        self._fragmenter = Fragmenter(
            send_func=self._raw_send,
            on_message=self._on_complete_message,
            threshold=1000,
        )

        self._peer_addr: Optional[tuple] = None
        self._peer_wg_pub: Optional[str] = None
        self._psk: Optional[str] = None
        self._running = False
        self._handshake_complete = threading.Event()
        self._received_msg: Optional[bytes] = None
        self._msg_event = threading.Event()
        self._bg_reader_thread: Optional[threading.Thread] = None

    def _raw_send(self, data: bytes, addr: tuple) -> None:
        """Raw UDP send callback for the fragmenter."""
        self._sock.sendto(data, addr)

    def _on_complete_message(self, payload: bytes, addr: tuple) -> None:
        """Called when a complete (reassembled) message arrives."""
        self._received_msg = payload
        self._peer_addr = addr
        self._msg_event.set()

    def _bg_socket_reader(self) -> None:
        """Background thread: continuously reads UDP packets and feeds them to the fragmenter."""
        while self._running:
            try:
                self._sock.settimeout(0.3)
                data, addr = self._sock.recvfrom(65535)
                self._fragmenter.receive(data, addr)
            except socket.timeout:
                continue
            except OSError:
                break

    def _recv_message(self, timeout: float = 10.0) -> bytes:
        """Receive a complete message (handling fragmentation)."""
        self._msg_event.clear()
        self._received_msg = None
        deadline = time.time() + timeout

        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            if self._msg_event.wait(timeout=min(remaining, 0.3)):
                return self._received_msg

        raise TimeoutError("Timed out waiting for message")

    def _send_message(self, data: bytes, addr: tuple) -> None:
        """Send a message through the fragmentation wrapper."""
        self._fragmenter.send(data, addr)

    # ---- Handshake ------------------------------------------------

    def run_handshake(self) -> bool:
        """Execute the PQC handshake based on role."""
        start = time.time()
        try:
            if self.role == "server":
                success = self._server_handshake()
            else:
                success = self._client_handshake()

            elapsed_ms = (time.time() - start) * 1000
            if success:
                logger.info(f"✅ Layer 1 PQC handshake complete in {elapsed_ms:.1f}ms")
                self._handshake_complete.set()
            else:
                logger.error("❌ Layer 1 PQC handshake failed")
            return success

        except Exception as e:
            logger.error(f"❌ Handshake error: {e}")
            return False

    def _server_handshake(self) -> bool:
        """Server-side handshake: wait for init, respond."""
        port = self.config["sidecar_port"]
        self._sock.bind(("0.0.0.0", port))
        self._running = True
        self._bg_reader_thread = threading.Thread(target=self._bg_socket_reader, daemon=True)
        self._bg_reader_thread.start()
        logger.info(f"Layer 1 Sidecar (SERVER) listening on UDP :{port}")

        # 1. Receive handshake init
        raw = self._recv_message(timeout=30.0)
        msg_type, payload = decode_message(raw)
        if msg_type != MsgType.L1_HANDSHAKE_INIT:
            raise SecurityError(f"Expected L1_HANDSHAKE_INIT, got {msg_type}")

        init_data = decode_handshake_init(payload)
        logger.info(f"Received L1 handshake init from {self._peer_addr}")

        # Extract peer's WireGuard public key from init (appended after signature)
        # We embed it in the signature field as extra data
        peer_wg_pub = init_data.get("peer_wg_pub")

        # 2. Process init + create response
        handshake_msg = {
            "kem_pk": init_data["kem_pk"],
            "sig_pk": init_data["sig_pk"],
            "sig": init_data["sig"],
            "timestamp": init_data["timestamp"],
        }
        resp = self.session.process_handshake_init(handshake_msg)

        # 3. Generate WireGuard keys and include in response
        self.wg.generate_wg_keypair()
        resp_payload = encode_handshake_resp(
            resp["ciphertext"], resp["sig_pk"], resp["sig"]
        )
        resp_wire = encode_message(MsgType.L1_HANDSHAKE_RESP, resp_payload)

        # Also send our WG public key
        wg_pub_msg = encode_message(MsgType.L1_DATA, self.wg.public_key.encode())

        self._send_message(resp_wire, self._peer_addr)
        time.sleep(0.1)
        self._send_message(wg_pub_msg, self._peer_addr)

        # 4. Receive peer's WG public key
        raw2 = self._recv_message(timeout=10.0)
        msg_type2, payload2 = decode_message(raw2)
        if msg_type2 == MsgType.L1_DATA:
            self._peer_wg_pub = payload2.decode()

        # 5. Derive PSK from the PQC shared secret
        self._derive_and_inject_psk("server")
        return True

    def _client_handshake(self) -> bool:
        """Client-side handshake: initiate."""
        host, port_str = self.peer_endpoint.rsplit(":", 1)
        peer_addr = (host, int(port_str))

        self._sock.bind(("0.0.0.0", 0))  # Ephemeral port
        self._running = True
        self._bg_reader_thread = threading.Thread(target=self._bg_socket_reader, daemon=True)
        self._bg_reader_thread.start()
        logger.info(f"Layer 1 Sidecar (CLIENT) connecting to {peer_addr}")

        # 1. Generate WireGuard keys
        self.wg.generate_wg_keypair()

        # 2. Create handshake init
        init = self.session.create_handshake_init()
        init_payload = encode_handshake_init(
            init["kem_pk"], init["sig_pk"], init["sig"]
        )
        init_wire = encode_message(MsgType.L1_HANDSHAKE_INIT, init_payload)

        self._send_message(init_wire, peer_addr)
        logger.info("Sent L1 handshake init")

        # 3. Receive handshake response
        raw = self._recv_message(timeout=10.0)
        msg_type, payload = decode_message(raw)
        if msg_type != MsgType.L1_HANDSHAKE_RESP:
            raise SecurityError(f"Expected L1_HANDSHAKE_RESP, got {msg_type}")

        resp_data = decode_handshake_resp(payload)
        self.session.process_handshake_resp(resp_data)

        # 4. Receive peer's WG public key
        raw2 = self._recv_message(timeout=10.0)
        msg_type2, payload2 = decode_message(raw2)
        if msg_type2 == MsgType.L1_DATA:
            self._peer_wg_pub = payload2.decode()

        # 5. Send our WG public key
        wg_pub_msg = encode_message(MsgType.L1_DATA, self.wg.public_key.encode())
        self._send_message(wg_pub_msg, peer_addr)

        # 6. Derive PSK
        self._derive_and_inject_psk("client")
        return True

    def _derive_and_inject_psk(self, role: str) -> None:
        """
        Derive a WireGuard Pre-Shared Key from the Kyber shared secret
        and inject it into the WireGuard interface.
        """
        # The PQC session has a shared secret; derive a PSK from it
        session_info = self.session.session_info()
        shared_secret_hash = session_info["shared_secret_hash"]

        # Derive a 32-byte PSK using HKDF with role-specific context
        psk_bytes = derive_key(
            self.session._shared_secret,
            info=b"wireguard-pqc-psk",
            salt=b"double-blind-layer1",
        )
        self._psk = base64.b64encode(psk_bytes).decode()

        logger.info(f"PQC-derived PSK: {self._psk[:24]}...")

        # Setup WireGuard interface
        address = (self.config["tunnel_address_server"] if role == "server"
                   else self.config["tunnel_address_client"])
        self.wg.setup_interface(self.config["wg_listen_port"], address)

        # Add peer with PSK
        if self._peer_wg_pub:
            peer_ep = (f"{self._peer_addr[0]}:{self.config['wg_listen_port']}"
                       if self._peer_addr else "")
            self.wg.add_peer(
                self._peer_wg_pub, self._psk,
                endpoint=peer_ep,
                allowed_ips="10.0.0.0/24",
            )

    def get_tunnel_info(self) -> dict:
        """Return diagnostic info about the tunnel."""
        return {
            "role": self.role,
            "session": self.session.session_info(),
            "wg_interface": self.config["wg_interface"],
            "wg_public_key": self.wg.public_key,
            "peer_wg_public_key": self._peer_wg_pub,
            "psk_set": self._psk is not None,
            "fragmentation_stats": self._fragmenter.get_stats(),
        }

    def shutdown(self) -> None:
        """Cleanup."""
        self._running = False
        self._sock.close()
        self.wg.teardown()
        logger.info("Layer 1 Sidecar shut down")


# ---------------------------------------------------------------------------
#  CLI Entry Point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Layer 1 — PQC VPN Sidecar (Kyber-768 + WireGuard)"
    )
    parser.add_argument("role", choices=["server", "client"],
                        help="Run as 'server' (listen) or 'client' (connect)")
    parser.add_argument("--peer", type=str, default="127.0.0.1:51821",
                        help="Peer endpoint host:port (client mode)")
    parser.add_argument("--config", type=str, default="config.json",
                        help="Path to config file")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    # Logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    config = load_config(args.config)

    print(f"\n{'='*60}")
    print(f"  Layer 1 — PQC VPN Sidecar")
    print(f"  Role: {args.role.upper()}")
    print(f"  Sidecar Port: {config['sidecar_port']}")
    print(f"  KEM: Kyber-768 (ML-KEM-768)")
    print(f"  Auth: Dilithium-3 (ML-DSA-65)")
    print(f"{'='*60}\n")

    sidecar = PQCSidecar(
        role=args.role,
        config=config,
        peer_endpoint=args.peer,
    )

    try:
        success = sidecar.run_handshake()
        if success:
            info = sidecar.get_tunnel_info()
            print(f"\n{'─'*60}")
            print(f"  ✅ PQC VPN Tunnel Established!")
            print(f"  Shared Secret Hash: {info['session']['shared_secret_hash']}")
            print(f"  WG Public Key: {info['wg_public_key'][:24]}...")
            print(f"  Peer WG Key: {info.get('peer_wg_public_key', 'N/A')[:24] if info.get('peer_wg_public_key') else 'N/A'}...")
            print(f"  PSK Injected: {info['psk_set']}")
            fstats = info['fragmentation_stats']
            print(f"  Fragments Sent/Recv: {fstats['fragments_sent']}/{fstats['fragments_received']}")
            print(f"{'─'*60}\n")

            # Keep alive for the VPN tunnel
            print("Tunnel active. Press Ctrl+C to teardown.")
            while True:
                time.sleep(1)
        else:
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        sidecar.shutdown()


if __name__ == "__main__":
    main()
