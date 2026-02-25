"""
Double-Blind Post-Quantum Communication Ecosystem
===================================================
Layer 2 — PQC Messenger

A real encrypted chat application that runs *inside* the VPN tunnel.
Uses Kyber-768 for key exchange and AES-256-GCM for message encryption.
All large handshake payloads are handled by the Fragmentation Wrapper.

Architecture:
  ┌─────────────────────────────────────────┐
  │              VPN Tunnel (Layer 1)       │
  │  ┌───────────┐         ┌───────────┐   │
  │  │ Messenger │◄──UDP──►│ Messenger │   │
  │  │  (Alice)  │ :51822  │   (Bob)   │   │
  │  │ Kyber KEM │         │ Kyber KEM │   │
  │  │ AES-GCM   │         │ AES-GCM   │   │
  │  └───────────┘         └───────────┘   │
  └─────────────────────────────────────────┘

The messenger provides:
  - Post-quantum key exchange (Kyber-768)
  - Authenticated encryption (AES-256-GCM)
  - Peer authentication (Dilithium-3 signatures)
  - Application-layer fragmentation for large handshakes
  - Interactive terminal-based chat UI
"""

import os
import sys
import json
import time
import socket
import threading
import logging
import argparse
import signal
from typing import Optional
from datetime import datetime

from crypto_core import PQCSession, SecurityError
from protocol import (
    MsgType, encode_message, decode_message,
    encode_handshake_init, decode_handshake_init,
    encode_handshake_resp, decode_handshake_resp,
    encode_chat_message, decode_chat_message,
)
from fragmentation import Fragmenter

logger = logging.getLogger("layer2_messenger")

# ANSI color codes for the terminal UI
class Color:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    GRAY    = "\033[90m"


# ---------------------------------------------------------------------------
#  PQC Messenger
# ---------------------------------------------------------------------------

class PQCMessenger:
    """
    Post-Quantum Encrypted Messenger.
    Performs a Kyber-768 handshake, then sends/receives AES-256-GCM encrypted
    messages over UDP, with application-layer fragmentation.
    """

    def __init__(self, username: str, listen_port: int = 51822,
                 peer_addr: Optional[tuple] = None, bind_addr: str = "0.0.0.0"):
        self.username = username
        self.listen_port = listen_port
        self.bind_addr = bind_addr
        self._peer_addr = peer_addr
        self._peer_name: Optional[str] = None

        # PQC session
        self.session = PQCSession(
            role="initiator" if peer_addr else "responder",
            label="L2-Chat"
        )

        # UDP socket
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.settimeout(1.0)

        # Fragmentation wrapper
        self._fragmenter = Fragmenter(
            send_func=self._raw_send,
            on_message=self._on_complete_message,
            threshold=1000,
        )

        self._running = False
        self._handshake_done = threading.Event()
        self._message_queue = []
        self._msg_lock = threading.Lock()
        self._msg_event = threading.Event()
        self._recv_buffer = []
        self._recv_event = threading.Event()

        # Background socket reader — feeds ALL incoming packets to the fragmenter
        # so that ACKs are processed even while send() is blocking
        self._bg_reader_thread: Optional[threading.Thread] = None

    def _raw_send(self, data: bytes, addr: tuple) -> None:
        """Raw UDP send for the fragmenter."""
        self._sock.sendto(data, addr)

    def _on_complete_message(self, payload: bytes, addr: tuple) -> None:
        """Called when a complete reassembled message arrives."""
        with self._msg_lock:
            self._recv_buffer.append((payload, addr))
        self._recv_event.set()

    def _bg_socket_reader(self) -> None:
        """
        Background thread: continuously reads from the UDP socket and feeds
        ALL packets to the fragmenter. This ensures ACKs are processed even
        while Fragmenter.send() is blocking in the main/handshake thread.
        """
        while self._running:
            try:
                self._sock.settimeout(0.3)
                data, addr = self._sock.recvfrom(65535)
                self._fragmenter.receive(data, addr)
            except socket.timeout:
                continue
            except OSError:
                break  # Socket closed

    def _recv_one(self, timeout: float = 10.0) -> tuple:
        """Receive one complete message (blocking until delivered by fragmenter)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._msg_lock:
                if self._recv_buffer:
                    return self._recv_buffer.pop(0)
            self._recv_event.clear()
            self._recv_event.wait(timeout=min(0.2, deadline - time.time()))

        raise TimeoutError("No message received")

    def _send_wire(self, data: bytes, addr: tuple) -> None:
        """Send data through the fragmentation wrapper."""
        self._fragmenter.send(data, addr)

    # ---- Handshake ------------------------------------------------

    def start(self) -> None:
        """Start the messenger and perform PQC handshake."""
        self._sock.bind((self.bind_addr, self.listen_port))
        self._running = True

        # Start background socket reader so ACKs are processed during handshake
        self._bg_reader_thread = threading.Thread(
            target=self._bg_socket_reader, daemon=True
        )
        self._bg_reader_thread.start()

        if self._peer_addr:
            self._client_handshake()
        else:
            self._server_handshake()

    def _server_handshake(self) -> None:
        """Wait for incoming handshake, respond."""
        self._print_system(f"Waiting for peer on UDP :{self.listen_port}...")

        # 1. Receive handshake init
        raw, addr = self._recv_one(timeout=60.0)
        self._peer_addr = addr
        msg_type, payload = decode_message(raw)

        if msg_type != MsgType.L2_HANDSHAKE_INIT:
            raise SecurityError(f"Expected L2_HANDSHAKE_INIT, got {msg_type}")

        init_data = decode_handshake_init(payload)
        self._print_system(f"Received handshake from {addr}")

        # 2. Process and create response
        handshake_msg = {
            "kem_pk": init_data["kem_pk"],
            "sig_pk": init_data["sig_pk"],
            "sig": init_data["sig"],
            "timestamp": init_data["timestamp"],
        }
        resp = self.session.process_handshake_init(handshake_msg)

        # 3. Send response
        resp_payload = encode_handshake_resp(
            resp["ciphertext"], resp["sig_pk"], resp["sig"]
        )
        resp_wire = encode_message(MsgType.L2_HANDSHAKE_RESP, resp_payload)
        self._send_wire(resp_wire, self._peer_addr)

        # 4. Receive peer's username (encrypted)
        raw2, _ = self._recv_one(timeout=10.0)
        msg_type2, enc_name = decode_message(raw2)
        if msg_type2 == MsgType.L2_PRESENCE:
            self._peer_name = self.session.decrypt(enc_name).decode()

        # 5. Send our username (encrypted)
        enc_our_name = self.session.encrypt(self.username.encode())
        name_wire = encode_message(MsgType.L2_PRESENCE, enc_our_name)
        self._send_wire(name_wire, self._peer_addr)

        self._handshake_done.set()
        self._print_handshake_complete()

    def _client_handshake(self) -> None:
        """Initiate handshake to peer."""
        self._print_system(f"Connecting to {self._peer_addr}...")

        # 1. Create and send handshake init
        init = self.session.create_handshake_init()
        init_payload = encode_handshake_init(
            init["kem_pk"], init["sig_pk"], init["sig"]
        )
        init_wire = encode_message(MsgType.L2_HANDSHAKE_INIT, init_payload)
        self._send_wire(init_wire, self._peer_addr)
        self._print_system("Sent PQC handshake init (Kyber-768 + Dilithium-3)")

        # 2. Receive response
        raw, _ = self._recv_one(timeout=10.0)
        msg_type, payload = decode_message(raw)
        if msg_type != MsgType.L2_HANDSHAKE_RESP:
            raise SecurityError(f"Expected L2_HANDSHAKE_RESP, got {msg_type}")

        resp_data = decode_handshake_resp(payload)
        self.session.process_handshake_resp(resp_data)

        # 3. Send our username (encrypted)
        enc_name = self.session.encrypt(self.username.encode())
        name_wire = encode_message(MsgType.L2_PRESENCE, enc_name)
        self._send_wire(name_wire, self._peer_addr)

        # 4. Receive peer's username (encrypted)
        raw2, _ = self._recv_one(timeout=10.0)
        msg_type2, enc_peer = decode_message(raw2)
        if msg_type2 == MsgType.L2_PRESENCE:
            self._peer_name = self.session.decrypt(enc_peer).decode()

        self._handshake_done.set()
        self._print_handshake_complete()

    # ---- Messaging ------------------------------------------------

    def send_message(self, text: str) -> None:
        """Encrypt and send a chat message."""
        if not self.session.is_established:
            self._print_system("Session not established!")
            return

        chat_payload = encode_chat_message(self.username, text)
        encrypted = self.session.encrypt(chat_payload)
        wire = encode_message(MsgType.L2_CHAT_MSG, encrypted)
        self._send_wire(wire, self._peer_addr)

    def _receive_loop(self) -> None:
        """Background thread: process reassembled messages from the fragmenter."""
        while self._running:
            try:
                # The bg reader thread feeds the fragmenter; we just drain reassembled messages
                with self._msg_lock:
                    messages = list(self._recv_buffer)
                    self._recv_buffer.clear()

                for raw, src in messages:
                    self._handle_message(raw, src)

                if not messages:
                    self._recv_event.clear()
                    self._recv_event.wait(timeout=0.3)

                # Periodically cleanup stale reassembly buffers
                self._fragmenter.cleanup_stale()

            except Exception as e:
                if self._running:
                    logger.error(f"Receive error: {e}")

    def _handle_message(self, raw: bytes, addr: tuple) -> None:
        """Process a complete received message."""
        try:
            msg_type, payload = decode_message(raw)

            if msg_type == MsgType.L2_CHAT_MSG:
                plaintext = self.session.decrypt(payload)
                chat = decode_chat_message(plaintext)
                self._print_incoming(chat)

            elif msg_type == MsgType.PING:
                pong = encode_message(MsgType.PONG, b"pong")
                self._send_wire(pong, addr)

            elif msg_type == MsgType.PONG:
                logger.debug("Pong received")

        except SecurityError as e:
            self._print_system(f"⚠ Security error: {e}")
        except Exception as e:
            logger.error(f"Message handling error: {e}")

    # ---- Interactive Chat UI --------------------------------------

    def run_chat(self) -> None:
        """Run the interactive chat loop."""
        # Start receive thread
        recv_thread = threading.Thread(target=self._receive_loop, daemon=True)
        recv_thread.start()

        self._print_system("Type your message and press Enter. /quit to exit, /stats for info.\n")

        try:
            while self._running:
                try:
                    text = input(f"{Color.GREEN}{self.username}{Color.RESET} ▸ ")
                except EOFError:
                    break

                text = text.strip()
                if not text:
                    continue

                if text.lower() == "/quit":
                    break
                elif text.lower() == "/stats":
                    self._print_stats()
                    continue
                elif text.lower() == "/info":
                    self._print_session_info()
                    continue

                self.send_message(text)
        except KeyboardInterrupt:
            pass
        finally:
            self._running = False
            self._print_system("Chat ended.")

    # ---- Terminal UI helpers --------------------------------------

    def _print_system(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"{Color.GRAY}[{ts}]{Color.RESET} {Color.CYAN}⚡ {msg}{Color.RESET}")

    def _print_incoming(self, chat: dict) -> None:
        ts = datetime.fromtimestamp(chat["ts"]).strftime("%H:%M:%S")
        sender = chat["sender"]
        text = chat["text"]
        print(f"\r{Color.GRAY}[{ts}]{Color.RESET} {Color.MAGENTA}{sender}{Color.RESET} ◂ {text}")
        # Re-show prompt
        print(f"{Color.GREEN}{self.username}{Color.RESET} ▸ ", end="", flush=True)

    def _print_handshake_complete(self) -> None:
        info = self.session.session_info()
        fstats = self._fragmenter.get_stats()

        print(f"\n{Color.GREEN}{'═'*60}")
        print(f"  🔒 Post-Quantum Encrypted Session Established!")
        print(f"{'═'*60}{Color.RESET}")
        print(f"  {Color.BOLD}Peer:{Color.RESET}        {self._peer_name or 'Unknown'} @ {self._peer_addr}")
        print(f"  {Color.BOLD}KEM:{Color.RESET}         Kyber-768 (ML-KEM-768)")
        print(f"  {Color.BOLD}Auth:{Color.RESET}        Dilithium-3 (ML-DSA-65)")
        print(f"  {Color.BOLD}Cipher:{Color.RESET}      AES-256-GCM")
        print(f"  {Color.BOLD}Session ID:{Color.RESET}  {info['shared_secret_hash']}")
        print(f"  {Color.BOLD}Fragments:{Color.RESET}   Sent={fstats['fragments_sent']} "
              f"Recv={fstats['fragments_received']} "
              f"Reassembled={fstats['messages_reassembled']}")
        print(f"{Color.GREEN}{'═'*60}{Color.RESET}\n")

    def _print_stats(self) -> None:
        fstats = self._fragmenter.get_stats()
        info = self.session.session_info()
        print(f"\n{Color.CYAN}{'─'*40}")
        print(f"  Session Info")
        print(f"{'─'*40}{Color.RESET}")
        print(f"  Role:          {info['role']}")
        print(f"  Established:   {info['established']}")
        print(f"  Session ID:    {info['shared_secret_hash']}")
        print(f"\n{Color.CYAN}  Fragmentation Stats{Color.RESET}")
        for k, v in fstats.items():
            print(f"  {k}: {v}")
        print(f"{Color.CYAN}{'─'*40}{Color.RESET}\n")

    def _print_session_info(self) -> None:
        info = self.session.session_info()
        print(f"\n{Color.YELLOW}{'─'*40}")
        print(f"  Crypto Details")
        print(f"{'─'*40}{Color.RESET}")
        print(f"  KEM:     Kyber-768 (1184B pk, 1088B ct)")
        print(f"  Auth:    Dilithium-3 (1952B pk, 3293B sig)")
        print(f"  Cipher:  AES-256-GCM (32B key, 12B nonce)")
        print(f"  KDF:     HKDF-SHA256")
        print(f"  MTU safe threshold: 1000B (fragments above this)")
        print(f"{Color.YELLOW}{'─'*40}{Color.RESET}\n")

    def shutdown(self) -> None:
        """Cleanup."""
        self._running = False
        self._sock.close()
        logger.info("Messenger shut down")


# ---------------------------------------------------------------------------
#  CLI Entry Point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Layer 2 — PQC Encrypted Messenger (Kyber-768 + AES-256-GCM)"
    )
    parser.add_argument("--name", "-n", type=str, required=True,
                        help="Your display name")
    parser.add_argument("--listen", "-l", type=int, default=51822,
                        help="UDP port to listen on (default: 51822)")
    parser.add_argument("--connect", "-c", type=str, default=None,
                        help="Peer address host:port to connect to (omit to listen)")
    parser.add_argument("--bind", "-b", type=str, default="0.0.0.0",
                        help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    # Logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    peer_addr = None
    if args.connect:
        host, port_str = args.connect.rsplit(":", 1)
        peer_addr = (host, int(port_str))

    print(f"\n{Color.BOLD}{'═'*60}")
    print(f"  Layer 2 — PQC Encrypted Messenger")
    print(f"  User: {args.name}")
    print(f"  Mode: {'Connect to ' + args.connect if args.connect else 'Listen on :' + str(args.listen)}")
    print(f"  KEM:  Kyber-768 | Cipher: AES-256-GCM")
    print(f"  Fragmentation Threshold: 1000 bytes")
    print(f"{'═'*60}{Color.RESET}\n")

    messenger = PQCMessenger(
        username=args.name,
        listen_port=args.listen,
        peer_addr=peer_addr,
        bind_addr=args.bind,
    )

    try:
        messenger.start()
        messenger.run_chat()
    except TimeoutError:
        print(f"\n{Color.RED}Connection timed out.{Color.RESET}")
    except SecurityError as e:
        print(f"\n{Color.RED}Security error: {e}{Color.RESET}")
    except Exception as e:
        print(f"\n{Color.RED}Error: {e}{Color.RESET}")
        logger.exception("Fatal error")
    finally:
        messenger.shutdown()


if __name__ == "__main__":
    main()
