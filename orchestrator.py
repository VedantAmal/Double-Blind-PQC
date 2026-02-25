"""
Double-Blind Post-Quantum Communication Ecosystem
===================================================
Orchestrator — Unified launcher for the Double-Blind system.

Starts both Layer 1 (PQC VPN Sidecar) and Layer 2 (PQC Messenger)
and coordinates between them.
"""

import os
import sys
import json
import time
import signal
import logging
import argparse
import subprocess
import threading
from typing import Optional

logger = logging.getLogger("orchestrator")

# ANSI color codes
class Color:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"


BANNER = f"""{Color.CYAN}{Color.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     🛡️  Double-Blind Post-Quantum Communication Ecosystem    ║
║                                                              ║
║     Layer 1: PQC VPN Sidecar  (Kyber-768 + WireGuard)       ║
║     Layer 2: PQC Messenger    (Kyber-768 + AES-256-GCM)     ║
║     Defense: Fragmentation Wrapper (1000B threshold)         ║
║                                                              ║
║     "Hide metadata from the ISP, content from the VPN"      ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
{Color.RESET}"""


def load_config(path: str = "config.json") -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def print_status(msg: str, color: str = Color.CYAN) -> None:
    print(f"{color}[orchestrator]{Color.RESET} {msg}")


def run_layer1(role: str, peer: str, config_path: str, python: str) -> subprocess.Popen:
    """Start the Layer 1 sidecar in a subprocess."""
    cmd = [
        python, "layer1_sidecar.py", role,
        "--peer", peer,
        "--config", config_path,
    ]
    print_status(f"Starting Layer 1 ({role}): {' '.join(cmd)}")
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    return proc


def stream_output(proc: subprocess.Popen, label: str, color: str) -> None:
    """Stream subprocess output with a colored label."""
    try:
        for line in proc.stdout:
            print(f"{color}[{label}]{Color.RESET} {line}", end="")
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(
        description="Double-Blind PQC Ecosystem — Unified Launcher"
    )
    parser.add_argument("mode", choices=["server", "client", "messenger-only", "demo"],
                        help="Deployment mode")
    parser.add_argument("--name", "-n", type=str, default="User",
                        help="Your display name for the messenger")
    parser.add_argument("--peer-vpn", type=str, default="127.0.0.1:51821",
                        help="Layer 1 peer endpoint (client mode)")
    parser.add_argument("--peer-chat", type=str, default=None,
                        help="Layer 2 peer endpoint host:port (connect mode)")
    parser.add_argument("--listen", "-l", type=int, default=51822,
                        help="Messenger listen port")
    parser.add_argument("--config", type=str, default="config.json")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    # Logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    print(BANNER)

    config = load_config(args.config)
    python = sys.executable

    if args.mode == "demo":
        # Demo mode: run messenger only (for demonstration without root/WireGuard)
        print_status("🎮 DEMO MODE — Messenger only (no VPN layer)", Color.YELLOW)
        print_status("This demonstrates the PQC encrypted chat with fragmentation")
        print()

        messenger_cmd = [
            python, "layer2_messenger.py",
            "--name", args.name,
            "--listen", str(args.listen),
        ]
        if args.peer_chat:
            messenger_cmd.extend(["--connect", args.peer_chat])
        if args.verbose:
            messenger_cmd.append("--verbose")

        print_status(f"Running: {' '.join(messenger_cmd)}")
        os.execvp(python, messenger_cmd)

    elif args.mode == "messenger-only":
        # Direct messenger mode
        messenger_cmd = [
            python, "layer2_messenger.py",
            "--name", args.name,
            "--listen", str(args.listen),
        ]
        if args.peer_chat:
            messenger_cmd.extend(["--connect", args.peer_chat])
        if args.verbose:
            messenger_cmd.append("--verbose")

        os.execvp(python, messenger_cmd)

    elif args.mode in ("server", "client"):
        # Full double-blind mode: Layer 1 + Layer 2
        vpn_role = args.mode

        print_status(f"Phase 1: Starting Layer 1 VPN Sidecar ({vpn_role})...")
        l1_proc = run_layer1(vpn_role, args.peer_vpn, args.config, python)

        # Stream L1 output in background
        l1_thread = threading.Thread(
            target=stream_output,
            args=(l1_proc, "L1-VPN", Color.BLUE),
            daemon=True,
        )
        l1_thread.start()

        # Wait for L1 to establish
        print_status("Waiting for Layer 1 tunnel to establish...")
        time.sleep(3)

        if l1_proc.poll() is not None:
            print_status("❌ Layer 1 failed to start", Color.RED)
            sys.exit(1)

        print_status("Phase 2: Starting Layer 2 Messenger...")
        messenger_cmd = [
            python, "layer2_messenger.py",
            "--name", args.name,
            "--listen", str(args.listen),
        ]
        if args.peer_chat:
            messenger_cmd.extend(["--connect", args.peer_chat])
        if args.verbose:
            messenger_cmd.append("--verbose")

        try:
            os.execvp(python, messenger_cmd)
        except KeyboardInterrupt:
            l1_proc.terminate()


if __name__ == "__main__":
    main()
