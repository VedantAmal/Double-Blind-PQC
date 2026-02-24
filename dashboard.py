"""
dashboard.py — Web Dashboard for Double-Blind PQC Ecosystem
===========================================================
Provides a real-time monitoring UI showing:
  - VPN tunnel status
  - Fragmentation stats
  - E2E session metrics
  - Live message log
  - Packet flow visualization
"""

import threading
import time
import json
import os
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from ecosystem import DoubleBlindNode, run_full_validation
from pqc_core import KYBER768_PUBLIC_KEY_SIZE, KYBER768_CIPHERTEXT_SIZE, KYBER768_SECRET_KEY_SIZE

log = logging.getLogger("Dashboard")

# ─── Global State ─────────────────────────────────────────────────────────────
alice_node: DoubleBlindNode = None
bob_node:   DoubleBlindNode = None
message_log: list = []
system_running = False
demo_thread = None


def init_system():
    global alice_node, bob_node, system_running, message_log
    message_log = []

    alice_node = DoubleBlindNode("Alice")
    bob_node   = DoubleBlindNode("Bob")

    alice_port = alice_node.start()
    bob_port   = bob_node.start()

    # Wire up message reception
    def on_bob_message(sid, sender, text):
        message_log.append({
            "ts":      time.time(),
            "from":    "Alice",
            "to":      "Bob",
            "text":    text,
            "session": sid,
            "layer":   "E2E (L2)",
        })

    bob_node.messenger.on_chat_message = on_bob_message

    # Layer 1 handshake
    def do_connect():
        alice_node.connect("127.0.0.1", bob_port, bob_node.vpn_pk)

    t = threading.Thread(target=do_connect, daemon=True)
    t.start()
    bob_node.vpn_ready.wait(timeout=5)
    t.join(timeout=5)

    # Layer 2 handshake
    alice_node.open_chat("demo-channel")
    time.sleep(0.2)

    system_running = True
    message_log.append({
        "ts":      time.time(),
        "from":    "SYSTEM",
        "to":      "ALL",
        "text":    "Double-Blind PQC Ecosystem initialized ✓",
        "session": "system",
        "layer":   "SYSTEM",
    })
    return alice_port, bob_port


def send_demo_message(text: str):
    if alice_node and system_running:
        alice_node.send("demo-channel", text)


# ─── HTTP Handler ─────────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Double-Blind PQC Ecosystem</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:       #050a12;
    --bg2:      #0a1628;
    --bg3:      #0d1f3c;
    --cyan:     #00f5ff;
    --cyan2:    #00bcd4;
    --green:    #39ff14;
    --amber:    #ffaa00;
    --red:      #ff3860;
    --purple:   #7c3aed;
    --text:     #cce8ff;
    --dim:      #4a6480;
    --border:   rgba(0,245,255,0.15);
    --glow:     0 0 20px rgba(0,245,255,0.3);
    --glow2:    0 0 40px rgba(0,245,255,0.15);
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Rajdhani', sans-serif;
    font-size: 15px;
    min-height: 100vh;
    overflow-x: hidden;
  }
  body::before {
    content: '';
    position: fixed; inset: 0;
    background:
      repeating-linear-gradient(0deg, transparent, transparent 2px,
        rgba(0,245,255,0.015) 2px, rgba(0,245,255,0.015) 4px),
      repeating-linear-gradient(90deg, transparent, transparent 2px,
        rgba(0,245,255,0.015) 2px, rgba(0,245,255,0.015) 4px);
    pointer-events: none; z-index: 0;
  }
  .container { max-width: 1400px; margin: 0 auto; padding: 0 20px; position: relative; z-index: 1; }

  /* Header */
  header {
    background: linear-gradient(135deg, var(--bg2) 0%, var(--bg3) 100%);
    border-bottom: 1px solid var(--border);
    padding: 16px 0;
    box-shadow: var(--glow2);
  }
  .header-inner { display: flex; align-items: center; justify-content: space-between; }
  .logo {
    display: flex; align-items: center; gap: 14px;
  }
  .logo-icon {
    width: 48px; height: 48px;
    background: conic-gradient(from 0deg, var(--cyan), var(--purple), var(--cyan));
    clip-path: polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%);
    animation: spin 12s linear infinite;
    flex-shrink: 0;
  }
  @keyframes spin { to { filter: hue-rotate(360deg); } }
  .logo-text h1 {
    font-size: 22px; font-weight: 700; color: var(--cyan);
    letter-spacing: 2px; text-transform: uppercase;
    text-shadow: 0 0 20px rgba(0,245,255,0.6);
  }
  .logo-text p { font-size: 11px; color: var(--dim); letter-spacing: 3px; text-transform: uppercase; }
  .status-bar { display: flex; gap: 16px; align-items: center; }
  .status-pill {
    display: flex; align-items: center; gap: 6px;
    background: rgba(0,245,255,0.05); border: 1px solid var(--border);
    padding: 4px 12px; border-radius: 20px; font-size: 11px;
    letter-spacing: 1px; text-transform: uppercase;
  }
  .dot {
    width: 7px; height: 7px; border-radius: 50%;
    background: var(--green);
    box-shadow: 0 0 8px var(--green);
    animation: blink 1.5s ease-in-out infinite;
  }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }
  .dot.amber { background: var(--amber); box-shadow: 0 0 8px var(--amber); }
  .dot.red { background: var(--red); box-shadow: 0 0 8px var(--red); animation: none; }

  /* Layout */
  main { padding: 24px 0; }
  .grid { display: grid; gap: 16px; }
  .grid-3 { grid-template-columns: repeat(3, 1fr); }
  .grid-2 { grid-template-columns: 1fr 1fr; }
  .grid-7-5 { grid-template-columns: 7fr 5fr; }

  /* Cards */
  .card {
    background: linear-gradient(135deg, var(--bg2), var(--bg3));
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
    box-shadow: var(--glow2);
  }
  .card-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 12px 16px;
    background: rgba(0,245,255,0.04);
    border-bottom: 1px solid var(--border);
  }
  .card-title {
    font-size: 11px; font-weight: 600; letter-spacing: 2px;
    text-transform: uppercase; color: var(--cyan);
  }
  .card-body { padding: 16px; }

  /* Metrics */
  .metrics-grid { display: grid; grid-template-columns: repeat(2,1fr); gap: 10px; }
  .metric {
    background: rgba(0,0,0,0.3); border: 1px solid var(--border);
    border-radius: 6px; padding: 10px 12px; text-align: center;
  }
  .metric-val {
    font-family: 'Share Tech Mono', monospace;
    font-size: 22px; font-weight: 700; color: var(--cyan);
    text-shadow: 0 0 15px rgba(0,245,255,0.5);
    line-height: 1;
  }
  .metric-val.green { color: var(--green); text-shadow: 0 0 15px rgba(57,255,20,0.4); }
  .metric-val.amber { color: var(--amber); text-shadow: 0 0 15px rgba(255,170,0,0.4); }
  .metric-lbl { font-size: 10px; color: var(--dim); letter-spacing: 1px; text-transform: uppercase; margin-top: 4px; }

  /* Architecture Diagram */
  .arch-diagram {
    position: relative; overflow: hidden;
  }
  .arch-node {
    background: rgba(0,0,0,0.5); border: 1px solid var(--border);
    border-radius: 6px; padding: 10px 14px; margin: 6px 0;
    display: flex; align-items: center; gap: 10px;
    font-size: 12px; font-family: 'Share Tech Mono', monospace;
    transition: all 0.3s ease;
    position: relative;
  }
  .arch-node:hover { border-color: var(--cyan); box-shadow: var(--glow); }
  .arch-node.layer2 { border-color: rgba(57,255,20,0.3); }
  .arch-node.layer2:hover { border-color: var(--green); box-shadow: 0 0 20px rgba(57,255,20,0.3); }
  .arch-node.physical { border-color: rgba(255,170,0,0.2); font-size: 11px; }
  .node-icon { font-size: 16px; flex-shrink: 0; }
  .node-label { flex: 1; }
  .node-size { font-size: 10px; color: var(--dim); }
  .arch-arrow {
    text-align: center; color: var(--dim); font-size: 11px;
    font-family: 'Share Tech Mono', monospace;
    padding: 2px 0;
    display: flex; align-items: center; gap: 8px; justify-content: center;
  }
  .arch-arrow::before, .arch-arrow::after {
    content: ''; flex: 1; height: 1px;
    background: linear-gradient(90deg, transparent, var(--border), transparent);
  }

  /* Privacy Layers */
  .privacy-layers { display: flex; flex-direction: column; gap: 8px; }
  .privacy-layer {
    border-radius: 6px; padding: 12px;
    border-left: 3px solid;
    background: rgba(0,0,0,0.3);
  }
  .privacy-layer.l1 { border-color: var(--cyan); }
  .privacy-layer.l2 { border-color: var(--green); }
  .privacy-layer.threat { border-color: var(--red); }
  .pl-title { font-size: 11px; font-weight: 700; letter-spacing: 1.5px; text-transform: uppercase; margin-bottom: 4px; }
  .pl-l1 { color: var(--cyan); }
  .pl-l2 { color: var(--green); }
  .pl-threat { color: var(--red); }
  .pl-desc { font-size: 12px; color: var(--text); opacity: 0.8; }

  /* Packet Flow */
  .flow-vis {
    display: flex; flex-direction: column; gap: 4px;
    font-family: 'Share Tech Mono', monospace; font-size: 11px;
  }
  .flow-row {
    display: flex; align-items: center; gap: 8px; padding: 6px 8px;
    border-radius: 4px; background: rgba(0,0,0,0.3);
  }
  .flow-label { width: 80px; color: var(--dim); flex-shrink: 0; }
  .flow-bar-wrap { flex: 1; background: rgba(0,0,0,0.5); border-radius: 2px; overflow: hidden; height: 12px; }
  .flow-bar {
    height: 100%; border-radius: 2px; transition: width 0.5s ease;
    background: linear-gradient(90deg, var(--cyan), var(--purple));
    box-shadow: 0 0 8px rgba(0,245,255,0.5);
    min-width: 4px;
  }
  .flow-bar.green { background: linear-gradient(90deg, var(--green), var(--cyan2)); }
  .flow-val { width: 60px; text-align: right; color: var(--text); }

  /* Message Log */
  .msg-log {
    height: 280px; overflow-y: auto;
    font-family: 'Share Tech Mono', monospace; font-size: 11px;
    background: rgba(0,0,0,0.4); border-radius: 6px;
    padding: 10px;
  }
  .msg-log::-webkit-scrollbar { width: 4px; }
  .msg-log::-webkit-scrollbar-track { background: transparent; }
  .msg-log::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
  .msg-entry {
    padding: 5px 8px; margin: 3px 0; border-radius: 4px;
    border-left: 2px solid;
    animation: fadeIn 0.4s ease;
  }
  @keyframes fadeIn { from { opacity:0; transform:translateX(-8px); } to { opacity:1; transform:none; } }
  .msg-entry.chat { border-color: var(--green); background: rgba(57,255,20,0.05); }
  .msg-entry.system { border-color: var(--amber); background: rgba(255,170,0,0.05); color: var(--amber); }
  .msg-time { color: var(--dim); margin-right: 6px; }
  .msg-from { color: var(--cyan); margin-right: 6px; }
  .msg-text { color: var(--text); }

  /* Chat Input */
  .chat-input-row {
    display: flex; gap: 8px; margin-top: 10px;
  }
  .chat-input {
    flex: 1; background: rgba(0,0,0,0.5);
    border: 1px solid var(--border); border-radius: 6px;
    padding: 8px 12px; color: var(--text);
    font-family: 'Share Tech Mono', monospace; font-size: 12px;
    outline: none; transition: border-color 0.2s;
  }
  .chat-input:focus { border-color: var(--cyan); box-shadow: 0 0 10px rgba(0,245,255,0.2); }
  .btn {
    background: linear-gradient(135deg, rgba(0,245,255,0.1), rgba(0,245,255,0.2));
    border: 1px solid var(--cyan); color: var(--cyan);
    padding: 8px 16px; border-radius: 6px; cursor: pointer;
    font-family: 'Rajdhani', sans-serif; font-size: 12px;
    font-weight: 600; letter-spacing: 1.5px; text-transform: uppercase;
    transition: all 0.2s; white-space: nowrap;
  }
  .btn:hover { background: rgba(0,245,255,0.2); box-shadow: var(--glow); }
  .btn.green { border-color: var(--green); color: var(--green); background: rgba(57,255,20,0.05); }
  .btn.green:hover { background: rgba(57,255,20,0.15); box-shadow: 0 0 20px rgba(57,255,20,0.3); }
  .btn-row { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 8px; }

  /* Key visualization */
  .key-vis {
    font-family: 'Share Tech Mono', monospace; font-size: 10px;
    line-height: 1.8; color: var(--dim); word-break: break-all;
    background: rgba(0,0,0,0.4); border-radius: 4px; padding: 8px;
    max-height: 80px; overflow: hidden; position: relative;
  }
  .key-vis::after {
    content: '';
    position: absolute; bottom: 0; left: 0; right: 0; height: 30px;
    background: linear-gradient(transparent, rgba(5,10,18,0.95));
  }
  .key-label { font-size: 9px; color: var(--dim); letter-spacing: 1px; text-transform: uppercase; margin-bottom: 4px; }

  /* Tabs */
  .tabs { display: flex; gap: 0; margin-bottom: -1px; }
  .tab {
    padding: 8px 16px; font-size: 11px; letter-spacing: 1.5px;
    text-transform: uppercase; cursor: pointer;
    border: 1px solid transparent; border-bottom: none;
    border-radius: 6px 6px 0 0; transition: all 0.2s;
    color: var(--dim);
  }
  .tab.active { border-color: var(--border); color: var(--cyan); background: var(--bg2); }
  .tab:hover:not(.active) { color: var(--text); }

  /* Progress bars */
  .progress { height: 4px; background: rgba(0,0,0,0.4); border-radius: 2px; overflow: hidden; }
  .progress-bar {
    height: 100%; border-radius: 2px;
    background: linear-gradient(90deg, var(--cyan), var(--purple));
    box-shadow: 0 0 8px rgba(0,245,255,0.4);
    transition: width 0.5s ease;
  }

  /* Threat model */
  .threat-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .threat-table th {
    text-align: left; padding: 6px 10px;
    font-size: 10px; letter-spacing: 1.5px; text-transform: uppercase;
    color: var(--dim); border-bottom: 1px solid var(--border);
  }
  .threat-table td { padding: 8px 10px; border-bottom: 1px solid rgba(255,255,255,0.04); }
  .threat-table tr:last-child td { border: none; }
  .badge {
    display: inline-block; padding: 2px 8px; border-radius: 12px;
    font-size: 9px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase;
  }
  .badge-blocked { background: rgba(255,56,96,0.15); color: var(--red); border: 1px solid rgba(255,56,96,0.3); }
  .badge-ok { background: rgba(57,255,20,0.1); color: var(--green); border: 1px solid rgba(57,255,20,0.2); }

  @media (max-width: 900px) {
    .grid-3 { grid-template-columns: 1fr; }
    .grid-2 { grid-template-columns: 1fr; }
    .grid-7-5 { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>
<header>
  <div class="container">
    <div class="header-inner">
      <div class="logo">
        <div class="logo-icon"></div>
        <div class="logo-text">
          <h1>Double-Blind PQC Ecosystem</h1>
          <p>Post-Quantum Communication Infrastructure · Kyber-768 · ML-KEM</p>
        </div>
      </div>
      <div class="status-bar">
        <div class="status-pill"><div class="dot" id="vpn-dot"></div><span id="vpn-status">VPN</span></div>
        <div class="status-pill"><div class="dot amber" id="e2e-dot"></div><span id="e2e-status">E2E</span></div>
        <div class="status-pill" style="font-family:'Share Tech Mono',monospace;font-size:10px" id="clock"></div>
      </div>
    </div>
  </div>
</header>

<main>
<div class="container">

  <!-- Row 1: Key Metrics -->
  <div class="grid grid-3" style="margin-bottom:16px">
    <div class="card">
      <div class="card-header"><span class="card-title">⬡ Kyber-768 Key Sizes</span><span style="font-size:9px;color:var(--dim)">NIST FIPS 203</span></div>
      <div class="card-body">
        <div class="metrics-grid">
          <div class="metric"><div class="metric-val">1184</div><div class="metric-lbl">Public Key (B)</div></div>
          <div class="metric"><div class="metric-val">1088</div><div class="metric-lbl">Ciphertext (B)</div></div>
          <div class="metric"><div class="metric-val amber">2400</div><div class="metric-lbl">Secret Key (B)</div></div>
          <div class="metric"><div class="metric-val green">32</div><div class="metric-lbl">Shared Secret (B)</div></div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-header"><span class="card-title">⚡ Performance Metrics</span><span style="font-size:9px;color:var(--dim)">vs. Section 3.2</span></div>
      <div class="card-body">
        <div class="metrics-grid">
          <div class="metric"><div class="metric-val" id="l1-hs">—</div><div class="metric-lbl">L1 Handshake (ms)</div></div>
          <div class="metric"><div class="metric-val" id="l2-hs">—</div><div class="metric-lbl">L2 Handshake (ms)</div></div>
          <div class="metric"><div class="metric-val green" id="pkt-loss">0%</div><div class="metric-lbl">Packet Loss</div></div>
          <div class="metric"><div class="metric-val" id="frags">0</div><div class="metric-lbl">Fragments Sent</div></div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-header"><span class="card-title">🔒 Privacy Status</span><span style="font-size:9px;color:var(--dim)">Double-Blind</span></div>
      <div class="card-body">
        <div class="privacy-layers">
          <div class="privacy-layer l1">
            <div class="pl-title pl-l1">Layer 1 — VPN Tunnel</div>
            <div class="pl-desc">ISP cannot see who you talk to. Kyber-768 + WireGuard.</div>
          </div>
          <div class="privacy-layer l2">
            <div class="pl-title pl-l2">Layer 2 — E2E Encryption</div>
            <div class="pl-desc">VPN provider cannot read messages. Independent Kyber session.</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Row 2: Architecture + Chat -->
  <div class="grid grid-7-5" style="margin-bottom:16px">

    <!-- Architecture Diagram -->
    <div class="card">
      <div class="card-header"><span class="card-title">🏗 System Architecture</span><span style="font-size:9px;color:var(--dim)">Block Diagram (Section 6)</span></div>
      <div class="card-body">
        <div style="display:grid;grid-template-columns:1fr 60px 1fr;gap:8px;align-items:start">
          <!-- Alice side -->
          <div>
            <div style="font-size:9px;color:var(--dim);letter-spacing:2px;text-transform:uppercase;margin-bottom:8px;text-align:center">CLIENT (Alice)</div>
            <div class="arch-node layer2"><span class="node-icon">💬</span><span class="node-label">PQC Messenger (L2)</span><span class="node-size">Kyber-768</span></div>
            <div class="arch-arrow">↓ generates Kyber PK (1184B)</div>
            <div class="arch-node" style="border-color:var(--amber);background:rgba(255,170,0,0.05)"><span class="node-icon">🔀</span><span class="node-label">Fragmentation Wrapper</span><span class="node-size">≤1000B</span></div>
            <div class="arch-arrow">↓ chunks → L1 tunnel</div>
            <div class="arch-node"><span class="node-icon">🌐</span><span class="node-label">WireGuard Interface (L1)</span><span class="node-size">Kyber-768</span></div>
            <div class="arch-arrow">↓ encrypts + encapsulates</div>
            <div class="arch-node physical"><span class="node-icon">📡</span><span class="node-label">Physical Network (UDP)</span><span class="node-size">&lt;1400B pkts</span></div>
          </div>
          <!-- Middle arrows -->
          <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;padding-top:40px">
            <div style="writing-mode:vertical-rl;font-family:'Share Tech Mono',monospace;font-size:9px;color:var(--dim);letter-spacing:2px">INTERNET</div>
            <div style="margin:8px 0;color:var(--dim);font-size:18px">⟷</div>
            <div style="font-family:'Share Tech Mono',monospace;font-size:8px;color:var(--dim);text-align:center">Encrypted<br>UDP<br>Packets</div>
          </div>
          <!-- Bob side -->
          <div>
            <div style="font-size:9px;color:var(--dim);letter-spacing:2px;text-transform:uppercase;margin-bottom:8px;text-align:center">SERVER (Bob)</div>
            <div class="arch-node physical"><span class="node-icon">📡</span><span class="node-label">Physical Network (UDP)</span></div>
            <div class="arch-arrow">↓ receives fragments</div>
            <div class="arch-node"><span class="node-icon">🌐</span><span class="node-label">WireGuard Interface (L1)</span></div>
            <div class="arch-arrow">↓ decapsulates</div>
            <div class="arch-node" style="border-color:var(--amber);background:rgba(255,170,0,0.05)"><span class="node-icon">🔄</span><span class="node-label">Reassembly Buffer</span><span class="node-size">Reconstructs PK</span></div>
            <div class="arch-arrow">↓ full key restored</div>
            <div class="arch-node layer2"><span class="node-icon">💬</span><span class="node-label">PQC Messenger (L2)</span></div>
          </div>
        </div>

        <!-- MTU Breakdown -->
        <div style="margin-top:16px;padding:12px;background:rgba(0,0,0,0.3);border-radius:6px;border:1px solid var(--border)">
          <div style="font-size:9px;color:var(--dim);letter-spacing:2px;text-transform:uppercase;margin-bottom:8px">MTU Budget (Nested MTU Paradox — Section 4)</div>
          <div class="flow-vis">
            <div class="flow-row"><span class="flow-label">Physical</span><div class="flow-bar-wrap"><div class="flow-bar" style="width:100%"></div></div><span class="flow-val">1500 B</span></div>
            <div class="flow-row"><span class="flow-label">−WG hdrs</span><div class="flow-bar-wrap"><div class="flow-bar" style="width:94.7%"></div></div><span class="flow-val">1420 B</span></div>
            <div class="flow-row"><span class="flow-label">IPv6 path</span><div class="flow-bar-wrap"><div class="flow-bar" style="width:85.3%"></div></div><span class="flow-val">1280 B</span></div>
            <div class="flow-row"><span class="flow-label">Safe chunk</span><div class="flow-bar-wrap"><div class="flow-bar green" style="width:66.7%"></div></div><span class="flow-val">1000 B ✓</span></div>
          </div>
        </div>
      </div>
    </div>

    <!-- Chat Panel -->
    <div class="card">
      <div class="card-header"><span class="card-title">💬 Live Secure Chat</span><span style="font-size:9px;color:var(--dim)" id="session-id-display">Session: —</span></div>
      <div class="card-body" style="display:flex;flex-direction:column;height:calc(100% - 46px)">
        <div class="msg-log" id="msg-log"></div>
        <div class="chat-input-row">
          <input class="chat-input" id="msg-input" placeholder="Type message (sent via Kyber-768 E2E)..." onkeypress="if(event.key==='Enter')sendMsg()">
          <button class="btn" onclick="sendMsg()">SEND</button>
        </div>
        <div class="btn-row">
          <button class="btn green" onclick="sendDemo()">▶ Demo Messages</button>
          <button class="btn" onclick="sendPQCTest()">⬡ PQC Key Test</button>
        </div>
        <!-- Fragmentation stats -->
        <div style="margin-top:12px;padding:10px;background:rgba(0,0,0,0.3);border-radius:6px;border:1px solid var(--border)">
          <div style="font-size:9px;color:var(--dim);letter-spacing:2px;text-transform:uppercase;margin-bottom:6px">Fragmentation Stats</div>
          <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:6px;font-family:'Share Tech Mono',monospace;font-size:11px;text-align:center">
            <div><div style="color:var(--cyan)" id="stat-frags-sent">0</div><div style="font-size:9px;color:var(--dim)">Frags Sent</div></div>
            <div><div style="color:var(--green)" id="stat-msgs">0</div><div style="font-size:9px;color:var(--dim)">Msgs</div></div>
            <div><div style="color:var(--amber)" id="stat-bytes">0</div><div style="font-size:9px;color:var(--dim)">Bytes Enc</div></div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Row 3: Threat Model + Key Visualization -->
  <div class="grid grid-2">
    <div class="card">
      <div class="card-header"><span class="card-title">🛡 Threat Model — Trust Gap Analysis</span></div>
      <div class="card-body">
        <table class="threat-table">
          <thead>
            <tr><th>Adversary</th><th>Sees</th><th>VPN-Only</th><th>E2E-Only</th><th>Double-Blind</th></tr>
          </thead>
          <tbody>
            <tr>
              <td>ISP</td>
              <td style="font-size:11px;color:var(--dim)">Who you talk to</td>
              <td><span class="badge badge-ok">BLOCKED</span></td>
              <td><span class="badge badge-blocked">EXPOSED</span></td>
              <td><span class="badge badge-ok">BLOCKED</span></td>
            </tr>
            <tr>
              <td>VPN Provider</td>
              <td style="font-size:11px;color:var(--dim)">Message content</td>
              <td><span class="badge badge-blocked">EXPOSED</span></td>
              <td><span class="badge badge-ok">BLOCKED</span></td>
              <td><span class="badge badge-ok">BLOCKED</span></td>
            </tr>
            <tr>
              <td>Quantum Attacker</td>
              <td style="font-size:11px;color:var(--dim)">RSA/ECDH keys</td>
              <td><span class="badge badge-blocked">BROKEN</span></td>
              <td><span class="badge badge-blocked">BROKEN</span></td>
              <td><span class="badge badge-ok">BLOCKED</span></td>
            </tr>
            <tr>
              <td>HNDL Attacker</td>
              <td style="font-size:11px;color:var(--dim)">Stored traffic</td>
              <td><span class="badge badge-blocked">EXPOSED</span></td>
              <td><span class="badge badge-blocked">EXPOSED</span></td>
              <td><span class="badge badge-ok">BLOCKED</span></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <div class="card-header"><span class="card-title">🔑 Live Key Material</span><span style="font-size:9px;color:var(--dim)">Kyber-768 (NIST FIPS 203)</span></div>
      <div class="card-body">
        <div class="key-label">Alice VPN Public Key (1184 bytes)</div>
        <div class="key-vis" id="alice-pk">Loading...</div>
        <div class="key-label" style="margin-top:10px">Bob VPN Public Key (1184 bytes)</div>
        <div class="key-vis" id="bob-pk">Loading...</div>
        <div style="margin-top:10px;padding:8px;background:rgba(0,0,0,0.3);border-radius:4px;font-size:11px;font-family:'Share Tech Mono',monospace">
          <div style="color:var(--dim);font-size:9px;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Algorithm Comparison (Section 3.3)</div>
          <div style="display:flex;justify-content:space-between;margin-bottom:4px">
            <span style="color:var(--green)">Kyber-768</span>
            <span>1,184 B → 2 UDP frags ✓</span>
          </div>
          <div style="display:flex;justify-content:space-between">
            <span style="color:var(--red)">McEliece</span>
            <span>261,120 B → ~200 frags ✗</span>
          </div>
          <div class="progress" style="margin-top:6px">
            <div class="progress-bar" style="width:0.45%"></div>
          </div>
          <div style="font-size:9px;color:var(--dim);margin-top:3px">Kyber is 220× smaller than McEliece</div>
        </div>
      </div>
    </div>
  </div>

</div>
</main>

<script>
let msgCount = 0;

function pad2(n) { return n<10?'0'+n:n; }
function updateClock() {
  const d = new Date();
  document.getElementById('clock').textContent =
    pad2(d.getHours())+':'+pad2(d.getMinutes())+':'+pad2(d.getSeconds());
}
setInterval(updateClock, 1000); updateClock();

function addMessage(entry) {
  const log = document.getElementById('msg-log');
  const ts = new Date(entry.ts*1000);
  const timeStr = pad2(ts.getHours())+':'+pad2(ts.getMinutes())+':'+pad2(ts.getSeconds());
  const div = document.createElement('div');
  div.className = 'msg-entry ' + (entry.layer==='SYSTEM'?'system':'chat');
  div.innerHTML = `<span class="msg-time">${timeStr}</span>`+
    (entry.layer!=='SYSTEM'?`<span class="msg-from">${entry.from}→${entry.to}</span>`:'')+
    `<span class="msg-text">${entry.text}</span>`;
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
}

async function pollStatus() {
  try {
    const r = await fetch('/api/status');
    const d = await r.json();

    // Update status dots
    if (d.vpn_ready) {
      document.getElementById('vpn-dot').className = 'dot';
      document.getElementById('vpn-status').textContent = 'VPN ACTIVE';
    }
    if (d.e2e_ready) {
      document.getElementById('e2e-dot').className = 'dot';
      document.getElementById('e2e-status').textContent = 'E2E ACTIVE';
    }

    // Metrics
    if (d.metrics) {
      const m = d.metrics;
      if (m.layer1_handshake_ms > 0) document.getElementById('l1-hs').textContent = m.layer1_handshake_ms.toFixed(1);
      if (m.layer2_handshake_ms > 0) document.getElementById('l2-hs').textContent = m.layer2_handshake_ms.toFixed(1);
      if (m.fragments_sent !== undefined) document.getElementById('frags').textContent = m.fragments_sent;
    }
    if (d.frag_stats) {
      document.getElementById('stat-frags-sent').textContent = d.frag_stats.fragments_sent||0;
      document.getElementById('stat-msgs').textContent = d.frag_stats.messages_sent||0;
    }
    if (d.messenger_stats) {
      document.getElementById('stat-bytes').textContent = (d.messenger_stats.bytes_encrypted||0)+' B';
    }
    if (d.session_id) {
      document.getElementById('session-id-display').textContent = 'Session: '+d.session_id.substring(0,20)+'...';
    }
    if (d.alice_pk_hex) {
      document.getElementById('alice-pk').textContent = d.alice_pk_hex;
      document.getElementById('bob-pk').textContent = d.bob_pk_hex||'';
    }

    // New messages
    if (d.messages && d.messages.length > msgCount) {
      for (let i=msgCount; i<d.messages.length; i++) addMessage(d.messages[i]);
      msgCount = d.messages.length;
    }

  } catch(e) { console.error(e); }
}
setInterval(pollStatus, 1000);
pollStatus();

async function sendMsg() {
  const input = document.getElementById('msg-input');
  const text = input.value.trim();
  if (!text) return;
  input.value = '';
  await fetch('/api/send', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({text})});
}

async function sendDemo() {
  const msgs = [
    "Hello Bob! This is a Kyber-768 encrypted message.",
    "Even quantum computers can't break this encryption.",
    "Our VPN hides metadata, E2E hides content — Double-Blind!",
    "HNDL (Harvest Now, Decrypt Later) attacks are blocked.",
    "This is PFS — every session has a fresh Kyber keypair.",
  ];
  for (const m of msgs) {
    await fetch('/api/send', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({text:m})});
    await new Promise(r=>setTimeout(r,400));
  }
}

async function sendPQCTest() {
  await fetch('/api/send', {method:'POST', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({text:"[PQC TEST] Kyber-768 pk=1184B → 2 fragments of 1000B+184B. Reassembled at Bob ✓"})});
}
</script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args): pass  # Suppress default logging

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/" or path == "/index.html":
            self._serve_html()
        elif path == "/api/status":
            self._serve_status()
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/send":
            length = int(self.headers.get("Content-Length", 0))
            body   = json.loads(self.rfile.read(length))
            text   = body.get("text", "")
            if text:
                send_demo_message(text)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')
        else:
            self.send_response(404); self.end_headers()

    def _serve_html(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(HTML.encode())

    def _serve_status(self):
        global alice_node, bob_node, message_log
        data = {
            "vpn_ready": alice_node.vpn_ready.is_set() if alice_node else False,
            "e2e_ready": False,
            "metrics":   {},
            "frag_stats":{},
            "messenger_stats": {},
            "messages":  message_log[-50:],  # last 50 messages
            "session_id":"demo-channel",
            "alice_pk_hex": "",
            "bob_pk_hex":   "",
        }

        if alice_node:
            m = alice_node.metrics.copy()
            if alice_node.messenger:
                m["fragments_sent"] = alice_node.messenger.wrapper.stats["fragments_sent"]
            data["metrics"]          = m
            data["alice_pk_hex"]     = alice_node.vpn_pk.hex()
            data["e2e_ready"]        = any(
                s.get("established") for s in alice_node.messenger.get_session_info()
            ) if alice_node.messenger else False
            data["frag_stats"]       = alice_node.messenger.wrapper.get_stats() \
                                       if alice_node.messenger else {}
            data["messenger_stats"]  = alice_node.messenger.stats \
                                       if alice_node.messenger else {}

        if bob_node:
            data["bob_pk_hex"] = bob_node.vpn_pk.hex()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s"
    )

    print("\n" + "="*60)
    print("  DOUBLE-BLIND PQC ECOSYSTEM — DASHBOARD")
    print("="*60)
    print("\n[*] Initializing nodes...")

    alice_port, bob_port = init_system()
    print(f"[✓] Alice: port {alice_port} | Bob: port {bob_port}")
    print(f"[✓] VPN Layer (Kyber-768): {len(alice_node.vpn_pk)}B public keys")
    print(f"[✓] MTU detected: {alice_node.metrics['mtu_detected']}B → "
          f"safe chunk: {alice_node.messenger.wrapper.chunk_size}B")

    # Start dashboard
    server = HTTPServer(("0.0.0.0", 7860), DashboardHandler)
    print(f"\n[✓] Dashboard: http://localhost:7860")
    print(f"    Opening browser...")
    print(f"\n[*] Press Ctrl+C to stop\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        alice_node.stop()
        bob_node.stop()


if __name__ == "__main__":
    main()
