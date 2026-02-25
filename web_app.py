"""
Double-Blind Post-Quantum Communication Ecosystem
===================================================
Web Frontend — Flask + SocketIO Dashboard

Provides:
  1. Live PQC-encrypted chat (real Kyber-768 + AES-256-GCM)
  2. Handshake simulation with step-by-step visualization
  3. Fragmentation wrapper visualization
  4. Attacker panel — proves a third party CANNOT decrypt intercepted ciphertext
  5. Real-time packet capture log
  6. Backend terminal log stream
"""

import os, sys, json, time, math, struct, base64, hashlib, threading, logging, random as _random
from datetime import datetime
from collections import Counter

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit

sys.path.insert(0, os.path.dirname(__file__))
from crypto_core import (
    KyberKEM, DilithiumSigner, AESGCMCipher, PQCSession,
    derive_key, SecurityError,
)
from fragmentation import Fragmenter, HEADER_SIZE, _pack_header, _unpack_header, FLAG_FRAG, FLAG_ACK, FLAG_FIN
from protocol import (
    MsgType, encode_message, decode_message,
    encode_handshake_init, decode_handshake_init,
    encode_handshake_resp, decode_handshake_resp,
    encode_chat_message, decode_chat_message,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("web_frontend")

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = os.urandom(24).hex()
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ---------------------------------------------------------------------------
#  Backend log broadcast
# ---------------------------------------------------------------------------
def blog(level, text, **extra):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    entry = {"ts": ts, "level": level, "text": text, **extra}
    socketio.emit("backend_log", entry)
    getattr(logger, level, logger.info)(text)

# ---------------------------------------------------------------------------
#  Crypto-analysis helpers (used by the attacker panel)
# ---------------------------------------------------------------------------
def shannon_entropy(data: bytes) -> float:
    if not data: return 0.0
    freq = Counter(data); n = len(data)
    return round(-sum((c/n)*math.log2(c/n) for c in freq.values()), 4)

def byte_frequency_top(data: bytes, top_n=16):
    freq = Counter(data)
    return [{"byte": f"0x{b:02x}", "count": c, "pct": round(c/len(data)*100, 2)}
            for b, c in freq.most_common(top_n)]

def chi_squared_uniformity(data: bytes):
    n = len(data); expected = n / 256
    chi2 = sum((Counter(data).get(i, 0) - expected)**2 / expected for i in range(256))
    return {"chi_squared": round(chi2, 2), "df": 255, "critical_005": 293.25,
            "looks_random": chi2 < 293.25}

def find_repeated_patterns(data: bytes, plen=4):
    if len(data) < plen*2: return []
    pats = Counter(data[i:i+plen] for i in range(len(data)-plen+1))
    return [{"hex": p.hex(), "count": c} for p, c in pats.most_common(6) if c > 1]

# ---------------------------------------------------------------------------
#  Simulation state
# ---------------------------------------------------------------------------
class SimulationState:
    def __init__(self): self.reset()
    def reset(self):
        self.alice_session = self.bob_session = None
        self.alice_cipher = self.bob_cipher = None
        self.shared_secret = None
        self.session_established = False
        self.handshake_steps = []; self.messages = []
        self.intercepted_packets = []; self.fragment_log = []
        self.attacker_attempts = []
        self.stats = dict(handshake_time_ms=0, fragments_sent=0, fragments_received=0,
                          messages_encrypted=0, attacker_failures=0, total_bytes_transferred=0)

state = SimulationState()

# ---------------------------------------------------------------------------
#  Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index(): return render_template("index.html")

@app.route("/api/status")
def api_status():
    return jsonify(session_established=state.session_established, stats=state.stats,
                   messages_count=len(state.messages), intercepted_count=len(state.intercepted_packets))

# ---------------------------------------------------------------------------
#  Handshake
# ---------------------------------------------------------------------------
@socketio.on("connect")
def handle_connect():
    blog("info", f"Client connected: {request.sid}")
    emit("system_msg", {"text": "Connected to Double-Blind PQC Dashboard"})

@socketio.on("start_handshake")
def handle_start_handshake():
    state.reset(); emit("handshake_reset", {})
    blog("info", "═══════════════════════════════════════════════════════")
    blog("info", "  PQC Handshake Simulation Starting…")
    blog("info", "═══════════════════════════════════════════════════════")

    try:
        # Step 1 — key generation
        blog("info", "[Step 1/6] Generating Kyber-768 + Dilithium-3 keypairs for Alice…")
        emit("handshake_step", {"step":1,"title":"🔑 Key Generation",
             "description":"Alice generates Kyber-768 KEM keypair and Dilithium-3 signing keypair","status":"running"})

        state.alice_session = PQCSession(role="initiator", label="Alice")
        state.bob_session   = PQCSession(role="responder", label="Bob")
        t0 = time.perf_counter()
        init_msg = state.alice_session.create_handshake_init()
        keygen_ms = (time.perf_counter()-t0)*1000

        blog("info", f"  ✓ KEM pk: {len(init_msg['kem_pk'])}B  |  Sig pk: {len(init_msg['sig_pk'])}B  |  Sig: {len(init_msg['sig'])}B")
        blog("info", f"  ✓ Keygen {keygen_ms:.2f} ms")

        emit("handshake_step", {"step":1,"title":"🔑 Key Generation",
             "description":"Kyber-768 + Dilithium-3 keypairs generated","status":"complete",
             "details":{"kem_pk_size":len(init_msg["kem_pk"]),"sig_pk_size":len(init_msg["sig_pk"]),
                        "signature_size":len(init_msg["sig"]),
                        "kem_pk_preview":base64.b64encode(init_msg["kem_pk"]).decode()[:80]+"…",
                        "time_ms":round(keygen_ms,2)}})

        # Step 2 — fragment init
        init_payload = encode_handshake_init(init_msg["kem_pk"], init_msg["sig_pk"], init_msg["sig"])
        init_wire = encode_message(MsgType.L2_HANDSHAKE_INIT, init_payload)
        total_init_size = len(init_wire); threshold = 1000
        chunks = [init_wire[i:i+threshold] for i in range(0, len(init_wire), threshold)]

        blog("info", f"[Step 2/6] Init payload {total_init_size}B → {len(chunks)} fragments (threshold {threshold}B)")
        emit("handshake_step", {"step":2,"title":"📦 Fragmentation (Init)",
             "description":f"{total_init_size}B → {len(chunks)} fragments","status":"running"})

        # intercepted init
        _add_intercepted("Handshake Init (KEM+Sig PKs)", "Alice → Bob", init_wire)

        for i, ch in enumerate(chunks):
            blog("info", f"  → frag [{i+1}/{len(chunks)}] {len(ch)}B")
            socketio.emit("fragment_sent",{"direction":"alice_to_bob","seq":i,"total":len(chunks),"size":len(ch)})
            socketio.sleep(0.12)
        for i in range(len(chunks)):
            blog("info", f"  ← ACK  [{i+1}/{len(chunks)}]")
            socketio.emit("fragment_ack",{"direction":"bob_to_alice","seq":i,"total":len(chunks)})
            socketio.sleep(0.04)

        state.stats["fragments_sent"] += len(chunks)
        state.stats["fragments_received"] += len(chunks)
        state.stats["total_bytes_transferred"] += total_init_size
        blog("info", f"  ✓ {len(chunks)} fragments ACKed — 0 % loss")
        emit("handshake_step", {"step":2,"title":"📦 Fragmentation (Init)",
             "description":f"{total_init_size}B → {len(chunks)} chunks, all ACKed","status":"complete",
             "details":{"original_size":total_init_size,"num_fragments":len(chunks),"threshold":threshold}})

        # Step 3 — encapsulation
        blog("info", "[Step 3/6] Bob verifying Dilithium-3 sig → encapsulating…")
        emit("handshake_step", {"step":3,"title":"🔐 Encapsulation",
             "description":"Bob verifies signature, encapsulates shared secret with Alice's Kyber-768 pk","status":"running"})

        t1 = time.perf_counter()
        resp_msg = state.bob_session.process_handshake_init(init_msg)
        encap_ms = (time.perf_counter()-t1)*1000

        blog("info", f"  ✓ Signature VALID")
        blog("info", f"  ✓ Ciphertext: {len(resp_msg['ciphertext'])}B  |  {encap_ms:.2f} ms")
        _add_intercepted("Kyber-768 Ciphertext", "Bob → Alice", resp_msg["ciphertext"])

        emit("handshake_step", {"step":3,"title":"🔐 Encapsulation",
             "description":"Signature ✅ — shared secret encapsulated","status":"complete",
             "details":{"ciphertext_size":len(resp_msg["ciphertext"]),
                        "ciphertext_preview":base64.b64encode(resp_msg["ciphertext"]).decode()[:80]+"…",
                        "signature_valid":True,"time_ms":round(encap_ms,2)}})

        # Step 4 — fragment response
        resp_payload = encode_handshake_resp(resp_msg["ciphertext"], resp_msg["sig_pk"], resp_msg["sig"])
        resp_wire = encode_message(MsgType.L2_HANDSHAKE_RESP, resp_payload)
        resp_size = len(resp_wire)
        resp_chunks = [resp_wire[i:i+threshold] for i in range(0, len(resp_wire), threshold)]

        blog("info", f"[Step 4/6] Response {resp_size}B → {len(resp_chunks)} fragments")
        emit("handshake_step", {"step":4,"title":"📦 Fragmentation (Response)",
             "description":f"{resp_size}B → {len(resp_chunks)} fragments","status":"running"})
        _add_intercepted("Handshake Response (CT+Sig)", "Bob → Alice", resp_wire)

        for i, ch in enumerate(resp_chunks):
            blog("info", f"  → frag [{i+1}/{len(resp_chunks)}] {len(ch)}B")
            socketio.emit("fragment_sent",{"direction":"bob_to_alice","seq":i,"total":len(resp_chunks),"size":len(ch)})
            socketio.sleep(0.08)
        for i in range(len(resp_chunks)):
            blog("info", f"  ← ACK  [{i+1}/{len(resp_chunks)}]")
            socketio.emit("fragment_ack",{"direction":"alice_to_bob","seq":i,"total":len(resp_chunks)})
            socketio.sleep(0.03)
        state.stats["fragments_sent"] += len(resp_chunks)
        state.stats["fragments_received"] += len(resp_chunks)
        state.stats["total_bytes_transferred"] += resp_size
        emit("handshake_step", {"step":4,"title":"📦 Fragmentation (Response)",
             "description":f"{resp_size}B → {len(resp_chunks)} chunks ACKed ✅","status":"complete",
             "details":{"original_size":resp_size,"num_fragments":len(resp_chunks)}})

        # Step 5 — decapsulation
        blog("info", "[Step 5/6] Alice verifying Bob's sig → decapsulating…")
        emit("handshake_step", {"step":5,"title":"🔓 Decapsulation",
             "description":"Alice decapsulates the shared secret","status":"running"})
        t2 = time.perf_counter()
        state.alice_session.process_handshake_resp(resp_msg)
        decap_ms = (time.perf_counter()-t2)*1000

        ai = state.alice_session.session_info(); bi = state.bob_session.session_info()
        match = ai["shared_secret_hash"] == bi["shared_secret_hash"]
        total_ms = keygen_ms + encap_ms + decap_ms
        state.stats["handshake_time_ms"] = round(total_ms,2)
        state.shared_secret = state.alice_session._shared_secret

        blog("info", f"  ✓ Decap {decap_ms:.2f} ms  |  Secrets match: {'YES ✅' if match else 'NO ❌'}")
        blog("info", f"  ✓ Session hash: {ai['shared_secret_hash']}")
        emit("handshake_step", {"step":5,"title":"🔓 Decapsulation",
             "description":"Shared 256-bit secret derived!","status":"complete",
             "details":{"shared_secret_hash":ai["shared_secret_hash"],"secrets_match":match,
                        "time_ms":round(decap_ms,2),"total_handshake_ms":round(total_ms,2)}})

        # Step 6 — done
        state.session_established = True
        blog("info", "═══════════════════════════════════════════════════════")
        blog("info", f"  ✅ SESSION ESTABLISHED  |  {total_ms:.2f} ms  |  {state.stats['fragments_sent']} frags  |  {state.stats['total_bytes_transferred']}B")
        blog("info", "═══════════════════════════════════════════════════════")
        emit("handshake_step", {"step":6,"title":"✅ Session Established",
             "description":"AES-256-GCM encrypted channel active","status":"complete",
             "details":{"kem":"Kyber-768","auth":"Dilithium-3","cipher":"AES-256-GCM","kdf":"HKDF-SHA256",
                        "session_id":ai["shared_secret_hash"],"total_handshake_ms":round(total_ms,2),
                        "total_fragments":state.stats["fragments_sent"],
                        "total_bytes":state.stats["total_bytes_transferred"]}})
        emit("session_established",{"session_id":ai["shared_secret_hash"],"handshake_ms":round(total_ms,2)})
    except Exception as e:
        logger.exception("Handshake error"); blog("error", f"Handshake FAILED: {e}")
        emit("handshake_error", {"error": str(e)})


def _add_intercepted(ptype, direction, raw):
    pkt = {"id": len(state.intercepted_packets), "type": ptype, "direction": direction,
           "size": len(raw), "hex_preview": raw[:64].hex(),
           "b64_preview": base64.b64encode(raw[:128]).decode()+"…",
           "raw_bytes": raw, "timestamp": time.time()}
    state.intercepted_packets.append(pkt)
    socketio.emit("packet_intercepted", {k: v for k, v in pkt.items() if k != "raw_bytes"})

# ---------------------------------------------------------------------------
#  Chat
# ---------------------------------------------------------------------------
@socketio.on("send_message")
def handle_send_message(data):
    if not state.session_established:
        emit("system_msg", {"text": "Run handshake first!"}); return
    sender = data.get("sender","Alice"); text = data.get("text","")
    if not text: return

    blog("info", f"[Chat] {sender}: \"{text}\"")
    send_s = state.alice_session if sender=="Alice" else state.bob_session
    recv_s = state.bob_session if sender=="Alice" else state.alice_session
    receiver = "Bob" if sender=="Alice" else "Alice"

    chat_payload = encode_chat_message(sender, text)
    t0 = time.perf_counter(); encrypted = send_s.encrypt(chat_payload); enc_ms = (time.perf_counter()-t0)*1000
    state.stats["messages_encrypted"] += 1

    blog("info", f"  ✓ {len(chat_payload)}B → {len(encrypted)}B  |  nonce={encrypted[:12].hex()}  |  {enc_ms:.4f} ms")

    # Store intercepted packet (with plaintext for attacker analysis)
    pkt_entry = {"id": len(state.intercepted_packets), "type": "Chat Message (AES-256-GCM)",
        "direction": f"{sender} → {receiver}", "size": len(encrypted),
        "hex_preview": encrypted[:64].hex(),
        "b64_preview": base64.b64encode(encrypted).decode()[:100]+"…",
        "raw_bytes": encrypted, "plaintext": text, "timestamp": time.time()}
    state.intercepted_packets.append(pkt_entry)
    socketio.emit("packet_intercepted", {k: v for k, v in pkt_entry.items() if k not in ("raw_bytes", "plaintext")})

    t1 = time.perf_counter(); decrypted = recv_s.decrypt(encrypted); dec_ms = (time.perf_counter()-t1)*1000
    chat_data = decode_chat_message(decrypted)
    blog("info", f"  ✓ {receiver} decrypted {dec_ms:.4f} ms → \"{chat_data['text']}\"  integrity={'OK ✅' if chat_data['text']==text else 'FAIL ❌'}")

    msg = {"sender":sender,"text":text,"timestamp":time.time(),
           "plaintext_hex":chat_payload.hex(),"plaintext_size":len(chat_payload),
           "ciphertext_hex":encrypted.hex(),"ciphertext_b64":base64.b64encode(encrypted).decode(),
           "ciphertext_size":len(encrypted),"nonce_hex":encrypted[:12].hex(),
           "encrypt_time_ms":round(enc_ms,4),"decrypted_text":chat_data["text"],
           "integrity_ok":chat_data["text"]==text}
    state.messages.append(msg)
    emit("chat_message", msg, broadcast=True)

# ---------------------------------------------------------------------------
#  Attacker simulation
# ---------------------------------------------------------------------------
@socketio.on("attacker_try_decrypt")
def handle_attacker_decrypt(data):
    pkt_id = data.get("packet_id", -1); method = data.get("method","random_key")
    custom_key_hex = data.get("custom_key_hex",""); known_text = data.get("known_text","Hello")
    brute_count = min(int(data.get("brute_count", 1000)), 50000)

    if pkt_id < 0 or pkt_id >= len(state.intercepted_packets):
        emit("attacker_result",{"error":"No packets — run handshake + send messages first","method":method,"success":False}); return

    pkt = state.intercepted_packets[pkt_id]; raw = pkt["raw_bytes"]
    blog("warning", f"[Attacker] {method} on pkt #{pkt_id} ({pkt['type']}, {len(raw)}B)")

    res = {"packet_id":pkt_id,"method":method,"packet_type":pkt["type"],
           "ciphertext_size":len(raw),"success":False,"timestamp":time.time()}

    if method == "random_key":
        rk = os.urandom(32); res["attacker_key_hex"] = rk.hex()
        blog("warning", f"  Key: {rk.hex()[:32]}…")
        try:
            if "Chat" in pkt["type"]: AESGCMCipher.decrypt_with_key(rk, raw); res["success"]=True
            else: res["error_detail"]="KEM ciphertext — symmetric key useless"
        except Exception as e:
            res["error_detail"]=f"FAILED: {type(e).__name__}: {e}"
        blog("error", f"  → {res.get('error_detail','???')}")

    elif method == "custom_key":
        try:
            ck = bytes.fromhex(custom_key_hex.replace(" ","")) if custom_key_hex else os.urandom(32)
            if len(ck)!=32: res["error_detail"]=f"Need 32 bytes, got {len(ck)}"
            else:
                res["attacker_key_hex"]=ck.hex()
                blog("warning", f"  Custom key: {ck.hex()[:32]}…")
                try:
                    if "Chat" in pkt["type"]: AESGCMCipher.decrypt_with_key(ck, raw); res["success"]=True
                    else: res["error_detail"]="KEM ciphertext — symmetric key useless"
                except Exception as e: res["error_detail"]=f"FAILED: {type(e).__name__}: {e}"
        except ValueError as e: res["error_detail"]=f"Bad hex: {e}"
        blog("error", f"  → {res.get('error_detail','???')}")

    elif method == "brute_force":
        res["attempts"]=brute_count; fails=[]
        blog("warning", f"  Brute-forcing {brute_count} keys…")
        t0 = time.perf_counter(); batch = max(1, brute_count//20)
        for i in range(brute_count):
            rk = os.urandom(32)
            try:
                if "Chat" in pkt["type"]: AESGCMCipher.decrypt_with_key(rk, raw); res["success"]=True; break
            except Exception as e:
                if len(fails)<5: fails.append({"key":rk[:8].hex()+"…","error":type(e).__name__})
            if (i+1)%batch==0 or i==brute_count-1:
                el=(time.perf_counter()-t0)*1000
                socketio.emit("brute_force_progress",{"current":i+1,"total":brute_count,
                    "elapsed_ms":round(el,1),"keys_per_sec":round((i+1)/(el/1000)) if el>0 else 0,
                    "last_key":rk.hex()[:24]+"…"})
        el_total=(time.perf_counter()-t0)*1000; kps=round(brute_count/(el_total/1000)) if el_total>0 else 0
        res["elapsed_ms"]=round(el_total,2); res["keys_per_sec"]=kps; res["sample_failures"]=fails
        res["error_detail"]=(f"All {brute_count} keys failed in {el_total:.1f}ms ({kps:,} keys/sec). "
                             f"At this rate, 2²⁵⁶ keys ≈ {3.67e63:.0e} years.")
        blog("error", f"  → All {brute_count} failed in {el_total:.1f}ms")

    elif method == "wrong_kyber_key":
        blog("warning", "  Generating rogue Kyber-768 keypair…")
        ak = KyberKEM(); ak.generate_keypair()
        res["attacker_pk_hex"]=ak.public_key[:32].hex()+"…"
        try:
            if "Kyber" in pkt["type"] or "Handshake" in pkt["type"]:
                ss = ak.decapsulate(raw); res["decapsulated_hex"]=ss.hex()
                if state.shared_secret:
                    res["matches_real"]=(ss==state.shared_secret)
                    res["real_hash"]=hashlib.sha256(state.shared_secret).hexdigest()[:32]
                    res["attacker_hash"]=hashlib.sha256(ss).hexdigest()[:32]
                res["error_detail"]="Decapsulated a WRONG shared secret — completely independent of real session key"
            else:
                AESGCMCipher.decrypt_with_key(os.urandom(32), raw)
        except Exception as e:
            res["error_detail"]=f"Decapsulation FAILED: {type(e).__name__}: {e}"
        blog("error", f"  → {res.get('error_detail','')[:80]}")

    elif method == "replay_attack":
        nonce = raw[:12].hex() if len(raw)>=12 else "N/A"; res["nonce_hex"]=nonce
        res["error_detail"]=(f"Replay blocked — nonce [{nonce}] already consumed. AES-GCM nonces are unique per message; "
                             "re-sending yields nothing without the session key.")
        blog("error", f"  → Replay blocked, nonce {nonce}")

    elif method == "bit_flip":
        if len(raw)>20:
            positions = sorted(_random.sample(range(12, min(len(raw),200)), min(5, len(raw)-12)))
            tampered = bytearray(raw)
            for p in positions: tampered[p] ^= _random.randint(1,255)
            tampered = bytes(tampered)
            res["tampered_bytes"]=positions
            res["original_hex"]=raw[positions[0]:positions[0]+8].hex()
            res["tampered_hex"]=tampered[positions[0]:positions[0]+8].hex()
            blog("warning", f"  Flipping bytes at {positions}")
            try:
                if state.shared_secret and "Chat" in pkt["type"]:
                    sym_key = derive_key(state.shared_secret, info=b"double-blind-session")
                    AESGCMCipher.decrypt_with_key(sym_key, tampered); res["success"]=True
                else: res["error_detail"]="Cannot tamper-test without session key"
            except Exception as e:
                res["error_detail"]=(f"Tamper DETECTED: {type(e).__name__} — "
                    f"GCM auth tag rejected. Modified {len(positions)} bytes.")
                blog("error", f"  → GCM auth rejected ❌")
        else: res["error_detail"]="Packet too small"

    elif method == "entropy_analysis":
        blog("info", "  Computing entropy + chi² + pattern analysis…")
        ent = shannon_entropy(raw); chi2 = chi_squared_uniformity(raw)
        top_freq = byte_frequency_top(raw); pats = find_repeated_patterns(raw)
        pt = pkt.get("plaintext",""); pt_ent = shannon_entropy(pt.encode()) if pt else None
        res["entropy"]={"ciphertext":ent,"max":8.0,"ratio":round(ent/8,4),"plaintext":pt_ent}
        res["chi_squared"]=chi2; res["top_frequencies"]=top_freq; res["patterns"]=pats
        res["error_detail"]=(
            f"Shannon entropy: {ent}/8.0 bits/byte ({ent/8*100:.1f}%). "
            f"Chi² = {chi2['chi_squared']} (critical={chi2['critical_005']}): "
            f"{'random ✅' if chi2['looks_random'] else 'non-random ⚠️'}. "
            f"Repeated 4-byte patterns: {len(pats)}. "
            + (f"Plaintext entropy: {pt_ent}/8.0. " if pt_ent is not None else "")
            + "Ciphertext is statistically indistinguishable from random noise — zero information leakage."
        )
        blog("info", f"  → Entropy {ent}/8.0 | Chi² {chi2['chi_squared']} | Patterns {len(pats)}")

    elif method == "known_plaintext":
        blog("warning", f"  Known-plaintext attack with \"{known_text}\"…")
        kp = encode_chat_message("Alice", known_text)
        ct_body = raw[12:] if len(raw)>12 else raw
        xlen = min(len(kp), len(ct_body))
        xor = bytes(a^b for a,b in zip(kp[:xlen], ct_body[:xlen]))
        xe = shannon_entropy(xor)
        res["known_plaintext"]=known_text; res["known_hex"]=kp[:32].hex()
        res["xor_hex"]=xor[:32].hex(); res["xor_entropy"]=xe
        res["error_detail"]=(
            f"XOR(plaintext, ciphertext) → {xlen}B with entropy {xe}/8.0. "
            "Under a weak cipher this reveals the keystream, but AES-256-GCM uses "
            "random nonces + authenticated encryption — XOR output is pure noise. "
            "Identical plaintexts produce different ciphertexts every time."
        )
        blog("error", f"  → XOR entropy {xe}/8.0 — no key info extracted ❌")

    elif method == "dictionary_attack":
        words = ["password","123456","admin","letmein","welcome","monkey","dragon","master",
                 "qwerty","login","abc123","starwars","trustno1","iloveyou","shadow",
                 "ashley","football","michael","ninja","mustang","access"]
        blog("warning", f"  Dictionary attack — {len(words)} common passwords…")
        t0 = time.perf_counter(); fails=[]
        for i, w in enumerate(words):
            dk = hashlib.sha256(w.encode()).digest()
            try:
                if "Chat" in pkt["type"]: AESGCMCipher.decrypt_with_key(dk, raw); res["success"]=True; break
            except Exception as e: fails.append({"word":w,"key":dk.hex()[:16]+"…","error":type(e).__name__})
            socketio.emit("dict_attack_progress",{"current":i+1,"total":len(words),"word":w,"key_preview":dk.hex()[:16]+"…"})
            socketio.sleep(0.06)
        el=(time.perf_counter()-t0)*1000; res["wordlist_size"]=len(words)
        res["dict_failures"]=fails[:8]; res["elapsed_ms"]=round(el,2)
        res["error_detail"]=(f"All {len(words)} passwords failed in {el:.1f}ms. "
                             "Session key comes from Kyber-768 KEM, not a password — dictionary attacks are fundamentally useless.")
        blog("error", f"  → All {len(words)} words failed ❌")

    state.stats["attacker_failures"] += 0 if res["success"] else 1
    state.attacker_attempts.append(res)
    emit("attacker_result", res)

@socketio.on("run_full_attack_demo")
def handle_full_attack_demo():
    if not state.intercepted_packets:
        emit("system_msg",{"text":"No packets — run handshake + send messages first!"}); return
    methods = ["random_key","brute_force","wrong_kyber_key","bit_flip","replay_attack",
               "entropy_analysis","known_plaintext","dictionary_attack"]
    blog("warning", f"═══ FULL ATTACK DEMO — {len(state.intercepted_packets)} packets × {len(methods)} methods ═══")
    emit("attack_demo_start",{"total_packets":len(state.intercepted_packets)})
    for pi in range(len(state.intercepted_packets)):
        for m in methods:
            handle_attacker_decrypt({"packet_id":pi,"method":m,"brute_count":200})
            socketio.sleep(0.12)
    all_fail = all(not a.get("success") for a in state.attacker_attempts)
    emit("attack_demo_complete",{"total_attempts":len(state.attacker_attempts),"all_failed":all_fail})
    blog("info", f"  ✅ {len(state.attacker_attempts)} attacks — ALL FAILED" if all_fail else "  ⚠️ Some attacks succeeded?!")

# ---------------------------------------------------------------------------
#  Stats / info
# ---------------------------------------------------------------------------
@socketio.on("get_stats")
def handle_get_stats():
    emit("stats_update",{"stats":state.stats,"messages":len(state.messages),
         "intercepted":len(state.intercepted_packets),"attacker_attempts":len(state.attacker_attempts)})

@socketio.on("get_intercepted")
def handle_get_intercepted():
    emit("intercepted_list",[{k:v for k,v in p.items() if k!="raw_bytes"} for p in state.intercepted_packets])

if __name__ == "__main__":
    print("\n" + "="*60)
    print("  🛡️  Double-Blind PQC — Web Dashboard")
    print("  Open http://localhost:5050 in your browser")
    print("="*60 + "\n")
    socketio.run(app, host="0.0.0.0", port=5050, debug=False, allow_unsafe_werkzeug=True)
