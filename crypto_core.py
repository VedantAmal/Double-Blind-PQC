"""
Double-Blind Post-Quantum Communication Ecosystem
===================================================
Crypto Core Module — Kyber-768 KEM, Dilithium-3 Signatures,
AES-256-GCM Symmetric Encryption, and HKDF Key Derivation.

This module provides the real PQC cryptographic primitives used by
both Layer 1 (VPN Sidecar) and Layer 2 (Messenger).
"""

import os
import time
import hashlib
import struct
import logging
from typing import Tuple, Optional

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger("crypto_core")

# ---------------------------------------------------------------------------
#  Kyber-768 Key Encapsulation Mechanism (ML-KEM-768)
# ---------------------------------------------------------------------------

class KyberKEM:
    """
    Wraps liboqs Kyber-768 for key encapsulation.
    
    Kyber-768 produces:
      - Public key:  1,184 bytes
      - Ciphertext:  1,088 bytes
      - Shared secret: 32 bytes
    """

    ALGORITHM = "Kyber768"

    def __init__(self):
        self._kem = oqs.KeyEncapsulation(self.ALGORITHM)
        self._public_key: Optional[bytes] = None
        self._secret_key_stored = False

    def generate_keypair(self) -> bytes:
        """Generate a Kyber-768 keypair. Returns the public key."""
        self._public_key = self._kem.generate_keypair()
        self._secret_key_stored = True
        logger.info(f"Kyber-768 keypair generated (pk={len(self._public_key)}B)")
        return self._public_key

    @property
    def public_key(self) -> Optional[bytes]:
        return self._public_key

    def encapsulate(self, peer_public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret using the peer's public key.
        Returns (ciphertext, shared_secret).
        """
        kem_enc = oqs.KeyEncapsulation(self.ALGORITHM)
        ciphertext, shared_secret = kem_enc.encap_secret(peer_public_key)
        logger.info(f"Kyber-768 encapsulated (ct={len(ciphertext)}B, ss={len(shared_secret)}B)")
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """Decapsulate the ciphertext using our secret key. Returns shared_secret."""
        if not self._secret_key_stored:
            raise RuntimeError("No secret key — call generate_keypair() first")
        shared_secret = self._kem.decap_secret(ciphertext)
        logger.info(f"Kyber-768 decapsulated (ss={len(shared_secret)}B)")
        return shared_secret


# ---------------------------------------------------------------------------
#  Dilithium-3 Digital Signatures (ML-DSA-65)
# ---------------------------------------------------------------------------

class DilithiumSigner:
    """
    Wraps liboqs Dilithium3 for digital signatures.
    Used to authenticate peers during the PQC handshake.
    
    Dilithium-3 produces:
      - Public key:  1,952 bytes
      - Signature:   ~3,293 bytes
    """

    ALGORITHM = "Dilithium3"

    def __init__(self):
        self._sig = oqs.Signature(self.ALGORITHM)
        self._public_key: Optional[bytes] = None

    def generate_keypair(self) -> bytes:
        """Generate a Dilithium-3 signing keypair. Returns the public key."""
        self._public_key = self._sig.generate_keypair()
        logger.info(f"Dilithium-3 keypair generated (pk={len(self._public_key)}B)")
        return self._public_key

    @property
    def public_key(self) -> Optional[bytes]:
        return self._public_key

    def sign(self, message: bytes) -> bytes:
        """Sign a message with our secret key."""
        signature = self._sig.sign(message)
        return signature

    @staticmethod
    def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a signature against the signer's public key."""
        verifier = oqs.Signature(DilithiumSigner.ALGORITHM)
        try:
            is_valid = verifier.verify(message, signature, public_key)
            return is_valid
        except Exception:
            return False


# ---------------------------------------------------------------------------
#  AES-256-GCM Authenticated Encryption
# ---------------------------------------------------------------------------

class AESGCMCipher:
    """
    AES-256-GCM for symmetric authenticated encryption.
    The 32-byte shared secret from Kyber is used (via HKDF) as the key.
    Each message uses a unique 12-byte nonce (96-bit counter).
    """

    NONCE_SIZE = 12  # 96 bits
    KEY_SIZE = 32    # 256 bits
    TAG_SIZE = 16    # 128-bit auth tag (appended by AESGCM)

    def __init__(self, key: bytes):
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes, got {len(key)}")
        self._aesgcm = AESGCM(key)
        self._nonce_counter = 0

    def _next_nonce(self) -> bytes:
        """Generate a deterministic nonce from an incrementing counter."""
        nonce = struct.pack(">Q", self._nonce_counter).rjust(self.NONCE_SIZE, b'\x00')
        self._nonce_counter += 1
        return nonce

    def encrypt(self, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
        """
        Encrypt plaintext. Returns nonce || ciphertext || tag.
        """
        nonce = self._next_nonce()
        ct = self._aesgcm.encrypt(nonce, plaintext, aad)
        return nonce + ct  # nonce(12) + ciphertext + tag(16)

    @staticmethod
    def decrypt_with_key(key: bytes, data: bytes, aad: Optional[bytes] = None) -> bytes:
        """
        Decrypt data = nonce(12) || ciphertext || tag(16).
        """
        nonce = data[:AESGCMCipher.NONCE_SIZE]
        ct = data[AESGCMCipher.NONCE_SIZE:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ct, aad)

    def decrypt(self, data: bytes, aad: Optional[bytes] = None) -> bytes:
        """
        Decrypt data = nonce(12) || ciphertext || tag(16).
        """
        nonce = data[:self.NONCE_SIZE]
        ct = data[self.NONCE_SIZE:]
        return self._aesgcm.decrypt(nonce, ct, aad)


# ---------------------------------------------------------------------------
#  HKDF Key Derivation
# ---------------------------------------------------------------------------

def derive_key(shared_secret: bytes, info: bytes = b"double-blind-pqc",
               salt: Optional[bytes] = None, length: int = 32) -> bytes:
    """
    Derive a symmetric key from the Kyber shared secret using HKDF-SHA256.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    derived = hkdf.derive(shared_secret)
    logger.debug(f"HKDF derived {length}B key (info={info!r})")
    return derived


# ---------------------------------------------------------------------------
#  Full PQC Handshake Session
# ---------------------------------------------------------------------------

class PQCSession:
    """
    Orchestrates a complete Post-Quantum handshake:
      1. Kyber-768 key encapsulation  → shared secret
      2. HKDF key derivation          → AES-256 key
      3. AES-256-GCM for data traffic
    
    Optionally authenticates the peer with Dilithium-3 signatures.
    """

    def __init__(self, role: str, label: str = "default"):
        """
        role: "initiator" or "responder"
        label: human-readable label for logging
        """
        self.role = role
        self.label = label
        self.kem = KyberKEM()
        self.signer = DilithiumSigner()
        self._cipher: Optional[AESGCMCipher] = None
        self._shared_secret: Optional[bytes] = None
        self._peer_sig_pk: Optional[bytes] = None
        self._established = False
        self._established_at: Optional[float] = None

    # -- Key generation -------------------------------------------------

    def generate_keys(self) -> Tuple[bytes, bytes]:
        """
        Generate both KEM and signing keypairs.
        Returns (kem_public_key, sig_public_key).
        """
        kem_pk = self.kem.generate_keypair()
        sig_pk = self.signer.generate_keypair()
        return kem_pk, sig_pk

    # -- Handshake messages ---------------------------------------------

    def create_handshake_init(self) -> dict:
        """
        Initiator creates the first handshake message containing
        their KEM public key and signing public key.
        """
        kem_pk, sig_pk = self.generate_keys()
        # Sign the KEM public key to prove ownership
        sig = self.signer.sign(kem_pk)
        return {
            "type": "handshake_init",
            "kem_pk": kem_pk,
            "sig_pk": sig_pk,
            "sig": sig,
            "timestamp": time.time(),
        }

    def process_handshake_init(self, msg: dict) -> dict:
        """
        Responder processes the init, encapsulates a shared secret,
        and sends back the ciphertext + their own signing key.
        """
        peer_kem_pk = msg["kem_pk"]
        peer_sig_pk = msg["sig_pk"]
        peer_sig = msg["sig"]

        # Verify the initiator's signature on their KEM key
        if not DilithiumSigner.verify(peer_kem_pk, peer_sig, peer_sig_pk):
            raise SecurityError("Invalid signature on initiator's KEM public key")

        self._peer_sig_pk = peer_sig_pk

        # Encapsulate a shared secret
        ciphertext, shared_secret = self.kem.encapsulate(peer_kem_pk)
        self._shared_secret = shared_secret

        # Derive symmetric key and create cipher
        sym_key = derive_key(shared_secret, info=b"double-blind-session")
        self._cipher = AESGCMCipher(sym_key)
        self._established = True
        self._established_at = time.time()

        # Generate our signing key and sign the ciphertext
        _, sig_pk = self.generate_keys()
        sig = self.signer.sign(ciphertext)

        logger.info(f"[{self.label}] Session established (responder)")
        return {
            "type": "handshake_resp",
            "ciphertext": ciphertext,
            "sig_pk": sig_pk,
            "sig": sig,
            "timestamp": time.time(),
        }

    def process_handshake_resp(self, msg: dict) -> None:
        """
        Initiator processes the response, decapsulates the shared secret.
        """
        ciphertext = msg["ciphertext"]
        peer_sig_pk = msg["sig_pk"]
        peer_sig = msg["sig"]

        # Verify the responder's signature on the ciphertext
        if not DilithiumSigner.verify(ciphertext, peer_sig, peer_sig_pk):
            raise SecurityError("Invalid signature on responder's ciphertext")

        self._peer_sig_pk = peer_sig_pk

        # Decapsulate
        shared_secret = self.kem.decapsulate(ciphertext)
        self._shared_secret = shared_secret

        # Derive symmetric key and create cipher
        sym_key = derive_key(shared_secret, info=b"double-blind-session")
        self._cipher = AESGCMCipher(sym_key)
        self._established = True
        self._established_at = time.time()

        logger.info(f"[{self.label}] Session established (initiator)")

    # -- Data encryption ------------------------------------------------

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt application data with the session key."""
        if not self._established or self._cipher is None:
            raise RuntimeError("Session not established — handshake first")
        return self._cipher.encrypt(plaintext)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt application data with the session key."""
        if not self._established or self._cipher is None:
            raise RuntimeError("Session not established — handshake first")
        return self._cipher.decrypt(data)

    @property
    def is_established(self) -> bool:
        return self._established

    def session_info(self) -> dict:
        """Return diagnostic info about the session."""
        return {
            "role": self.role,
            "label": self.label,
            "established": self._established,
            "established_at": self._established_at,
            "shared_secret_hash": hashlib.sha256(
                self._shared_secret).hexdigest()[:16] if self._shared_secret else None,
        }


class SecurityError(Exception):
    """Raised when a cryptographic verification fails."""
    pass
