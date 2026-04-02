"""
Secure File Transfer Module
AES-256-GCM + RSA-2048-OAEP using the 'cryptography' library.
"""

import os, json, hashlib, base64
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

UPLOAD_DIR = Path("uploads")
DOWNLOAD_DIR = Path("downloads")
KEY_DIR = Path("keys")
for d in (UPLOAD_DIR, DOWNLOAD_DIR, KEY_DIR):
    d.mkdir(exist_ok=True)

_transfer_log = []

def generate_rsa_keypair(bits=2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    public_pem = public_key.public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    (KEY_DIR / f"private_{ts}.pem").write_text(private_pem)
    (KEY_DIR / f"public_{ts}.pem").write_text(public_pem)
    return {"private_key": private_pem, "public_key": public_pem,
            "private_key_file": f"keys/private_{ts}.pem",
            "public_key_file": f"keys/public_{ts}.pem",
            "bits": bits, "generated_at": datetime.now().isoformat()}

def load_or_create_keypair():
    pf = sorted(KEY_DIR.glob("private_*.pem"))
    pu = sorted(KEY_DIR.glob("public_*.pem"))
    if pf and pu:
        return {"private_key": pf[-1].read_text(), "public_key": pu[-1].read_text(),
                "private_key_file": str(pf[-1]), "public_key_file": str(pu[-1])}
    return generate_rsa_keypair()

def _oaep():
    return asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                              algorithm=hashes.SHA256(), label=None)

def encrypt_file(file_bytes: bytes, public_key_pem: str, filename: str) -> dict:
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    aes_key = os.urandom(32)
    nonce   = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, file_bytes, None)
    pub = serialization.load_pem_public_key(public_key_pem.encode())
    enc_key = pub.encrypt(aes_key, _oaep())
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_name = f"{ts}_{filename}.enc"
    package = {"filename": filename,
                "encrypted_key": base64.b64encode(enc_key).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "sha256": file_hash, "original_size": len(file_bytes),
                "encrypted_at": datetime.now().isoformat(),
                "algorithm": "AES-256-GCM + RSA-2048-OAEP/SHA-256"}
    (DOWNLOAD_DIR / out_name).write_text(json.dumps(package, indent=2))
    log = {"id": len(_transfer_log)+1, "time": datetime.now().strftime("%H:%M:%S"),
           "filename": filename, "original_size": len(file_bytes),
           "encrypted_size": len(ciphertext), "sha256": file_hash,
           "operation": "encrypt", "status": "success", "output_file": out_name}
    _transfer_log.append(log)
    return {**package, "output_file": out_name, "log": log}

def decrypt_file(package: dict, private_key_pem: str) -> dict:
    try:
        enc_key    = base64.b64decode(package["encrypted_key"])
        nonce      = base64.b64decode(package["nonce"])
        ciphertext = base64.b64decode(package["ciphertext"])
        priv = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        aes_key   = priv.decrypt(enc_key, _oaep())
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
        actual    = hashlib.sha256(plaintext).hexdigest()
        integrity = actual == package["sha256"]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_name = f"{ts}_decrypted_{package['filename']}"
        (DOWNLOAD_DIR / out_name).write_bytes(plaintext)
        log = {"id": len(_transfer_log)+1, "time": datetime.now().strftime("%H:%M:%S"),
               "filename": package["filename"], "original_size": len(plaintext),
               "sha256": actual, "operation": "decrypt",
               "status": "success" if integrity else "integrity_fail",
               "integrity": integrity, "output_file": out_name}
        _transfer_log.append(log)
        return {"success": True, "integrity_ok": integrity,
                "plaintext_size": len(plaintext), "sha256": actual,
                "output_file": out_name, "log": log}
    except Exception as e:
        log = {"id": len(_transfer_log)+1, "time": datetime.now().strftime("%H:%M:%S"),
               "filename": package.get("filename","?"), "operation": "decrypt",
               "status": "error", "error": str(e)}
        _transfer_log.append(log)
        return {"success": False, "error": str(e), "log": log}

def get_transfer_log():
    return list(_transfer_log)

def demo_encrypt_decrypt():
    keys   = load_or_create_keypair()
    sample = b"CONFIDENTIAL: Secure demo message from MiniSOC.\n" * 5
    enc    = encrypt_file(sample, keys["public_key"], "demo_message.txt")
    pkg    = {k: enc[k] for k in ("filename","encrypted_key","nonce","ciphertext","sha256","original_size")}
    dec    = decrypt_file(pkg, keys["private_key"])
    return {"keys": {"public": keys["public_key"][:200]+"...",
                     "private": keys["private_key"][:200]+"..."},
            "encrypt": {k: enc[k] for k in ("filename","original_size","sha256","algorithm","output_file")},
            "decrypt": dec}
