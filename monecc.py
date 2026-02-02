from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import sys
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib


P_PRIME = 101
P_A = 35
P_B = 3
BASE_POINT = (2, 9)


Point = Optional[Tuple[int, int]]



def _mod_inv(x: int, p: int = P_PRIME) -> int:
    """Multiplicative inverse modulo p."""
    if x % p == 0:
        raise ZeroDivisionError("Inverse does not exist for zero.")
    return pow(x, p - 2, p)


def _point_add(p1: Point, p2: Point) -> Point:
    """Add two points on the curve."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and (y1 + y2) % P_PRIME == 0:
        return None  # point at infinity

    if p1 == p2:
        # point doubling
        num = (3 * x1 * x1 + P_A) % P_PRIME
        den = _mod_inv((2 * y1) % P_PRIME)
    else:
        num = (y2 - y1) % P_PRIME
        den = _mod_inv((x2 - x1) % P_PRIME)

    slope = (num * den) % P_PRIME
    x3 = (slope * slope - x1 - x2) % P_PRIME
    y3 = (slope * (x1 - x3) - y1) % P_PRIME
    return (x3, y3)


def scalar_mult(k: int, point: Point = BASE_POINT) -> Point:
    """Compute k * point using double-and-add."""
    if k == 0 or point is None:
        return None
    result = None
    addend = point
    n = k
    while n > 0:
        if n & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        n >>= 1
    return result


# === Key file helpers ===
def _b64_encode_str(text: str) -> str:
    return base64.b64encode(text.encode("ascii")).decode("ascii")


def _b64_decode_str(text: str) -> str:
    return base64.b64decode(text.encode("ascii")).decode("ascii")


def write_key_files(base_name: str, k: int, public_point: Point) -> Tuple[str, str]:
    """Create private and public key files; returns their paths."""
    priv_path = f"{base_name}.priv"
    pub_path = f"{base_name}.pub"

    with open(priv_path, "w", encoding="utf-8") as f:
        f.write("---begin monECC private key---\n")
        f.write(f"{_b64_encode_str(str(k))}\n")
        f.write("---end monECC key---\n")

    if public_point is None:
        raise ValueError("Public point cannot be infinity.")
    qx, qy = public_point
    with open(pub_path, "w", encoding="utf-8") as f:
        f.write("---begin monECC public key---\n")
        f.write(f"{_b64_encode_str(f'{qx};{qy}')}\n")
        f.write("---end monECC key---\n")

    return priv_path, pub_path


def read_private_key(path: str) -> int:
    with open(path, "r", encoding="utf-8") as f:
        lines = [ln.strip() for ln in f.readlines()]
    if len(lines) < 3 or not lines[0].replace(" ", "") == "---beginmonECCprivatekey---":
        raise ValueError("Fichier de clé privée invalide (entête).")
    try:
        k_str = _b64_decode_str(lines[1])
        k = int(k_str)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("Impossible de lire la clé privée.") from exc
    return k


def read_public_key(path: str) -> Tuple[int, int]:
    with open(path, "r", encoding="utf-8") as f:
        lines = [ln.strip() for ln in f.readlines()]
    if len(lines) < 3 or not lines[0].replace(" ", "") == "---beginmonECCpublickey---":
        raise ValueError("Fichier de clé publique invalide (entête).")
    try:
        decoded = _b64_decode_str(lines[1])
        x_str, y_str = decoded.split(";")
        return int(x_str), int(y_str)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("Impossible de lire la clé publique.") from exc


# === AES helpers ===
def _derive_key_and_iv(shared_point: Point) -> Tuple[bytes, bytes]:
    if shared_point is None:
        raise ValueError("Le secret partagé est le point à l'infini.")
    x, y = shared_point
    material = f"{x}|{y}".encode("ascii")
    digest = hashlib.sha256(material).digest()  # 32 bytes
    iv = digest[:16]
    key = digest[16:]
    return key, iv


def _aes_encrypt(key: bytes, iv: bytes, plaintext: str) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def _aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> str:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded) + unpadder.finalize()
    return data.decode("utf-8")


# === High level operations ===
def keygen(base_name: str, size: int) -> Tuple[str, str, int, Point]:
    if size < 1:
        raise ValueError("La taille de clé doit être >= 1.")
    public: Point = None
    # regenerate until public point not at infinity
    while public is None:
        k = secrets.randbelow(size) + 1  # 1..size
        public = scalar_mult(k, BASE_POINT)
    priv_path, pub_path = write_key_files(base_name, k, public)
    return priv_path, pub_path, k, public


def encrypt(public_point: Point, message: str) -> Tuple[str, Point]:
    """Encrypt with ephemeral ECDH; returns payload string and ephemeral public."""
    if not message:
        raise ValueError("Le message à chiffrer est vide.")
    eph_k = secrets.randbelow(1000) + 1  # small range OK for this toy curve
    eph_pub = scalar_mult(eph_k, BASE_POINT)
    shared = scalar_mult(eph_k, public_point)
    key, iv = _derive_key_and_iv(shared)
    ct = _aes_encrypt(key, iv, message)
    payload = {
        "R": eph_pub,
        "iv": base64.b64encode(iv).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
    }
    encoded = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    return encoded, eph_pub


def decrypt(private_k: int, payload_b64: str) -> str:
    try:
        decoded_json = base64.b64decode(payload_b64.encode("ascii")).decode("utf-8")
        payload = json.loads(decoded_json)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("Cryptogramme mal formé (base64/json).") from exc

    try:
        r_point = tuple(payload["R"])  # type: ignore[arg-type]
        iv = base64.b64decode(payload["iv"])
        ct = base64.b64decode(payload["ct"])
    except Exception as exc:  # noqa: BLE001
        raise ValueError("Cryptogramme incomplet.") from exc

    shared = scalar_mult(private_k, r_point)
    key, derived_iv = _derive_key_and_iv(shared)
    # We keep IV from payload to follow spec; derived_iv should match
    if iv != derived_iv:
        # Not fatal, but signal mismatch early
        raise ValueError("IV ne correspond pas au secret dérivé (cryptogramme modifié ?).")
    return _aes_decrypt(key, iv, ct)


# === CLI ===
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="monECC",
        add_help=False,
        description="Chiffrement pédagogique ECC + AES/CBC sur courbe mod 101.",
    )
    subparsers = parser.add_subparsers(dest="command")

    # help handled manually
    keygen_p = subparsers.add_parser("keygen", add_help=False)
    keygen_p.add_argument("-f", metavar="file", default="monECC", help="préfixe des clés (default: monECC)")
    keygen_p.add_argument("-s", metavar="size", type=int, default=1000, help="borne max aléa (default: 1000)")

    crypt_p = subparsers.add_parser("crypt", add_help=False)
    crypt_p.add_argument("keyfile", nargs="?", help="clé publique .pub")
    crypt_p.add_argument("text", nargs="?", help="texte clair (si -i absent)")
    crypt_p.add_argument("-i", metavar="input", help="fichier texte en entrée")
    crypt_p.add_argument("-o", metavar="output", help="fichier de sortie")

    decrypt_p = subparsers.add_parser("decrypt", add_help=False)
    decrypt_p.add_argument("keyfile", nargs="?", help="clé privée .priv")
    decrypt_p.add_argument("text", nargs="?", help="cryptogramme (si -i absent)")
    decrypt_p.add_argument("-i", metavar="input", help="fichier cryptogramme en entrée")
    decrypt_p.add_argument("-o", metavar="output", help="fichier de sortie")

    subparsers.add_parser("help", add_help=False)
    return parser


def print_manual():
    manual = """Script monECC
Syntaxe :
  monECC <commande> [<clé>] [<texte>] [switchs]
Commande :
  keygen : Génère une paire de clé
  crypt  : Chiffre <texte> pour la clé publique <clé>
  decrypt: Déchiffre <texte> avec la clé privée <clé>
  help   : Affiche ce manuel
Clé :
  Fichier contenant une clé publique (.pub) pour crypt ou privée (.priv) pour decrypt
Texte :
  Phrase en clair (crypt) ou cryptogramme (decrypt)
Switchs :
  -f <file> : nom de base des clés générées (monECC.pub / monECC.priv par défaut)
  -s <size> : borne supérieure pour l'aléa de keygen (>=1, défaut 1000)
  -i <file> : lire le texte/cryptogramme depuis un fichier
  -o <file> : écrire le résultat dans un fichier plutôt que sur la sortie standard
"""
    print(manual)


def _read_input_text(args_text: Optional[str], path: Optional[str]) -> str:
    if path:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    if args_text is None:
        raise ValueError("Texte manquant.")
    return args_text


def _write_output(text: str, path: Optional[str]) -> None:
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        print(text)


def main(argv: list[str]) -> int:
    if not argv or argv[0] in {"help", "-h", "--help"}:
        print_manual()
        return 0

    # Accept common typos
    if argv[0] == "crytp":
        argv[0] = "crypt"
    if argv[0] == "decrytp":
        argv[0] = "decrypt"

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "keygen":
            priv, pub, k, q = keygen(args.f, args.s)
            print(f"Clés générées : {priv}, {pub}")
            print(f"k = {k}, Q = {q}")
        elif args.command == "crypt":
            if not args.keyfile:
                raise ValueError("Fichier de clé publique manquant.")
            public = read_public_key(args.keyfile)
            message = _read_input_text(args.text, args.i)
            payload, eph_pub = encrypt(public, message)
            _write_output(payload, args.o)
            print(f"[debug] Point éphémère R = {eph_pub}", file=sys.stderr)
        elif args.command == "decrypt":
            if not args.keyfile:
                raise ValueError("Fichier de clé privée manquant.")
            private_k = read_private_key(args.keyfile)
            payload = _read_input_text(args.text, args.i)
            plaintext = decrypt(private_k, payload.strip())
            _write_output(plaintext, args.o)
        else:
            print_manual()
            return 0
    except Exception as exc:  # noqa: BLE001
        print(f"Erreur : {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
