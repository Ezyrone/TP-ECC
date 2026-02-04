# TP MonECC

## Auteur

- Jory GRZESZCZAK — M2 AL ESGI Grenoble

## Avant de commencer

- Python 3.11+ (testé en 3.14)
- La librairie `cryptography` (installée via `pip`)

## Installation

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Comment s’en servir ?

  ```
- Générer une paire de clés (`monECC.pub` / `monECC.priv`) :
  ```bash
  python3 monecc.py keygen
  # options : -f <prefix> (nom des fichiers) ; -s <borne> (aléa, défaut 1000)
  ```

- Chiffrer avec une clé publique :

  ```bash
  python3 monecc.py crypt monECC.pub "message en clair"
  # ou python3 monecc.py crypt monECC.pub -i message.txt -o sortie.enc
  ```

- Déchiffrer avec la clé privée correspondante :

  ```bash
  python3 monecc.py decrypt monECC.priv "$(python3 monecc.py crypt monECC.pub 'bonjour')"
  # ou python3 monecc.py decrypt monECC.priv -i sortie.enc -o clair.txt
  ```

Le cryptogramme produit est un bloc base64 qui embarque le point éphémère, l’IV et le texte chiffré.

- Courbe : `y^2 = x^3 + 35x + 3 (mod 101)`, base P = (2, 9)
- Multiplication : double-and-add
- Secret partagé : ECDH, haché SHA-256 → 16 octets d’IV + 16 octets de clé AES
- Chiffrement : AES-128/CBC + PKCS7

```
