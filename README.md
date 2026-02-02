# TP MonECC (ECC + AES/CBC)

Implémentation en Python d'un mini-outil de chiffrement par courbe elliptique pédagogique
sur la courbe `y^2 = x^3 + 35x + 3 (mod 101)` avec le point de base P = (2, 9).

## Auteurs
- Jory GRZESZCZAK - M2 AL ESGI Grenoble

## Prérequis
- Python 3.11+ (testé avec 3.14)
- `cryptography` (installé via `pip`)

## Installation rapide
```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Utilisation
Affichage de l'aide :
```bash
python3 monecc.py help
```

Génération d'une paire de clés (fichiers `monECC.pub` et `monECC.priv`) :
```bash
python3 monecc.py keygen
# options : -f <prefix> pour renommer, -s <borne> pour changer la plage (défaut 1000)
```

Chiffrement avec une clé publique :
```bash
python3 monecc.py crypt monECC.pub "message en clair"
# ou python3 monecc.py crypt monECC.pub -i message.txt -o sortie.enc
```

Déchiffrement avec la clé privée correspondante :
```bash
python3 monecc.py decrypt monECC.priv "$(python3 monecc.py crypt monECC.pub 'bonjour')"
# ou python3 monecc.py decrypt monECC.priv -i sortie.enc -o clair.txt
```

Le cryptogramme est un bloc base64 contenant le point éphémère, l'IV et le texte chiffré.

## Détails techniques
- Courbe : `y^2 = x^3 + 35x + 3 (mod 101)`
- Base : P = (2, 9)
- Multiplication de point : double-and-add
- Secret partagé : ECDH avec clé éphémère (crypt) ou privée (decrypt), haché SHA-256
- Symétrique : AES-128/CBC avec PKCS7 (IV = 16 premiers octets du hash, clé = 16 derniers)

## Arborescence
- `monecc.py` : script CLI principal
- `requirements.txt` : dépendances Python

## Tests rapides
```bash
. .venv/bin/activate
python monecc.py keygen -f demo
cipher=$(python monecc.py crypt demo.pub "hello")
python monecc.py decrypt demo.priv "$cipher"
```
