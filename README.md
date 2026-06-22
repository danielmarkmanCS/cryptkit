# CryptKit

```
  ██████╗██████╗ ██╗   ██╗██████╗ ████████╗██╗  ██╗██╗████████╗
 ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██║ ██╔╝██║╚══██╔══╝
 ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   █████╔╝ ██║   ██║
 ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██╔═██╗ ██║   ██║
 ╚██████╗██║  ██║   ██║   ██║        ██║   ██║  ██╗██║   ██║
  ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   ╚═╝  ╚═╝╚═╝   ╚═╝
```

**A crypto & encoding Swiss Army knife built for CTF players.**

CryptKit handles the encoding, hashing, cipher-cracking, and analysis tasks you hit constantly in CTFs — all from one tool with beautiful terminal output.

## Features

- **Hashing** — MD5, SHA1, SHA256, SHA512, SHA3 for text and files
- **Encode/Decode** — Base64, Base32, Hex, URL, ROT13, Binary, Decimal ASCII
- **Magic Decode** — Auto-detects encoding and decodes (with recursive detection)
- **Caesar Brute Force** — All 25 shifts at a glance
- **XOR** — Encrypt/decrypt with key, single-byte brute-force on hex input
- **Frequency Analysis** — Letter distribution vs English, entropy calculation
- **Password Strength** — Entropy, charset, crack time estimates, common pattern detection
- **Interactive REPL** — Quick CTF workflow without re-typing commands

## Installation

```bash
git clone https://github.com/danielmarkcs/cryptkit.git
cd cryptkit
pip install rich
```

## Usage

### Command Line

```bash
# Hash text
python3 cryptkit.py hash "flag{hello}"
python3 cryptkit.py hash "flag{hello}" -a sha256

# Hash a file
python3 cryptkit.py hashfile secret.bin

# Encode/decode (shows all transformations)
python3 cryptkit.py encode "hello world"

# Auto-detect encoding
python3 cryptkit.py magic "aGVsbG8gd29ybGQ="
python3 cryptkit.py magic "68656c6c6f"

# Caesar brute-force
python3 cryptkit.py caesar "Uryyb Jbeyq"

# XOR
python3 cryptkit.py xor "secret" "key"

# XOR brute-force (hex input)
python3 cryptkit.py xorbrute "1b0a0411070a"

# Frequency analysis
python3 cryptkit.py freq "Gur dhvpx oebja sbk whzcf bire gur ynml qbt"

# Password strength
python3 cryptkit.py password "MyP@ssw0rd!"
```

### Interactive Mode

```bash
python3 cryptkit.py
```

```
cryptkit > magic aGVsbG8gd29ybGQ=
  Detected: Base64 → "hello world"

cryptkit > caesar Uryyb Jbeyq
  Shift 13: Hello World

cryptkit > password hunter2
  Strength: WEAK
  Entropy: 33.2 bits
```

## CTF Workflow Examples

```bash
# Got a suspicious string from a challenge?
python3 cryptkit.py magic "VkdobGNtVWdhWE1nZEdobElHWnNZV2M9"
# → Base64 → "VGhlcmUgaXMgdGhlIGZsYWc=" → Base64 → "There is the flag"

# Frequency analysis on substitution cipher
python3 cryptkit.py freq "$(cat ciphertext.txt)"

# Quick hash check
python3 cryptkit.py hash "flag{found_it}" -a md5
```

## Requirements

- Python 3.8+
- `rich` — terminal formatting
- No other dependencies (all crypto is stdlib)

## License

MIT
