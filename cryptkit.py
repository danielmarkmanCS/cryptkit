#!/usr/bin/env python3
"""CryptKit - Crypto & Encoding Swiss Army Knife for CTFs"""

import argparse
import base64
import binascii
import hashlib
import codecs
import math
import string
import sys
import os
from collections import Counter

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

BANNER = r"""[bold cyan]
  ██████╗██████╗ ██╗   ██╗██████╗ ████████╗██╗  ██╗██╗████████╗
 ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██║ ██╔╝██║╚══██╔══╝
 ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   █████╔╝ ██║   ██║
 ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██╔═██╗ ██║   ██║
 ╚██████╗██║  ██║   ██║   ██║        ██║   ██║  ██╗██║   ██║
  ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   ╚═╝  ╚═╝╚═╝   ╚═╝
[/bold cyan][dim] Crypto & Encoding Toolkit for CTFs[/dim]
"""


# ── Hashing ──────────────────────────────────────────────

def hash_text(text, algo=None):
    data = text.encode()
    algos = ["md5", "sha1", "sha256", "sha512", "sha3_256"]
    if algo:
        algos = [algo]

    table = Table(
        title="[bold green]Hashes[/bold green]",
        box=box.ROUNDED,
        border_style="green",
        header_style="bold",
    )
    table.add_column("Algorithm", style="cyan", width=12)
    table.add_column("Hash", style="yellow")

    for a in algos:
        h = hashlib.new(a)
        h.update(data)
        table.add_row(a.upper(), h.hexdigest())

    console.print(table)


def hash_file(filepath, algo=None):
    if not os.path.isfile(filepath):
        console.print(f"[red]File not found: {filepath}[/red]")
        return

    algos = ["md5", "sha1", "sha256"]
    if algo:
        algos = [algo]

    table = Table(
        title=f"[bold green]File Hashes — {os.path.basename(filepath)}[/bold green]",
        box=box.ROUNDED,
        border_style="green",
    )
    table.add_column("Algorithm", style="cyan", width=12)
    table.add_column("Hash", style="yellow")

    for a in algos:
        h = hashlib.new(a)
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        table.add_row(a.upper(), h.hexdigest())

    console.print(table)


# ── Encoding / Decoding ──────────────────────────────────

def encode_decode(text, operation="identify"):
    results = []

    # Base64
    try:
        decoded = base64.b64decode(text, validate=True).decode("utf-8", errors="replace")
        results.append(("Base64 decode", decoded))
    except Exception:
        pass
    results.append(("Base64 encode", base64.b64encode(text.encode()).decode()))

    # Base32
    try:
        decoded = base64.b32decode(text).decode("utf-8", errors="replace")
        results.append(("Base32 decode", decoded))
    except Exception:
        pass
    results.append(("Base32 encode", base64.b32encode(text.encode()).decode()))

    # Hex
    try:
        clean = text.replace(" ", "").replace("0x", "").replace("\\x", "")
        decoded = bytes.fromhex(clean).decode("utf-8", errors="replace")
        results.append(("Hex decode", decoded))
    except Exception:
        pass
    results.append(("Hex encode", text.encode().hex()))

    # URL encoding
    try:
        import urllib.parse
        results.append(("URL encode", urllib.parse.quote(text)))
        results.append(("URL decode", urllib.parse.unquote(text)))
    except Exception:
        pass

    # ROT13
    results.append(("ROT13", codecs.encode(text, "rot_13")))

    # Binary
    results.append(("Binary", " ".join(format(ord(c), "08b") for c in text)))

    # Reverse
    results.append(("Reversed", text[::-1]))

    # Decimal / ASCII
    results.append(("Decimal (ASCII)", " ".join(str(ord(c)) for c in text)))

    table = Table(
        title="[bold green]Encode / Decode[/bold green]",
        box=box.ROUNDED,
        border_style="green",
        show_lines=True,
    )
    table.add_column("Transform", style="cyan", width=16)
    table.add_column("Result", style="yellow")

    for name, val in results:
        table.add_row(name, str(val)[:120])

    console.print(table)


def magic_decode(text):
    """Try to auto-detect and decode the input."""
    console.print(f"\n[bold yellow]🔮 Magic Decode[/bold yellow] → [cyan]{text[:60]}{'...' if len(text) > 60 else ''}[/cyan]\n")

    found = []

    # Base64?
    try:
        if len(text) % 4 <= 1 and all(c in string.ascii_letters + string.digits + "+/=" for c in text):
            decoded = base64.b64decode(text, validate=True).decode("utf-8")
            if decoded.isprintable() and len(decoded) > 0:
                found.append(("Base64", decoded))
    except Exception:
        pass

    # Hex?
    try:
        clean = text.replace(" ", "").replace("0x", "").replace("\\x", "")
        if all(c in string.hexdigits for c in clean) and len(clean) % 2 == 0 and len(clean) >= 4:
            decoded = bytes.fromhex(clean).decode("utf-8")
            if decoded.isprintable():
                found.append(("Hex", decoded))
    except Exception:
        pass

    # Binary?
    try:
        clean = text.replace(" ", "")
        if all(c in "01" for c in clean) and len(clean) % 8 == 0:
            decoded = "".join(chr(int(clean[i:i+8], 2)) for i in range(0, len(clean), 8))
            if decoded.isprintable():
                found.append(("Binary", decoded))
    except Exception:
        pass

    # Decimal ASCII?
    try:
        nums = text.split()
        if all(n.isdigit() and 0 <= int(n) <= 127 for n in nums) and len(nums) >= 2:
            decoded = "".join(chr(int(n)) for n in nums)
            if decoded.isprintable():
                found.append(("Decimal ASCII", decoded))
    except Exception:
        pass

    # ROT13?
    rot = codecs.encode(text, "rot_13")
    if rot != text:
        found.append(("ROT13", rot))

    # URL encoded?
    try:
        import urllib.parse
        decoded = urllib.parse.unquote(text)
        if decoded != text:
            found.append(("URL decode", decoded))
    except Exception:
        pass

    # Base32?
    try:
        if all(c in string.ascii_uppercase + "234567=" for c in text) and len(text) >= 8:
            decoded = base64.b32decode(text).decode("utf-8")
            if decoded.isprintable():
                found.append(("Base32", decoded))
    except Exception:
        pass

    if found:
        table = Table(
            title="[bold green]Detected Encodings[/bold green]",
            box=box.ROUNDED,
            border_style="green",
            show_lines=True,
        )
        table.add_column("Encoding", style="cyan", width=16)
        table.add_column("Decoded", style="yellow")

        for name, val in found:
            table.add_row(name, val[:120])

        console.print(table)

        # Try recursive decoding
        for name, val in found:
            if val != text and name != "ROT13":
                console.print(f"\n  [dim]Trying recursive decode on {name} result...[/dim]")
                try:
                    inner = base64.b64decode(val, validate=True).decode("utf-8")
                    if inner.isprintable() and inner != val:
                        console.print(f"    [green]→ Double {name}: {inner}[/green]")
                except Exception:
                    pass
    else:
        console.print("[yellow]  No common encoding detected.[/yellow]")
    console.print()


# ── Caesar / ROT Brute Force ─────────────────────────────

def caesar_brute(text):
    table = Table(
        title="[bold green]Caesar Cipher Brute Force[/bold green]",
        box=box.ROUNDED,
        border_style="green",
    )
    table.add_column("Shift", style="cyan", justify="center", width=6)
    table.add_column("Result", style="yellow")

    for shift in range(1, 26):
        result = ""
        for c in text:
            if c.isalpha():
                base = ord("A") if c.isupper() else ord("a")
                result += chr((ord(c) - base + shift) % 26 + base)
            else:
                result += c
        table.add_row(str(shift), result)

    console.print(table)


# ── XOR ──────────────────────────────────────────────────

def xor_strings(text, key):
    key_bytes = key.encode()
    text_bytes = text.encode()
    result = bytes(t ^ key_bytes[i % len(key_bytes)] for i, t in enumerate(text_bytes))

    table = Table(
        title="[bold green]XOR Result[/bold green]",
        box=box.ROUNDED,
        border_style="green",
    )
    table.add_column("Format", style="cyan", width=12)
    table.add_column("Result", style="yellow")

    table.add_row("Hex", result.hex())
    table.add_row("Base64", base64.b64encode(result).decode())
    try:
        table.add_row("ASCII", result.decode("utf-8", errors="replace"))
    except Exception:
        table.add_row("ASCII", "[dim]non-printable[/dim]")

    console.print(table)


def xor_brute(hex_input, max_key=255):
    console.print(f"\n[bold yellow]XOR Brute Force[/bold yellow]\n")

    try:
        data = bytes.fromhex(hex_input.replace(" ", ""))
    except ValueError:
        console.print("[red]Invalid hex input[/red]")
        return

    table = Table(
        title="[bold green]Single-byte XOR Results (printable only)[/bold green]",
        box=box.ROUNDED,
        border_style="green",
    )
    table.add_column("Key", style="cyan", width=8, justify="center")
    table.add_column("Key (chr)", style="cyan", width=10, justify="center")
    table.add_column("Result", style="yellow")

    for key in range(max_key + 1):
        result = bytes(b ^ key for b in data)
        try:
            decoded = result.decode("ascii")
            if decoded.isprintable() and len(decoded.strip()) > 0:
                key_chr = chr(key) if 32 <= key < 127 else f"0x{key:02x}"
                table.add_row(f"0x{key:02x}", key_chr, decoded)
        except Exception:
            pass

    console.print(table)


# ── Multi-byte XOR Crack ─────────────────────────────────

def hamming_distance(b1, b2):
    return sum(bin(a ^ b).count("1") for a, b in zip(b1, b2))


def find_key_length(data, max_len=40):
    scores = []
    for kl in range(2, min(max_len + 1, len(data) // 2)):
        chunks = [data[i:i+kl] for i in range(0, len(data) - kl, kl)]
        if len(chunks) < 2:
            continue
        distances = []
        for i in range(min(len(chunks) - 1, 6)):
            d = hamming_distance(chunks[i], chunks[i+1]) / kl
            distances.append(d)
        avg = sum(distances) / len(distances)
        scores.append((kl, avg))

    scores.sort(key=lambda x: x[1])
    return scores[:5]


ENGLISH_WORDS = {
    "the", "be", "to", "of", "and", "a", "in", "that", "have", "i",
    "it", "for", "not", "on", "with", "he", "as", "you", "do", "at",
    "this", "but", "his", "by", "from", "they", "we", "say", "her",
    "she", "or", "an", "will", "my", "one", "all", "would", "there",
    "their", "what", "so", "up", "out", "if", "about", "who", "get",
    "which", "go", "me", "when", "make", "can", "like", "time", "no",
    "just", "him", "know", "take", "people", "into", "year", "your",
    "good", "some", "could", "them", "see", "other", "than", "then",
    "now", "look", "only", "come", "its", "over", "think", "also",
    "back", "after", "use", "two", "how", "our", "work", "first",
    "well", "way", "even", "new", "want", "because", "any", "these",
    "give", "day", "most", "us", "is", "was", "are", "has", "had",
    "flag", "hidden", "secret", "message", "encrypt", "crack", "find",
}


def score_english_raw(text):
    """Absolute score — for single-byte cracking of short blocks."""
    freq = {
        'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0,
        'n': 6.7, 's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3,
        'l': 4.0, ' ': 15.0,
    }
    score = 0
    for c in text.lower():
        if c in freq:
            score += freq[c]
        elif not c.isprintable():
            score -= 50
    return score


def score_english(text):
    """Smart normalized score — for ranking final plaintext candidates."""
    if not text:
        return -999

    raw = score_english_raw(text)
    score = raw / len(text)

    words = text.lower().split()
    if words:
        word_hits = sum(1 for w in words if w.strip(".,!?;:'\"()") in ENGLISH_WORDS)
        score += (word_hits / len(words)) * 20

    printable_ratio = sum(1 for c in text if c.isprintable()) / len(text)
    score += printable_ratio * 5

    return score


def crack_single_byte_xor(data):
    best_score = -999999
    best_key = 0
    best_text = b""
    for key in range(256):
        result = bytes(b ^ key for b in data)
        try:
            text = result.decode("ascii")
            s = score_english_raw(text)
            if s > best_score:
                best_score = s
                best_key = key
                best_text = result
        except Exception:
            pass
    return best_key, best_text, best_score


def xor_crack_multi(hex_input):
    console.print(f"\n[bold yellow]Multi-byte XOR Crack[/bold yellow]\n")

    try:
        data = bytes.fromhex(hex_input.replace(" ", ""))
    except ValueError:
        console.print("[red]Invalid hex input[/red]")
        return

    if len(data) < 8:
        console.print("[red]Input too short for multi-byte analysis (need 8+ bytes)[/red]")
        return

    console.print(f"  [dim]Ciphertext: {len(data)} bytes[/dim]\n")

    # Step 1: Find key length
    key_lengths = find_key_length(data)

    kl_table = Table(
        title="[bold green]Step 1: Key Length Detection (Hamming Distance)[/bold green]",
        box=box.ROUNDED,
        border_style="green",
    )
    kl_table.add_column("Key Length", style="cyan", justify="center", width=12)
    kl_table.add_column("Score", style="yellow", width=10)
    kl_table.add_column("", width=10)

    for i, (kl, score) in enumerate(key_lengths):
        marker = "[bold green]<< best[/bold green]" if i == 0 else ""
        kl_table.add_row(str(kl), f"{score:.3f}", marker)

    console.print(kl_table)

    # Step 2: Crack for top key lengths + all small lengths (2-12)
    console.print(f"\n  [bold blue]Step 2: Cracking candidate key lengths...[/bold blue]\n")

    candidate_lengths = set()
    for kl, _ in key_lengths[:5]:
        candidate_lengths.add(kl)
    for kl in range(2, 13):
        if kl < len(data) // 2:
            candidate_lengths.add(kl)

    results = []
    for kl in sorted(candidate_lengths):
        key_bytes = []
        for i in range(kl):
            block = bytes(data[j] for j in range(i, len(data), kl))
            best_key, _, _ = crack_single_byte_xor(block)
            key_bytes.append(best_key)

        full_key = bytes(key_bytes)
        decrypted = bytes(data[i] ^ full_key[i % kl] for i in range(len(data)))

        try:
            plaintext = decrypted.decode("ascii")
            text_score = score_english(plaintext)
            printable = plaintext.isprintable()
        except Exception:
            plaintext = decrypted.decode("utf-8", errors="replace")
            text_score = -999
            printable = False

        key_ascii = ""
        try:
            key_ascii = full_key.decode("ascii")
            if not key_ascii.isprintable():
                key_ascii = ""
        except Exception:
            pass

        results.append({
            "key_len": kl,
            "key_hex": full_key.hex(),
            "key_ascii": key_ascii,
            "plaintext": plaintext,
            "score": text_score,
            "printable": printable,
        })

    results.sort(key=lambda x: x["score"], reverse=True)

    result_table = Table(
        title="[bold green]Step 2: Results[/bold green]",
        box=box.ROUNDED,
        border_style="green",
        show_lines=True,
    )
    result_table.add_column("Key Len", style="cyan", justify="center", width=8)
    result_table.add_column("Key (hex)", style="yellow", width=18)
    result_table.add_column("Key (ASCII)", style="bold green", width=14)
    result_table.add_column("Score", style="magenta", justify="right", width=8)

    for r in results:
        result_table.add_row(
            str(r["key_len"]),
            r["key_hex"],
            r["key_ascii"] or "[dim]-[/dim]",
            f"{r['score']:.0f}",
        )

    console.print(result_table)

    # Show best plaintext
    best = results[0]
    console.print(Panel(
        f"[bold]Key:[/bold] [green]{best['key_ascii'] or best['key_hex']}[/green]\n"
        f"[bold]Key (hex):[/bold] [yellow]{best['key_hex']}[/yellow]\n"
        f"[bold]Key length:[/bold] [cyan]{best['key_len']}[/cyan]\n\n"
        f"[bold]Plaintext:[/bold]\n{best['plaintext'][:500]}",
        title="[bold green]Best Result[/bold green]",
        border_style="bright_green",
        box=box.DOUBLE,
    ))
    console.print()


# ── Frequency Analysis ───────────────────────────────────

def freq_analysis(text):
    letters = [c.lower() for c in text if c.isalpha()]
    total = len(letters)

    if total == 0:
        console.print("[yellow]No letters found in input[/yellow]")
        return

    counts = Counter(letters)
    english_freq = {
        "e": 12.7, "t": 9.1, "a": 8.2, "o": 7.5, "i": 7.0,
        "n": 6.7, "s": 6.3, "h": 6.1, "r": 6.0, "d": 4.3,
        "l": 4.0, "c": 2.8, "u": 2.8, "m": 2.4, "w": 2.4,
        "f": 2.2, "g": 2.0, "y": 2.0, "p": 1.9, "b": 1.5,
        "v": 1.0, "k": 0.8, "j": 0.2, "x": 0.2, "q": 0.1, "z": 0.1,
    }

    table = Table(
        title="[bold green]Frequency Analysis[/bold green]",
        box=box.ROUNDED,
        border_style="green",
    )
    table.add_column("Letter", style="cyan", justify="center", width=6)
    table.add_column("Count", justify="right", width=6)
    table.add_column("Frequency", style="yellow", width=10)
    table.add_column("English", style="dim", width=10)
    table.add_column("Bar", width=30)

    for letter in string.ascii_lowercase:
        count = counts.get(letter, 0)
        freq = (count / total * 100) if total > 0 else 0
        eng = english_freq.get(letter, 0)
        bar_len = int(freq / 15 * 25)
        bar = f"[green]{'█' * bar_len}[/green]"
        table.add_row(letter, str(count), f"{freq:.1f}%", f"{eng:.1f}%", bar)

    console.print(table)

    entropy = 0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)

    console.print(f"\n  [bold]Entropy:[/bold] [cyan]{entropy:.3f}[/cyan] bits/char")
    console.print(f"  [bold]Unique chars:[/bold] [cyan]{len(counts)}[/cyan]")
    console.print(f"  [bold]Total letters:[/bold] [cyan]{total}[/cyan]\n")


# ── Password Strength ────────────────────────────────────

def password_strength(password):
    length = len(password)
    charset_size = 0
    checks = []

    if any(c in string.ascii_lowercase for c in password):
        charset_size += 26
        checks.append(("[green]✓[/green]", "Lowercase letters"))
    else:
        checks.append(("[red]✗[/red]", "Lowercase letters"))

    if any(c in string.ascii_uppercase for c in password):
        charset_size += 26
        checks.append(("[green]✓[/green]", "Uppercase letters"))
    else:
        checks.append(("[red]✗[/red]", "Uppercase letters"))

    if any(c in string.digits for c in password):
        charset_size += 10
        checks.append(("[green]✓[/green]", "Digits"))
    else:
        checks.append(("[red]✗[/red]", "Digits"))

    if any(c in string.punctuation for c in password):
        charset_size += 32
        checks.append(("[green]✓[/green]", "Special characters"))
    else:
        checks.append(("[red]✗[/red]", "Special characters"))

    if length >= 12:
        checks.append(("[green]✓[/green]", f"Length ({length} chars)"))
    elif length >= 8:
        checks.append(("[yellow]~[/yellow]", f"Length ({length} chars — aim for 12+)"))
    else:
        checks.append(("[red]✗[/red]", f"Length ({length} chars — too short)"))

    entropy = length * math.log2(charset_size) if charset_size > 0 else 0
    combinations = charset_size ** length if charset_size > 0 else 0

    if entropy >= 80:
        strength = "[bold green]STRONG[/bold green]"
    elif entropy >= 50:
        strength = "[bold yellow]MODERATE[/bold yellow]"
    else:
        strength = "[bold red]WEAK[/bold red]"

    common_patterns = [
        "password", "123456", "qwerty", "abc123", "letmein",
        "admin", "welcome", "monkey", "dragon", "master",
    ]
    is_common = password.lower() in common_patterns
    if is_common:
        checks.append(("[red]✗[/red]", "Common password detected!"))
        strength = "[bold red]WEAK[/bold red]"

    table = Table(
        title="[bold green]Password Analysis[/bold green]",
        box=box.ROUNDED,
        border_style="green",
        show_lines=True,
    )
    table.add_column("Property", style="cyan", width=24)
    table.add_column("Value", style="yellow")

    table.add_row("Strength", strength)
    table.add_row("Entropy", f"{entropy:.1f} bits")
    table.add_row("Charset size", str(charset_size))
    table.add_row("Combinations", f"{combinations:.2e}" if combinations > 1e6 else str(combinations))

    crack_rates = [
        ("Online (1K/s)", 1_000),
        ("Fast hash (10B/s)", 10_000_000_000),
        ("GPU cluster (1T/s)", 1_000_000_000_000),
    ]
    for name, rate in crack_rates:
        if combinations > 0:
            secs = combinations / rate
            if secs < 1:
                time_str = "instant"
            elif secs < 60:
                time_str = f"{secs:.0f} seconds"
            elif secs < 3600:
                time_str = f"{secs/60:.0f} minutes"
            elif secs < 86400:
                time_str = f"{secs/3600:.0f} hours"
            elif secs < 86400 * 365:
                time_str = f"{secs/86400:.0f} days"
            elif secs < 86400 * 365 * 1e6:
                time_str = f"{secs/(86400*365):.0f} years"
            else:
                time_str = f"{secs/(86400*365):.1e} years"
            table.add_row(f"Crack time ({name})", time_str)

    console.print(table)

    console.print("\n  [bold]Checks:[/bold]")
    for icon, desc in checks:
        console.print(f"    {icon} {desc}")
    console.print()


# ── Interactive Mode ─────────────────────────────────────

def interactive():
    console.print(BANNER)
    console.print(Panel(
        "[bold]Commands:[/bold]\n"
        "  [cyan]hash[/cyan]     <text>              — Hash text (MD5, SHA1, SHA256, SHA512)\n"
        "  [cyan]hashfile[/cyan] <path>              — Hash a file\n"
        "  [cyan]encode[/cyan]   <text>              — Show all encodings/decodings\n"
        "  [cyan]magic[/cyan]    <text>              — Auto-detect and decode\n"
        "  [cyan]caesar[/cyan]   <text>              — Brute-force Caesar cipher\n"
        "  [cyan]xor[/cyan]      <text> <key>        — XOR encrypt/decrypt\n"
        "  [cyan]xorbrute[/cyan] <hex>               — Brute-force single-byte XOR\n"
        "  [cyan]xorcrack[/cyan] <hex>               — Crack multi-byte XOR key\n"
        "  [cyan]freq[/cyan]     <text>              — Frequency analysis\n"
        "  [cyan]password[/cyan] <password>           — Password strength analysis\n"
        "  [cyan]help[/cyan]                          — Show this menu\n"
        "  [cyan]exit[/cyan]                          — Quit",
        title="[bold magenta]CryptKit[/bold magenta]",
        border_style="bright_blue",
        box=box.ROUNDED,
    ))

    while True:
        try:
            cmd = console.input("\n[bold magenta]cryptkit[/bold magenta] [dim]>[/dim] ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Bye.[/dim]")
            break

        if not cmd:
            continue

        parts = cmd.split(maxsplit=1)
        action = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if action in ("exit", "quit", "q"):
            console.print("[dim]Bye.[/dim]")
            break
        elif action == "hash" and arg:
            hash_text(arg)
        elif action == "hashfile" and arg:
            hash_file(arg)
        elif action == "encode" and arg:
            encode_decode(arg)
        elif action == "magic" and arg:
            magic_decode(arg)
        elif action == "caesar" and arg:
            caesar_brute(arg)
        elif action == "xor":
            xor_parts = arg.split(maxsplit=1)
            if len(xor_parts) == 2:
                xor_strings(xor_parts[0], xor_parts[1])
            else:
                console.print("[red]Usage: xor <text> <key>[/red]")
        elif action == "xorbrute" and arg:
            xor_brute(arg)
        elif action == "xorcrack" and arg:
            xor_crack_multi(arg)
        elif action == "freq" and arg:
            freq_analysis(arg)
        elif action == "password" and arg:
            password_strength(arg)
        elif action == "help":
            console.print(Panel(
                "[bold]Commands:[/bold]\n"
                "  [cyan]hash[/cyan]     <text>              — Hash text\n"
                "  [cyan]hashfile[/cyan] <path>              — Hash a file\n"
                "  [cyan]encode[/cyan]   <text>              — Show all encodings\n"
                "  [cyan]magic[/cyan]    <text>              — Auto-detect encoding\n"
                "  [cyan]caesar[/cyan]   <text>              — Caesar brute-force\n"
                "  [cyan]xor[/cyan]      <text> <key>        — XOR encrypt/decrypt\n"
                "  [cyan]xorbrute[/cyan] <hex>               — XOR brute-force (1 byte)\n"
                "  [cyan]xorcrack[/cyan] <hex>               — XOR crack (multi-byte)\n"
                "  [cyan]freq[/cyan]     <text>              — Frequency analysis\n"
                "  [cyan]password[/cyan] <pw>                — Password strength\n"
                "  [cyan]exit[/cyan]                          — Quit",
                border_style="bright_blue",
            ))
        else:
            console.print(f"[red]Unknown command or missing argument: {cmd}[/red]")
            console.print("[dim]Type 'help' for commands[/dim]")


def main():
    parser = argparse.ArgumentParser(
        description="CryptKit — Crypto & Encoding Toolkit for CTFs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command")

    h = subparsers.add_parser("hash", help="Hash text")
    h.add_argument("text", help="Text to hash")
    h.add_argument("-a", "--algo", help="Specific algorithm")

    hf = subparsers.add_parser("hashfile", help="Hash a file")
    hf.add_argument("filepath", help="File path")
    hf.add_argument("-a", "--algo", help="Specific algorithm")

    e = subparsers.add_parser("encode", help="Encode/decode text")
    e.add_argument("text", help="Text to encode/decode")

    m = subparsers.add_parser("magic", help="Auto-detect and decode")
    m.add_argument("text", help="Encoded text")

    c = subparsers.add_parser("caesar", help="Caesar cipher brute-force")
    c.add_argument("text", help="Ciphertext")

    x = subparsers.add_parser("xor", help="XOR encrypt/decrypt")
    x.add_argument("text", help="Text")
    x.add_argument("key", help="XOR key")

    xb = subparsers.add_parser("xorbrute", help="XOR single-byte brute-force")
    xb.add_argument("hex_input", help="Hex-encoded ciphertext")

    xc = subparsers.add_parser("xorcrack", help="Crack multi-byte XOR key")
    xc.add_argument("hex_input", help="Hex-encoded ciphertext")

    f = subparsers.add_parser("freq", help="Frequency analysis")
    f.add_argument("text", help="Text to analyze")

    p = subparsers.add_parser("password", help="Password strength analysis")
    p.add_argument("password", help="Password to analyze")

    args = parser.parse_args()

    if args.command is None:
        interactive()
    elif args.command == "hash":
        console.print(BANNER)
        hash_text(args.text, args.algo)
    elif args.command == "hashfile":
        console.print(BANNER)
        hash_file(args.filepath, args.algo)
    elif args.command == "encode":
        console.print(BANNER)
        encode_decode(args.text)
    elif args.command == "magic":
        console.print(BANNER)
        magic_decode(args.text)
    elif args.command == "caesar":
        console.print(BANNER)
        caesar_brute(args.text)
    elif args.command == "xor":
        console.print(BANNER)
        xor_strings(args.text, args.key)
    elif args.command == "xorbrute":
        console.print(BANNER)
        xor_brute(args.hex_input)
    elif args.command == "xorcrack":
        console.print(BANNER)
        xor_crack_multi(args.hex_input)
    elif args.command == "freq":
        console.print(BANNER)
        freq_analysis(args.text)
    elif args.command == "password":
        console.print(BANNER)
        password_strength(args.password)


if __name__ == "__main__":
    main()
