#!/usr/bin/env python3
"""
Ultra-fast password candidate generator for hashcat/john piping.
Single-threaded, zero-copy where possible, hard limit enforcement.

Usage:
    # Pipe directly to hashcat (no progress, max speed)
    fastgen -w rockyou.txt | hashcat -m 0 hashes.txt

    # Interactive mode with progress (output to file/terminal)
    fastgen -w rockyou.txt -l 1000000 --progress

    # Brute force charset^length
    fastgen --brute --brute-length 4:6 --charset "abc123" | hashcat -m 0 hashes.txt

    # Auto-finds rockyou.txt in ~/Downloads if -w not specified
    fastgen --progress
"""

import sys
import os
import argparse
import string
import time
import shutil
from pathlib import Path

# ─── Precomputed Mutation Data ────────────────────────────────────────
LEET_MAP = {
    ord('a'): (ord('@'), ord('4')), ord('A'): (ord('@'), ord('4')),
    ord('b'): (ord('6'),), ord('B'): (ord('6'),),
    ord('c'): (ord('('),), ord('C'): (ord('('),),
    ord('d'): (ord('['),), ord('D'): (ord('['),),
    ord('e'): (ord('3'),), ord('E'): (ord('3'),),
    ord('g'): (ord('9'), ord('6')), ord('G'): (ord('9'), ord('6')),
    ord('h'): (ord('#'),), ord('H'): (ord('#'),),
    ord('i'): (ord('1'), ord('!')), ord('I'): (ord('1'), ord('!')),
    ord('k'): (ord('<'),), ord('K'): (ord('<'),),
    ord('l'): (ord('1'),), ord('L'): (ord('1'),),
    ord('o'): (ord('0'),), ord('O'): (ord('0'),),
    ord('q'): (ord('9'),), ord('Q'): (ord('9'),),
    ord('s'): (ord('$'), ord('5')), ord('S'): (ord('$'), ord('5')),
    ord('t'): (ord('7'),), ord('T'): (ord('7'),),
    ord('z'): (ord('2'),), ord('Z'): (ord('2'),),
}

YEARS = [str(y).encode() for y in range(1970, 2031)]
NUMBERS = [f"{i:02d}".encode() for i in range(100)] + \
          [f"{i:03d}".encode() for i in range(1000)] + \
          [f"{i:04d}".encode() for i in range(10000)]
SPECIALS = [c.encode() for c in "!@#$%^&*()-_=+[]{}|;:,.<>?`~"]
PREFIXES = [b"", b"admin", b"root", b"user", b"test", b"password", b"pass", b"pwd", b"123", b"2024", b"2025", b"2023", b"2022", b"2021", b"2020"]
INSERT_CHARS = [b"1", b"!", b"@", b"#", b"$", b"123", b"?", b"0", b".", b"_", b"-"]


def write_candidate(f, buf, candidate, written, buf_size=1 << 16):
    """Write candidate to buffer, flush if full."""
    buf.extend(candidate)
    buf.extend(b'\n')
    written += 1
    if len(buf) >= buf_size:
        f.write(buf)
        buf.clear()
        written = 0
    return written


def mutate_word(word: str, rules: dict, limit: int, f, buf, written, counter) -> int:
    """Generate all mutations for a word, respecting hard limit."""
    w_bytes = word.encode()
    targets = [w_bytes]

    # Rule: original
    if rules['original']:
        written = write_candidate(f, buf, w_bytes, written)
        counter[0] += 1
        if limit and counter[0] >= limit:
            return written

    # Rule: case variations
    if rules['case']:
        for variant in (
            word.lower().encode(),
            word.upper().encode(),
            word.capitalize().encode(),
            word.swapcase().encode(),
        ):
            if variant != w_bytes:
                written = write_candidate(f, buf, variant, written)
                counter[0] += 1
                if limit and counter[0] >= limit:
                    return written

    # Rule: leet speak
    if rules['leet']:
        leet_variants = []
        # Single substitutions
        for src, dst_tuple in LEET_MAP.items():
            if src in w_bytes:
                for dst in dst_tuple:
                    mutated = w_bytes.replace(bytes([src]), bytes([dst]))
                    if mutated != w_bytes:
                        leet_variants.append(mutated)
                        written = write_candidate(f, buf, mutated, written)
                        counter[0] += 1
                        if limit and counter[0] >= limit:
                            return written

        # Full leet (all applicable subs)
        if leet_variants:
            full_leet = bytearray(w_bytes)
            for i, b in enumerate(full_leet):
                if b in LEET_MAP:
                    full_leet[i] = LEET_MAP[b][0]
            full_leet = bytes(full_leet)
            if full_leet != w_bytes:
                written = write_candidate(f, buf, full_leet, written)
                counter[0] += 1
                if limit and counter[0] >= limit:
                    return written

        targets.extend(leet_variants)

    # Rules that apply to all targets
    for target in targets:
        # Years append/prepend
        if rules['years']:
            for yr in YEARS:
                written = write_candidate(f, buf, target + yr, written)
                counter[0] += 1
                if limit and counter[0] >= limit:
                    return written
                written = write_candidate(f, buf, yr + target, written)
                counter[0] += 1
                if limit and counter[0] >= limit:
                    return written

        # Numbers append/prepend
        if rules['numbers']:
            for num in NUMBERS:
                written = write_candidate(f, buf, target + num, written)
                counter[0] += 1
                if limit and counter[0] >= limit:
                    return written
                written = write_candidate(f, buf, num + target, written)
                counter[0] += 1
                if limit and counter[0] >= limit:
                    return written

        # Specials append/prepend
        if rules['special']:
            for sp in SPECIALS:
                written = write_candidate(f, buf, target + sp, written)
                counter[0] += 1
                if limit and counter[0] >= limit:
                    return written
                written = write_candidate(f, buf, sp + target, written)
                counter[0] += 1
                if limit and counter[0] >= limit:
                    return written

        # Prepend prefixes
        if rules['prepend']:
            for pre in PREFIXES:
                if pre:
                    written = write_candidate(f, buf, pre + target, written)
                    counter[0] += 1
                    if limit and counter[0] >= limit:
                        return written

        # Insert at positions
        if rules['insert'] and len(target) <= 12:
            for pos in range(min(len(target) + 1, 8)):
                for ch in INSERT_CHARS:
                    written = write_candidate(f, buf, target[:pos] + ch + target[pos:], written)
                    counter[0] += 1
                    if limit and counter[0] >= limit:
                        return written

    return written


def brute_force(charset: bytes, min_len: int, max_len: int, limit: int, f, buf, written, counter) -> int:
    """Generate charset^length combinations."""
    indices = [0] * min_len
    charset_len = len(charset)

    for length in range(min_len, max_len + 1):
        if length > len(indices):
            indices.extend([0] * (length - len(indices)))
        else:
            indices = indices[:length]

        while True:
            candidate = bytes(charset[i] for i in indices)
            written = write_candidate(f, buf, candidate, written)
            counter[0] += 1
            if limit and counter[0] >= limit:
                return written

            # Increment odometer
            pos = 0
            while pos < length:
                indices[pos] += 1
                if indices[pos] < charset_len:
                    break
                indices[pos] = 0
                pos += 1
            if pos >= length:
                break
    return written


def count_lines(path: str) -> int:
    if path == '-':
        return 0
    try:
        with open(path, 'rb') as f:
            return sum(1 for _ in f)
    except:
        return 0


def find_rockyou() -> str | None:
    """Auto-locate rockyou.txt in common locations."""
    candidates = [
        Path("~/Downloads/rockyou.txt").expanduser(),
        Path("~/Downloads/rockyou.txt.gz").expanduser(),
        Path("~/rockyou.txt").expanduser(),
        Path("/usr/share/wordlists/rockyou.txt"),
        Path("/usr/share/wordlists/rockyou.txt.gz"),
        Path("/opt/wordlists/rockyou.txt"),
        Path("/opt/wordlists/rockyou.txt.gz"),
        Path("/wordlists/rockyou.txt"),
        Path("/data/rockyou.txt"),
        Path("./rockyou.txt"),
    ]
    for p in candidates:
        if p.exists():
            return str(p)
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Ultra-fast password candidate generator for hashcat/john piping",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Pipe to hashcat (max speed, no progress)
  fastgen -w rockyou.txt | hashcat -m 0 hashes.txt

  # Interactive mode with progress (output to file/terminal)
  fastgen -w rockyou.txt -l 1000000 --progress

  # Auto-find rockyou.txt in ~/Downloads
  fastgen --progress

  # Brute force only
  fastgen --brute --brute-length 4:6 --charset "abc123" | hashcat -m 0 hashes.txt

  # John the Ripper
  fastgen -w rockyou.txt | john --pipe --format=NT hashes.txt

Rules (comma-separated, default=all):
  original, leet, years, numbers, special, prepend, insert, case
"""
    )
    parser.add_argument('-w', '--wordlist', default='AUTO', help="Input wordlist ('-' for stdin, 'AUTO' to auto-find rockyou.txt)")
    parser.add_argument('-o', '--output', default='-', help="Output file ('-' for stdout)")
    parser.add_argument('-l', '--limit', type=int, default=0, help="Max candidates (0 = unlimited)")
    parser.add_argument('-r', '--rules', default='original,leet,years,numbers,special,prepend,insert,case',
                        help="Comma-separated rules")
    parser.add_argument('--brute', action='store_true', help="Also generate brute-force candidates")
    parser.add_argument('--charset', default=string.printable[:-6], help="Charset for brute force")
    parser.add_argument('--brute-length', default='1:6', help="Min:max length for brute force")
    parser.add_argument('--progress', action='store_true', help="Show progress on stderr (auto-enabled for non-pipe output)")
    parser.add_argument('--no-progress', action='store_true', help="Disable progress even for non-pipe output")
    parser.add_argument('--find-rockyou', action='store_true', help="Show rockyou.txt location and exit")
    args = parser.parse_args()

    # Handle --find-rockyou
    if args.find_rockyou:
        path = find_rockyou()
        if path:
            print(f"Found: {path}")
        else:
            print("rockyou.txt not found in common locations")
            print("Searched: ~/Downloads, ~/rockyou.txt, /usr/share/wordlists, /opt/wordlists, /wordlists, /data, ./rockyou.txt")
        return 0

    # Parse rules
    rule_names = ['original', 'leet', 'years', 'numbers', 'special', 'prepend', 'insert', 'case']
    enabled = set(r.strip() for r in args.rules.split(','))
    rules = {r: r in enabled for r in rule_names}

    # Parse brute length
    try:
        min_len, max_len = map(int, args.brute_length.split(':'))
    except:
        min_len, max_len = 1, 6

    # Determine wordlist
    if args.wordlist == 'AUTO':
        wordlist = find_rockyou()
        if not wordlist:
            sys.stderr.write("Error: rockyou.txt not found. Use -w to specify path or download it to ~/Downloads/rockyou.txt\n")
            sys.stderr.write("Download: wget -O ~/Downloads/rockyou.txt.gz https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt.gz\n")
            sys.stderr.write("Then: gunzip ~/Downloads/rockyou.txt.gz\n")
            return 1
        if not args.no_progress and not args.progress and not sys.stdout.isatty():
            # Being piped - don't show progress by default for max speed
            pass
        elif not args.no_progress and (args.progress or sys.stdout.isatty() or args.output != '-'):
            # Not piped, or output to file/terminal - show progress
            args.progress = True
    elif args.wordlist == '-':
        wordlist = '-'
    else:
        wordlist = args.wordlist

    # Determine if we should show progress
    # Auto-enable progress when NOT piping to hashcat/john (stdout is not a pipe)
    is_piped = not sys.stdout.isatty() and args.output == '-'
    show_progress = args.progress or (not args.no_progress and not is_piped)

    # Output
    if args.output == '-':
        f = sys.stdout.buffer
    else:
        f = open(args.output, 'wb')

    buf = bytearray()
    buf_size = 1 << 16
    written = 0
    counter = [0]
    start_time = time.time()
    last_progress = 0
    words_done = 0

    try:
        # Read wordlist
        if wordlist == '-':
            reader = sys.stdin.buffer
            total_words = 0
        else:
            wordlist_path = Path(wordlist)
            if not wordlist_path.exists():
                sys.stderr.write(f"Error: Wordlist file not found: {wordlist}\n")
                return 1
            reader = open(wordlist_path, 'rb')
            total_words = count_lines(wordlist) if show_progress else 0

        with reader:
            for line in reader:
                word = line.strip()
                if not word:
                    continue

                try:
                    word = word.decode('utf-8', errors='ignore')
                except:
                    word = word.decode('latin-1', errors='ignore')

                written = mutate_word(word, rules, args.limit, f, buf, written, counter)

                words_done += 1

                if show_progress:
                    now = time.time()
                    if now - last_progress >= 0.5:
                        elapsed = now - start_time
                        cps = counter[0] / elapsed if elapsed > 0 else 0
                        wps = words_done / elapsed if elapsed > 0 else 0
                        msg = f"\r[{elapsed:.1f}s] words: {words_done:,} | candidates: {counter[0]:,} | {wps:,.0f} w/s | {cps:,.0f} c/s"
                        if total_words:
                            pct = words_done / total_words * 100
                            msg += f" | {pct:.1f}%"
                        sys.stderr.write(msg)
                        sys.stderr.flush()
                        last_progress = now

                if args.limit and counter[0] >= args.limit:
                    break

        # Brute force
        if args.brute and (not args.limit or counter[0] < args.limit):
            charset = args.charset.encode()
            written = brute_force(charset, min_len, max_len, args.limit, f, buf, written, counter)

        # Flush
        if buf:
            f.write(buf)
        f.flush()

        if show_progress:
            elapsed = time.time() - start_time
            cps = counter[0] / elapsed if elapsed > 0 else 0
            sys.stderr.write(f"\nDone! {words_done:,} words, {counter[0]:,} candidates, {elapsed:.2f}s, {cps:,.0f} c/s\n")

    except BrokenPipeError:
        # hashcat/john closed the pipe - exit silently for clean piping
        pass
    except KeyboardInterrupt:
        sys.stderr.write("\nInterrupted\n")
    finally:
        if args.output != '-':
            f.close()

    return 0


if __name__ == '__main__':
    sys.exit(main())
