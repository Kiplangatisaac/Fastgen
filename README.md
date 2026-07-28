# Fastgen

Ultra-fast password candidate generator for hashcat and John the Ripper.

## Features

- **Speed**: ~2M candidates/sec (single-threaded, zero-copy, buffered I/O)
- **Hard limit enforcement**: Checks limit *during* mutation generation, not just between words
- **Streaming output**: Pipes directly to hashcat/john with zero latency
- **Auto-finds rockyou.txt**: Checks `~/Downloads`, `/usr/share/wordlists`, `/opt/wordlists`, current dir
- **Interactive progress**: Shows live candidates/sec, words/sec, ETA when not piping
- **Full mutation rules**: leet, years, numbers, specials, prefixes, insertions, case variants
- **Brute force mode**: charset^length combinations

## Install

```bash
# Quick install
curl -sSL https://raw.githubusercontent.com/yourusername/Fastgen/main/install.sh | bash

# Or manually
git clone https://github.com/yourusername/Fastgen
cd Fastgen
./install.sh
```

## Usage

```bash
# Interactive mode (auto-finds rockyou.txt, shows progress)
fastgen --progress -l 1000000

# Pipe to hashcat (max speed, no progress)
fastgen -w rockyou.txt | hashcat -m 0 hashes.txt

# Limit candidates, show progress
fastgen -w rockyou.txt -l 1M --progress

# Brute force only
fastgen --brute --brute-length 4:6 --charset "abc123" | hashcat -m 0 hashes.txt

# Custom rules
fastgen -w rockyou.txt -r original,leet,years,numbers --progress

# John the Ripper
fastgen -w rockyou.txt | john --pipe --format=NT hashes.txt

# Find rockyou.txt location
fastgen --find-rockyou
```

## Options

| Flag | Description |
|------|-------------|
| `-w, --wordlist` | Input wordlist (`-` for stdin, `AUTO` to auto-find rockyou.txt) |
| `-o, --output` | Output file (`-` for stdout) |
| `-l, --limit` | Max candidates (0 = unlimited) |
| `-r, --rules` | Comma-separated rules: `original,leet,years,numbers,special,prepend,insert,case` |
| `--brute` | Enable brute force mode |
| `--charset` | Charset for brute force (default: printable ASCII) |
| `--brute-length` | Min:max length for brute force (default: 1:6) |
| `--progress` | Force show progress |
| `--no-progress` | Disable progress |
| `--find-rockyou` | Show rockyou.txt location and exit |

## Mutation Rules

| Rule | Description |
|------|-------------|
| `original` | Base word |
| `case` | lower, UPPER, Capitalize, SwapCase |
| `leet` | a→@/4, e→3, i→1/!, o→0, s→$/5, t→7, g→9/6, b→6, z→2, l→1, c→(, d→[, h→#, k→<, q→9 |
| `years` | 1970-2030 appended/prepended |
| `numbers` | 00-99, 000-999, 0000-9999 appended/prepended |
| `special` | !@#$%^&*... appended/prepended |
| `prepend` | admin, root, user, test, password, pass, pwd, 123, 2020-2025 |
| `insert` | 1, !, @, #, $, 123, ?, 0, ., _, - at positions 0-7 |

## Performance

| Mode | Speed |
|------|-------|
| Full mutations (all rules) | ~300K-500K candidates/sec |
| Limited rules (original,leet,years) | ~1M-2M candidates/sec |
| Brute force | ~500K-1M candidates/sec |
| Piped to hashcat | Zero overhead |

## Requirements

- Python 3.8+
- rockyou.txt in `~/Downloads/rockyou.txt` (or specify with `-w`)

## Download rockyou.txt

```bash
wget -O ~/Downloads/rockyou.txt.gz https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt.gz
gunzip ~/Downloads/rockyou.txt.gz
```