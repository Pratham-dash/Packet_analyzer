# Packet Analyzer (Python 3)

This repository now provides a Python 3 implementation of the DPI packet analyzer, functionally replacing the previous C++ executable workflow while preserving CLI usage.

## What it does

- Reads PCAP files
- Parses Ethernet + IPv4 + TCP/UDP packets
- Tracks flows via five-tuple
- Extracts TLS ClientHello SNI
- Extracts HTTP `Host` for plaintext HTTP
- Classifies traffic into app categories (YouTube, Facebook, etc.)
- Applies configurable blocking rules:
  - source IP
  - application
  - domain / wildcard domain (`*.example.com`)
- Writes forwarded packets to output PCAP with preserved packet bytes and timestamps
- Reports forwarded/dropped and protocol/application counts
- Supports thread configuration using `--lbs` and `--fps` (effective worker count = `lbs * fps`)

## Repository structure

- `/packet_analyzer.py` – main Python DPI engine and CLI
- `/dpi_engine` – executable launcher (keeps `./dpi_engine ...` usability)
- `/generate_test_pcap.py` – sample PCAP generator
- `/test_dpi.pcap` – sample input capture
- `/tests/test_packet_analyzer.py` – Python unit/integration tests
- `/src`, `/include`, `/CMakeLists.txt` – legacy C++ implementation/reference

## Requirements

- Python 3.12
- No external Python packages required (see `requirements.txt`)

## Usage

### Preferred (same as previous executable-style workflow)

```bash
./dpi_engine <input.pcap> <output.pcap> [options]
```

### Equivalent direct Python invocation

```bash
python3.12 packet_analyzer.py <input.pcap> <output.pcap> [options]
```

### CLI options

- `--block-ip <ip>` (repeatable)
- `--block-app <app>` (repeatable)
- `--block-domain <domain-or-pattern>` (repeatable)
- `--rules <rules_file>` (C++-compatible section format)
- `--lbs <n>` number of load-balancer shards (default `2`)
- `--fps <n>` workers per LB shard (default `2`)

### Examples

```bash
./dpi_engine test_dpi.pcap output.pcap

./dpi_engine test_dpi.pcap output.pcap \
  --block-app YouTube \
  --block-app TikTok \
  --block-ip 192.168.1.50 \
  --block-domain facebook

./dpi_engine test_dpi.pcap output.pcap --lbs 4 --fps 4
```

## Rules file format

You can pass a rules file via `--rules`:

```text
[BLOCKED_IPS]
192.168.1.50

[BLOCKED_APPS]
YouTube

[BLOCKED_DOMAINS]
*.facebook.com
example.org
```

## Generate sample PCAP

```bash
python3.12 generate_test_pcap.py
```

This creates `test_dpi.pcap` with TLS SNI, HTTP, DNS, and blocked-IP style traffic.

## Testing

Run:

```bash
python3.12 -m unittest discover -s tests -p 'test_*.py' -v
```

Coverage in tests includes:

- packet parsing
- TLS SNI extraction
- HTTP Host extraction
- app classification
- blocking logic
- PCAP processing/round-trip path
- CLI execution

## Compatibility decisions

- CLI shape is preserved for the main workflow (`./dpi_engine input output [options]`).
- Existing block options and thread configuration flags are preserved.
- Output keeps original packet payload bytes and timestamps for forwarded packets.
- Legacy C++ source/build files are kept in the repository as reference, but Python is now the primary runtime path.
