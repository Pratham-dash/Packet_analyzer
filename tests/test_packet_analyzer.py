import os
import subprocess
import tempfile
import unittest

from packet_analyzer import (
    AppType,
    BlockingRules,
    classify_host,
    extract_http_host,
    extract_sni,
    parse_packet,
    run_engine,
)
from generate_test_pcap import create_tls_client_hello

REPO = "/home/runner/work/Packet_analyzer/Packet_analyzer"
SAMPLE_PCAP = os.path.join(REPO, "test_dpi.pcap")


class PacketAnalyzerTests(unittest.TestCase):
    def test_parse_tcp_packet(self):
        with open(SAMPLE_PCAP, "rb") as f:
            f.read(24)
            hdr = f.read(16)
            incl = int.from_bytes(hdr[8:12], "little")
            data = f.read(incl)
        parsed = parse_packet(1, 1, data)
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.has_ip)
        self.assertTrue(parsed.has_tcp)
        self.assertEqual(parsed.protocol, 6)

    def test_extract_sni(self):
        payload = create_tls_client_hello("www.youtube.com")
        self.assertEqual(extract_sni(payload), "www.youtube.com")

    def test_extract_http_host(self):
        payload = b"GET / HTTP/1.1\r\nHost: example.com:80\r\n\r\n"
        self.assertEqual(extract_http_host(payload), "example.com")

    def test_classification(self):
        self.assertEqual(classify_host("www.youtube.com"), AppType.YOUTUBE)
        self.assertEqual(classify_host("unknown.example"), AppType.HTTPS)

    def test_blocking(self):
        rules = BlockingRules()
        rules.block_ip("192.168.1.50")
        rules.block_app("YouTube")
        rules.block_domain("*.facebook.com")
        self.assertTrue(rules.should_block(BlockingRules.parse_ip("192.168.1.50"), AppType.UNKNOWN, ""))
        self.assertTrue(rules.should_block(0, AppType.YOUTUBE, ""))
        self.assertTrue(rules.should_block(0, AppType.UNKNOWN, "video.facebook.com"))

    def test_pcap_round_trip(self):
        rules = BlockingRules()
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "out.pcap")
            stats = run_engine(SAMPLE_PCAP, out, rules, lbs=1, fps=1)
            self.assertGreater(stats.forwarded, 0)
            self.assertEqual(stats.dropped, 0)
            self.assertGreater(os.path.getsize(out), 24)

    def test_cli(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "cli_out.pcap")
            cmd = [
                "python3",
                os.path.join(REPO, "packet_analyzer.py"),
                SAMPLE_PCAP,
                out,
                "--block-app",
                "YouTube",
                "--lbs",
                "1",
                "--fps",
                "1",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, msg=res.stderr)
            self.assertIn("Output written to", res.stdout)
            self.assertTrue(os.path.exists(out))


if __name__ == "__main__":
    unittest.main()
