import email
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner.timeline import (
    DeliverySummary,
    MailHop,
    TimelineAnalysis,
    _classify_ip,
    build_delivery_timeline,
    calculate_delivery_delays,
    extract_mail_hops,
    generate_delivery_summary,
    parse_received_header,
    parse_received_headers,
)


class TimelineAnalysisTests(unittest.TestCase):

    def test_classify_ip_native_ipaddress(self):
        # Public IPv4
        ip_type, is_internal = _classify_ip("8.8.8.8")
        self.assertEqual(ip_type, "Public IP")
        self.assertFalse(is_internal)

        # Private IPv4 subnets
        ip_type, is_internal = _classify_ip("192.168.1.100")
        self.assertEqual(ip_type, "Private IP")
        self.assertTrue(is_internal)

        ip_type, is_internal = _classify_ip("10.0.0.1")
        self.assertEqual(ip_type, "Private IP")
        self.assertTrue(is_internal)

        # Loopback
        ip_type, is_internal = _classify_ip("127.0.0.1")
        self.assertEqual(ip_type, "Loopback")
        self.assertTrue(is_internal)

        # IPv6
        ip_type, is_internal = _classify_ip("2001:db8::1")
        self.assertEqual(ip_type, "IPv6")

    def test_single_received_header_parsing(self):
        header = (
            "from mail.example.com (mail.example.com [198.51.100.10]) "
            "by mx.google.com with ESMTP id 12345; Wed, 5 Aug 2026 01:23:45 +0000"
        )
        hop = parse_received_header(header)
        self.assertIsNotNone(hop)
        self.assertEqual(hop.from_host, "mail.example.com")
        self.assertEqual(hop.from_ip, "198.51.100.10")
        self.assertEqual(hop.by_host, "mx.google.com")
        self.assertEqual(hop.protocol, "ESMTP")
        self.assertEqual(hop.ip_type, "Public IP")
        self.assertFalse(hop.is_internal)

    def test_multiple_received_headers_chronological_reversal(self):
        eml_bytes = (
            b"From: victim@enterprise.sec\n"
            b"To: analyst@enterprise.sec\n"
            b"Subject: Security Test Email\n"
            b"Received: by mail.company.com (Postfix, from userid 1000)\n"
            b"\tid ABC1234; Wed, 05 Aug 2026 01:24:00 +0000\n"
            b"Received: from mx.google.com (mx.google.com [172.217.1.1])\n"
            b"\tby mail.company.com with ESMTP; Wed, 05 Aug 2026 01:23:55 +0000\n"
            b"Received: from mail.attacker.com (mail.attacker.com [198.51.100.22])\n"
            b"\tby mx.google.com with ESMTP; Wed, 05 Aug 2026 01:23:40 +0000\n"
            b"\n"
            b"Hello world!\n"
        )
        msg = email.message_from_bytes(eml_bytes)
        timeline = build_delivery_timeline(msg)

        self.assertTrue(timeline.has_timeline)
        self.assertEqual(len(timeline.hops), 3)

        # Hop 1 (First relay: mail.attacker.com)
        self.assertEqual(timeline.hops[0].hop_number, 1)
        self.assertEqual(timeline.hops[0].from_host, "mail.attacker.com")
        self.assertEqual(timeline.hops[0].from_ip, "198.51.100.22")

        # Hop 2 (mx.google.com)
        self.assertEqual(timeline.hops[1].hop_number, 2)
        self.assertEqual(timeline.hops[1].from_host, "mx.google.com")
        self.assertEqual(timeline.hops[1].delay_display, "15s")

        # Hop 3 (Final recipient: mail.company.com)
        self.assertEqual(timeline.hops[2].hop_number, 3)
        self.assertEqual(timeline.hops[2].by_host, "mail.company.com")
        self.assertEqual(timeline.hops[2].delay_display, "5s")

        # Summary
        self.assertEqual(timeline.summary.total_hops, 3)
        self.assertEqual(timeline.summary.total_delivery_time_display, "20s")

    def test_malformed_headers_graceful_handling(self):
        headers = [
            "Malformed header without delimitation",
            "from ;;; by ::: invalid",
            "",
            "Received: from [127.0.0.1] by localhost; invalid timestamp",
        ]
        parsed = parse_received_headers(headers)
        self.assertTrue(isinstance(parsed, list))
        # Should not crash on any malformed input

    def test_missing_timestamps_and_delays(self):
        header1 = "from mail1.sec (mail1.sec [198.51.100.1]) by mail2.sec"
        header2 = "from mail2.sec (mail2.sec [198.51.100.2]) by mail3.sec; Wed, 05 Aug 2026 01:23:40 +0000"

        hops = parse_received_headers([header1, header2])
        hops = calculate_delivery_delays(hops)

        self.assertEqual(len(hops), 2)
        self.assertEqual(hops[0].delay_display, "0s (Initial Hop)")
        self.assertIn("Missing timestamp", hops[0].observations)

    def test_ipv6_relay_detection(self):
        header = (
            "from mail6.example.com (mail6.example.com [IPv6:2001:db8::1]) "
            "by mx.google.com with ESMTP; Wed, 5 Aug 2026 01:23:45 +0000"
        )
        hop = parse_received_header(header)
        self.assertIsNotNone(hop)
        self.assertEqual(hop.from_ip, "2001:db8::1")
        self.assertEqual(hop.ip_type, "IPv6")
        self.assertIn("IPv6 relay", hop.observations)

    def test_duplicate_relay_detection(self):
        hop1 = MailHop(hop_number=1, from_host="relay1.com", from_ip="198.51.100.1")
        hop2 = MailHop(hop_number=2, from_host="relay1.com", from_ip="198.51.100.1")
        calculate_delivery_delays([hop1, hop2])
        self.assertIn("Duplicate relay", hop2.observations)

    def test_empty_email_returns_no_timeline(self):
        msg = email.message_from_bytes(b"From: a@b.com\nTo: c@d.com\n\nNo received headers")
        timeline = build_delivery_timeline(msg)
        self.assertFalse(timeline.has_timeline)
        self.assertEqual(len(timeline.hops), 0)
        self.assertEqual(timeline.summary_message, "No delivery path available.")


if __name__ == "__main__":
    unittest.main()
