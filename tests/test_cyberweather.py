import json
import unittest
from pathlib import Path

from ingest.normalize import normalize_greynoise
from ingest.taxii import map_stix
from model.stats import map_name
from model.weather import classify, forecast, median


ROOT = Path(__file__).resolve().parents[1]
GNQL = next(ROOT.glob("gnql_*.json"))


class WeatherTests(unittest.TestCase):
    def test_states(self):
        self.assertEqual(classify({}), "Clear")
        self.assertEqual(classify({"crawler": 4}), "Watch")
        self.assertEqual(classify({"scanner": 2, "sibling": 9}), "Advisory")
        self.assertEqual(classify({"malicious_ips": 10}), "Storm")
        self.assertEqual(classify({"malicious_ips": 10, "kev_listed": True}), "Named storm")

    def test_median_and_brief(self):
        self.assertEqual(median([10, 10, 30]), 10)
        brief = forecast(
            {
                "cve": "CVE-2026-88771",
                "malicious_ips": 121,
                "ip_count": 121,
                "kev_listed": True,
                "crawler": 30,
                "scanner": 24,
                "sibling": 108,
                "trio": 22,
                "reused": 70,
                "between": 2,
                "post": 49,
                "session_values": [10, 10, 30000],
                "session_sum": 44080,
                "session_max": 30000,
                "after_landfall": True,
            }
        )
        self.assertEqual(brief["condition"], "Named storm")
        self.assertIn("after landfall", brief["after_landfall_note"])
        self.assertNotIn("${", brief["nature"])
        self.assertEqual(brief["precursors"]["trio"], 22)

    def test_map_alias(self):
        self.assertEqual(map_name("United States"), "United States of America")


class NormalizeTests(unittest.TestCase):
    def test_drops_http_payloads(self):
        payload = {
            "request_metadata": {"query": "cve:CVE-2026-88771 last_seen:30d"},
            "data": [
                {
                    "ip": "203.0.113.10",
                    "internet_scanner_intelligence": {
                        "classification": "malicious",
                        "spoofable": "False",
                        "first_seen": "2026-09-20",
                        "last_seen": "2026-10-01",
                        "tags": [
                            {
                                "id": "t1",
                                "slug": "citrix-adc-gateway-login-panel-crawler",
                                "name": "Citrix ADC Gateway Login Panel Crawler",
                                "intention": "unknown",
                                "cves": [],
                            }
                        ],
                        "tag_volumes": [{"tag_id": "t1", "session_count": "4"}],
                        "cves": ["CVE-2026-88771"],
                        "metadata": {
                            "organization": "Example Hosting",
                            "asn": "AS64500",
                            "source_country": "United States",
                            "source_country_code": "US",
                            "sensor_count": "3",
                            "sensor_hits": "9",
                            "destination_countries": ["Germany"],
                            "destination_country_codes": ["DE"],
                        },
                        "raw_data": {
                            "http": {"path": ["/vpn/../etc/passwd ${IFS} id"], "useragent": ["exploit-agent"]},
                            "scan": [{"payload": "() { :; }; /bin/sh"}],
                            "ja3": [{"fingerprint": "b885946e72ad51dca6c70abc2f773506", "port": "443"}],
                        },
                    },
                }
            ],
        }
        bundle = normalize_greynoise(payload)
        blob = json.dumps(bundle.vertices) + json.dumps(bundle.edges)
        self.assertNotIn("passwd", blob)
        self.assertNotIn("${IFS}", blob)
        self.assertNotIn("/bin/sh", blob)
        self.assertNotIn("exploit-agent", blob)
        self.assertIn("ip:203.0.113.10", bundle.vertices)
        self.assertTrue(bundle.vertices["ip:203.0.113.10"]["props"]["has_crawler"])
        self.assertEqual(len(bundle.exposure), 2)

    def test_real_export_shape(self):
        bundle = normalize_greynoise(json.loads(GNQL.read_text()))
        ips = [key for key, vertex in bundle.vertices.items() if vertex["type"] == "Ip"]
        self.assertEqual(len(ips), 121)
        blob = json.dumps(bundle.vertices)
        self.assertNotIn("request_header", blob)
        self.assertNotIn(".ctxs.receiver", blob)


class TaxiiTests(unittest.TestCase):
    def test_merges_cve_and_drops_payload_pattern(self):
        objects = [
            {
                "type": "vulnerability",
                "id": "vulnerability--11111111-1111-4111-8111-111111111111",
                "name": "CVE-2026-88771",
                "external_references": [{"source_name": "cve", "external_id": "CVE-2026-88771"}],
            },
            {
                "type": "indicator",
                "id": "indicator--22222222-2222-4222-8222-222222222222",
                "name": "source address",
                "pattern": "[ipv4-addr:value = '198.51.100.20']",
                "pattern_type": "stix",
            },
            {
                "type": "indicator",
                "id": "indicator--33333333-3333-4333-8333-333333333333",
                "name": "withheld",
                "pattern": "[url:value = 'http://example.test/${IFS}/bin/sh']",
                "pattern_type": "stix",
            },
            {
                "type": "relationship",
                "id": "relationship--44444444-4444-4444-8444-444444444444",
                "relationship_type": "indicates",
                "source_ref": "indicator--22222222-2222-4222-8222-222222222222",
                "target_ref": "vulnerability--11111111-1111-4111-8111-111111111111",
            },
        ]
        bundle = map_stix(objects)
        blob = json.dumps(bundle.vertices) + json.dumps(bundle.edges)
        self.assertIn("cve:CVE-2026-88771", bundle.vertices)
        self.assertIn("ip:198.51.100.20", bundle.vertices)
        self.assertNotIn("${IFS}", blob)
        self.assertNotIn("/bin/sh", blob)
        self.assertTrue(any(edge["type"] == "Indicates" for edge in bundle.edges.values()))


if __name__ == "__main__":
    unittest.main()
