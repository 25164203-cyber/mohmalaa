import json
import tempfile
import unittest
from pathlib import Path

import ssrfscope


class SSRFScopeTests(unittest.TestCase):
    def test_query_parameter_replacement(self):
        result = ssrfscope.replace_query_parameter(
            "http://example.test/fetch?a=1&url=old", "url", "http://127.0.0.1:8788/"
        )
        self.assertIn("a=1", result)
        self.assertIn("url=http%3A%2F%2F127.0.0.1%3A8788%2F", result)

    def test_nested_json_update(self):
        body = ssrfscope.update_json_body(
            '{"options":{"redirect":{"url":"old"}}}',
            "options.redirect.url",
            "http://127.0.0.1:8788/",
        )
        parsed = json.loads(body)
        self.assertEqual(parsed["options"]["redirect"]["url"], "http://127.0.0.1:8788/")

    def test_signature_detection(self):
        signatures = ssrfscope.detect_signatures("internal-demo-service LAB_INTERNAL_CANARY_SSRFSCOPE")
        self.assertIn("lab-internal-canary", signatures)

    def test_differential_new_finding(self):
        current = {
            "generated_at": "now",
            "results": [{"attempts": [{
                "target": {"kind": "parameter", "name": "url"},
                "payload": "http://127.0.0.1:8788/",
                "payload_template": "http://127.0.0.1:8788/",
                "severity": "possible-ssrf",
                "score": 4,
                "response": {"signatures": ["lab-internal-canary"]},
            }]}],
        }
        previous = {"generated_at": "old", "results": []}
        diff = ssrfscope.compare_documents(current, previous)
        self.assertEqual(diff["new_count"], 1)

    def test_raw_request_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "request.txt"
            path.write_text(
                "POST /api/fetch HTTP/1.1\n"
                "Host: 127.0.0.1:8787\n"
                "Content-Type: application/json\n\n"
                '{"url":"x"}',
                encoding="utf-8",
            )
            parsed = ssrfscope.parse_raw_request(str(path))
            self.assertEqual(parsed["method"], "POST")
            self.assertEqual(parsed["url"], "http://127.0.0.1:8787/api/fetch")
            self.assertIn(b'"url":"x"', parsed["body"])

    def test_dns_rebind_sequence_is_lab_safe(self):
        self.assertEqual(ssrfscope.validate_lab_ip("198.51.100.10"), "198.51.100.10")
        self.assertEqual(ssrfscope.validate_lab_ip("127.0.0.1"), "127.0.0.1")
        with self.assertRaises(ValueError):
            ssrfscope.validate_lab_ip("8.8.8.8")


if __name__ == "__main__":
    unittest.main()
