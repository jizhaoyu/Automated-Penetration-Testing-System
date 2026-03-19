import unittest

from autopentest.models import EngagementRecord
from autopentest.scope import assert_in_scope, canonicalize_url, host_matches, is_url_in_scope


class ScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engagement = EngagementRecord(
            id=1,
            name="demo",
            description="",
            authorized_by="lead",
            ticket_id="SEC-1",
            owner="blue",
            allowed_hosts=["*.example.com", "10.0.0.10"],
            allowed_prefixes=["https://portal.internal.local/admin"],
            created_at="2026-01-01T00:00:00+00:00",
        )

    def test_canonicalize_url(self) -> None:
        self.assertEqual(
            canonicalize_url("https://app.example.com/path#frag"),
            "https://app.example.com/path",
        )

    def test_host_matches_supports_wildcards(self) -> None:
        self.assertTrue(host_matches("*.example.com", "app.example.com"))
        self.assertTrue(host_matches("*.example.com", "example.com"))
        self.assertFalse(host_matches("*.example.com", "evil-example.com"))

    def test_scope_accepts_host_match(self) -> None:
        self.assertTrue(is_url_in_scope("https://api.example.com", self.engagement))

    def test_scope_accepts_prefix_match(self) -> None:
        self.assertTrue(is_url_in_scope("https://portal.internal.local/admin/users", self.engagement))

    def test_scope_rejects_out_of_scope(self) -> None:
        with self.assertRaises(ValueError):
            assert_in_scope("https://unauthorized.example.net", self.engagement)


if __name__ == "__main__":
    unittest.main()
