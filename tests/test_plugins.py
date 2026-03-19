import unittest
from datetime import datetime, timedelta, timezone

from autopentest.models import EngagementRecord, HttpObservation, TargetRecord, TlsObservation
from autopentest.plugins.base import CheckContext
from autopentest.plugins.cookie_flags import CookieFlagsPlugin
from autopentest.plugins.security_headers import SecurityHeadersPlugin
from autopentest.plugins.tls_metadata import TlsMetadataPlugin


def make_context(
    *,
    headers: dict[str, list[str]] | None = None,
    final_url: str = "https://app.example.com",
    tls: TlsObservation | None = None,
) -> CheckContext:
    engagement = EngagementRecord(
        id=1,
        name="demo",
        description="",
        authorized_by="lead",
        ticket_id="SEC-1",
        owner="blue",
        allowed_hosts=["app.example.com"],
        allowed_prefixes=[],
        created_at="2026-01-01T00:00:00+00:00",
    )
    target = TargetRecord(
        id=2,
        engagement_id=1,
        url=final_url,
        label="app",
        created_at="2026-01-01T00:00:00+00:00",
    )
    http = HttpObservation(
        status_code=200,
        final_url=final_url,
        headers=headers or {},
        body_excerpt="ok",
    )
    return CheckContext(engagement=engagement, target=target, http=http, tls=tls)


class PluginTests(unittest.TestCase):
    def test_security_headers_plugin_reports_missing_headers(self) -> None:
        findings = SecurityHeadersPlugin().run(make_context())
        titles = {finding.title for finding in findings}
        self.assertIn("缺少 Content-Security-Policy 响应头", titles)
        self.assertIn("缺少 Strict-Transport-Security 响应头", titles)

    def test_cookie_plugin_reports_missing_flags(self) -> None:
        findings = CookieFlagsPlugin().run(
            make_context(headers={"set-cookie": ["sessionid=abc123; Path=/"]})
        )
        self.assertEqual(len(findings), 1)
        self.assertIn("Secure", findings[0].description)
        self.assertIn("未包含以下属性", findings[0].description)

    def test_tls_plugin_reports_expiring_certificate(self) -> None:
        expiry = datetime.now(timezone.utc) + timedelta(days=7)
        tls = TlsObservation(
            hostname="app.example.com",
            port=443,
            protocol="TLSv1.2",
            expires_at=expiry.isoformat(timespec="seconds"),
            expires_in_days=7,
            subject="CN=app.example.com",
            issuer="CN=Example CA",
        )
        findings = TlsMetadataPlugin().run(make_context(tls=tls))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "TLS 证书即将过期")


if __name__ == "__main__":
    unittest.main()
