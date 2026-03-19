import http.client
import json
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from autopentest.storage import Storage
from autopentest.web import create_server


class _DemoTargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b"demo"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Set-Cookie", "sessionid=abc123; Path=/")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A003
        return


class WebApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.storage = Storage(self.db_path)
        self.storage.init_db()

        self.target_server = ThreadingHTTPServer(("127.0.0.1", 0), _DemoTargetHandler)
        self.target_server.daemon_threads = True
        self.target_server.block_on_close = False
        self.target_thread = threading.Thread(target=self.target_server.serve_forever, daemon=True)
        self.target_thread.start()

        self.app_server = create_server("127.0.0.1", 0, self.storage)
        self.app_thread = threading.Thread(target=self.app_server.serve_forever, daemon=True)
        self.app_thread.start()
        time.sleep(0.05)

    def tearDown(self) -> None:
        self.app_server.shutdown()
        self.app_server.server_close()
        self.app_thread.join(timeout=2)
        self.target_server.shutdown()
        self.target_server.server_close()
        self.target_thread.join(timeout=2)
        last_error = None
        for _ in range(20):
            try:
                self.temp_dir.cleanup()
                last_error = None
                break
            except PermissionError as exc:
                last_error = exc
                time.sleep(0.1)
        if last_error is not None:
            pass

    def test_health_endpoint(self) -> None:
        status, payload, _ = self.request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")
        self.assertTrue(payload["database"]["available"])

    def test_health_endpoint_reports_database_failure(self) -> None:
        with patch.object(self.storage, "connect", side_effect=RuntimeError("db down")):
            status, payload, _ = self.request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "degraded")
        self.assertFalse(payload["database"]["available"])

    def test_web_console_assets_are_served(self) -> None:
        status, body, content_type = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", content_type)
        self.assertIn('id="engagementForm"', body)

        status, body, content_type = self.request("GET", "/app.js")
        self.assertEqual(status, 200)
        self.assertTrue(
            "javascript" in content_type or "text/plain" in content_type,
            f"unexpected content type: {content_type}",
        )
        self.assertIn("const state =", body)

        status, body, content_type = self.request("GET", "/favicon.svg")
        self.assertEqual(status, 200)
        self.assertIn("image/svg+xml", content_type)
        self.assertIn("<svg", body)

    def test_web_console_sets_security_headers(self) -> None:
        connection = http.client.HTTPConnection("127.0.0.1", self.app_server.server_port, timeout=10)
        connection.request("GET", "/")
        response = connection.getresponse()
        response.read()
        self.assertEqual(response.status, 200)
        self.assertIn("frame-ancestors 'none'", response.getheader("Content-Security-Policy", ""))
        self.assertEqual(response.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.getheader("Referrer-Policy"), "strict-origin-when-cross-origin")
        self.assertEqual(response.getheader("X-Frame-Options"), "DENY")
        connection.close()

    def test_engagement_job_and_report_flow(self) -> None:
        target_url = f"http://127.0.0.1:{self.target_server.server_port}"

        status, engagement, _ = self.request(
            "POST",
            "/api/engagements",
            {
                "name": "UI Demo",
                "description": "demo",
                "authorized_by": "Security Lead",
                "ticket_id": "SEC-WEB-1",
                "owner": "Blue Team",
                "allowed_hosts": ["127.0.0.1"],
                "allowed_prefixes": [],
            },
        )
        self.assertEqual(status, 201)

        status, target, _ = self.request(
            "POST",
            f"/api/engagements/{engagement['id']}/targets",
            {"url": target_url, "label": "local-demo"},
        )
        self.assertEqual(status, 201)
        self.assertEqual(target["url"], target_url)

        status, job_payload, _ = self.request(
            "POST",
            f"/api/engagements/{engagement['id']}/jobs",
            {"requested_by": "tester"},
        )
        self.assertEqual(status, 201)
        self.assertEqual(job_payload["job"]["status"], "completed")
        self.assertGreaterEqual(job_payload["job"]["summary"]["finding_count"], 1)
        self.assertEqual(job_payload["job"]["summary"]["scanned_target_count"], 1)
        self.assertEqual(job_payload["job"]["summary"]["blocked_target_count"], 0)
        self.assertEqual(job_payload["job"]["summary"]["plugin_error_count"], 0)

        jobs_status, jobs_payload, _ = self.request("GET", f"/api/engagements/{engagement['id']}/jobs")
        self.assertEqual(jobs_status, 200)
        self.assertEqual(len(jobs_payload["items"]), 1)
        self.assertEqual(jobs_payload["items"][0]["id"], job_payload["job"]["id"])

        audit_status, audit_payload, _ = self.request("GET", f"/api/jobs/{job_payload['job']['id']}/audit-events")
        self.assertEqual(audit_status, 200)
        self.assertGreaterEqual(len(audit_payload["items"]), 2)
        self.assertIn("job_started", [item["event_type"] for item in audit_payload["items"]])
        self.assertIn("job_completed", [item["event_type"] for item in audit_payload["items"]])

        report_status, report_json, content_type = self.request(
            "GET",
            f"/api/jobs/{job_payload['job']['id']}/report?format=json",
        )
        self.assertEqual(report_status, 200)
        self.assertIn("application/json", content_type)
        self.assertEqual(report_json["job"]["id"], job_payload["job"]["id"])

        report_status, report_markdown, content_type = self.request(
            "GET",
            f"/api/jobs/{job_payload['job']['id']}/report?format=md",
        )
        self.assertEqual(report_status, 200)
        self.assertIn("text/markdown", content_type)
        self.assertIn("SEC-WEB-1", report_markdown)

    def test_scanning_built_in_console_has_no_missing_security_header_findings(self) -> None:
        target_url = f"http://127.0.0.1:{self.app_server.server_port}"

        status, engagement, _ = self.request(
            "POST",
            "/api/engagements",
            {
                "name": "Self Scan",
                "description": "scan built-in console",
                "authorized_by": "Security Lead",
                "ticket_id": "SEC-SELF-1",
                "owner": "Blue Team",
                "allowed_hosts": ["127.0.0.1"],
                "allowed_prefixes": [],
            },
        )
        self.assertEqual(status, 201)

        status, _, _ = self.request(
            "POST",
            f"/api/engagements/{engagement['id']}/targets",
            {"url": target_url, "label": "self-console"},
        )
        self.assertEqual(status, 201)

        status, job_payload, _ = self.request(
            "POST",
            f"/api/engagements/{engagement['id']}/jobs",
            {"requested_by": "tester"},
        )
        self.assertEqual(status, 201)
        self.assertEqual(job_payload["job"]["summary"]["finding_count"], 0)
        self.assertEqual(job_payload["findings"], [])

    def test_duplicate_target_returns_conflict(self) -> None:
        demo_url = f"http://127.0.0.1:{self.target_server.server_port}"
        status, engagement, _ = self.request(
            "POST",
            "/api/engagements",
            {
                "name": "Duplicate Target",
                "description": "duplicate target",
                "authorized_by": "Security Lead",
                "ticket_id": "SEC-DUP-1",
                "owner": "Blue Team",
                "allowed_hosts": ["127.0.0.1"],
                "allowed_prefixes": [],
            },
        )
        self.assertEqual(status, 201)

        first_status, _, _ = self.request(
            "POST",
            f"/api/engagements/{engagement['id']}/targets",
            {"url": demo_url, "label": "demo-target"},
        )
        self.assertEqual(first_status, 201)

        second_status, second_payload, _ = self.request(
            "POST",
            f"/api/engagements/{engagement['id']}/targets",
            {"url": demo_url, "label": "demo-target-2"},
        )
        self.assertEqual(second_status, 409)
        self.assertEqual(second_payload["error"], "同一任务下已存在相同目标 URL。")

    def test_error_semantics_for_unknown_and_bad_requests(self) -> None:
        status, payload, _ = self.request("GET", "/api/engagements/99999")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"], "未找到请求的资源")

        status, payload, _ = self.request("GET", "/api/jobs/99999")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"], "未找到请求的资源")

        status, payload, _ = self.request("DELETE", "/api/targets/99999")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"], "未找到请求的资源")

        status, payload, _ = self.request("POST", "/api/engagements", {"name": "bad"})
        self.assertEqual(status, 400)
        self.assertIn("allowed_hosts", payload["error"])

        status, payload, _ = self.request("POST", "/api/engagements/99999/jobs", {"requested_by": "tester"})
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"], "未找到请求的资源")

    def test_invalid_json_returns_bad_request(self) -> None:
        connection = http.client.HTTPConnection("127.0.0.1", self.app_server.server_port, timeout=10)
        connection.request(
            "POST",
            "/api/engagements",
            body=b"{not-json}",
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        connection.close()
        self.assertEqual(response.status, 400)
        self.assertEqual(payload["error"], "请求体不是合法的 JSON。")

    def test_unhandled_exception_returns_stable_internal_error(self) -> None:
        with patch.object(self.storage, "list_engagements", side_effect=RuntimeError("sensitive failure")):
            status, payload, _ = self.request("GET", "/api/engagements")
        self.assertEqual(status, 500)
        self.assertEqual(payload["error"], "服务器内部错误。")

    def test_job_failure_records_job_failed_audit_event(self) -> None:
        demo_url = f"http://127.0.0.1:{self.target_server.server_port}"
        status, engagement, _ = self.request(
            "POST",
            "/api/engagements",
            {
                "name": "Failure Audit",
                "description": "force failure",
                "authorized_by": "Security Lead",
                "ticket_id": "SEC-FAIL-1",
                "owner": "Blue Team",
                "allowed_hosts": ["127.0.0.1"],
                "allowed_prefixes": [],
            },
        )
        self.assertEqual(status, 201)

        status, _, _ = self.request(
            "POST",
            f"/api/engagements/{engagement['id']}/targets",
            {"url": demo_url, "label": "demo-target"},
        )
        self.assertEqual(status, 201)

        with patch("autopentest.orchestrator.fetch_http_observation", side_effect=RuntimeError("boom")):
            status, payload, _ = self.request(
                "POST",
                f"/api/engagements/{engagement['id']}/jobs",
                {"requested_by": "tester"},
            )
        self.assertEqual(status, 500)
        self.assertEqual(payload["error"], "服务器内部错误。")

        jobs_status, jobs_payload, _ = self.request("GET", f"/api/engagements/{engagement['id']}/jobs")
        self.assertEqual(jobs_status, 200)
        self.assertEqual(jobs_payload["items"][0]["status"], "failed")

        failed_job_id = jobs_payload["items"][0]["id"]
        audit_status, audit_payload, _ = self.request("GET", f"/api/jobs/{failed_job_id}/audit-events")
        self.assertEqual(audit_status, 200)
        self.assertIn("job_failed", [item["event_type"] for item in audit_payload["items"]])

    def test_delete_target_removes_findings_and_refreshes_job_summary(self) -> None:
        demo_url = f"http://127.0.0.1:{self.target_server.server_port}"

        status, engagement, _ = self.request(
            "POST",
            "/api/engagements",
            {
                "name": "Target Delete",
                "description": "delete target",
                "authorized_by": "Security Lead",
                "ticket_id": "SEC-DEL-TARGET-1",
                "owner": "Blue Team",
                "allowed_hosts": ["127.0.0.1"],
                "allowed_prefixes": [],
            },
        )
        self.assertEqual(status, 201)

        status, target, _ = self.request(
            "POST",
            f"/api/engagements/{engagement['id']}/targets",
            {"url": demo_url, "label": "demo-target"},
        )
        self.assertEqual(status, 201)

        status, job_payload, _ = self.request(
            "POST",
            f"/api/engagements/{engagement['id']}/jobs",
            {"requested_by": "tester"},
        )
        self.assertEqual(status, 201)
        self.assertGreater(job_payload["job"]["summary"]["finding_count"], 0)

        status, deleted, _ = self.request("DELETE", f"/api/targets/{target['id']}")
        self.assertEqual(status, 200)
        self.assertEqual(deleted["deleted_target_id"], target["id"])
        self.assertGreaterEqual(deleted["deleted_finding_count"], 1)

        status, targets_payload, _ = self.request("GET", f"/api/engagements/{engagement['id']}/targets")
        self.assertEqual(status, 200)
        self.assertEqual(targets_payload["items"], [])

        status, refreshed_job, _ = self.request("GET", f"/api/jobs/{job_payload['job']['id']}")
        self.assertEqual(status, 200)
        self.assertEqual(refreshed_job["job"]["summary"]["finding_count"], 0)
        self.assertEqual(refreshed_job["findings"], [])

    def test_delete_engagement_removes_nested_records_from_database(self) -> None:
        demo_url = f"http://127.0.0.1:{self.target_server.server_port}"

        status, engagement, _ = self.request(
            "POST",
            "/api/engagements",
            {
                "name": "Engagement Delete",
                "description": "delete engagement",
                "authorized_by": "Security Lead",
                "ticket_id": "SEC-DEL-ENG-1",
                "owner": "Blue Team",
                "allowed_hosts": ["127.0.0.1"],
                "allowed_prefixes": [],
            },
        )
        self.assertEqual(status, 201)

        status, _, _ = self.request(
            "POST",
            f"/api/engagements/{engagement['id']}/targets",
            {"url": demo_url, "label": "demo-target"},
        )
        self.assertEqual(status, 201)

        status, job_payload, _ = self.request(
            "POST",
            f"/api/engagements/{engagement['id']}/jobs",
            {"requested_by": "tester"},
        )
        self.assertEqual(status, 201)

        status, deleted, _ = self.request("DELETE", f"/api/engagements/{engagement['id']}")
        self.assertEqual(status, 200)
        self.assertEqual(deleted["deleted_engagement_id"], engagement["id"])
        self.assertEqual(deleted["deleted_job_count"], 1)
        self.assertEqual(len(self.storage.list_engagements()), 0)
        self.assertEqual(self.storage.list_targets(engagement["id"]), [])
        with self.assertRaises(ValueError):
            self.storage.get_engagement(engagement["id"])
        with self.assertRaises(ValueError):
            self.storage.get_job(job_payload["job"]["id"])

    def request(self, method: str, path: str, payload: dict[str, object] | None = None):
        connection = http.client.HTTPConnection("127.0.0.1", self.app_server.server_port, timeout=10)
        headers = {}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        content_type = response.getheader("Content-Type", "")
        raw = response.read()
        connection.close()
        if "application/json" in content_type:
            return response.status, json.loads(raw.decode("utf-8")), content_type
        return response.status, raw.decode("utf-8"), content_type


if __name__ == "__main__":
    unittest.main()
