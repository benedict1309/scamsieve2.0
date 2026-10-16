# File: tests/test_threat_feed_service.py
"""
Kiểm thử Dịch vụ Tự động Đồng bộ Tình báo Mối đe dọa (Threat Feed Service).
Bao gồm kiểm thử đơn vị, kiểm thử tích hợp SQLite và kiểm thử API Endpoints.
"""
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.database import SessionLocal
from app.models.enums import ContentType
from app.models.blacklist import Blacklist
from app.services.blacklist_service import threat_intel
from app.services.threat_feed_service import (
    clean_domain,
    threat_feed_service,
    ThreatFeedService,
)

client = TestClient(app)


class TestCleanDomain:
    def test_clean_domain_standard_url(self):
        assert clean_domain("https://bad-phishing-site.xyz/login?ref=123") == "bad-phishing-site.xyz"
        assert clean_domain("http://evil-malware.top:8080/payload.exe") == "evil-malware.top"
        assert clean_domain("sub.attack.org") == "sub.attack.org"

    def test_clean_domain_ignores_local_and_whitelist(self):
        assert clean_domain("http://localhost:8000/test") is None
        assert clean_domain("127.0.0.1") is None
        assert clean_domain("https://google.com/search") is None
        assert clean_domain("") is None
        assert clean_domain("# Comment line") is None


class TestThreatFeedService:
    def test_urlhaus_parsing_with_mock(self):
        mock_text_feed = (
            "# URLhaus Text Feed\n"
            "http://malware-drop-zone.com/bin.sh\n"
            "https://infected-host.net:8443/i\n"
            "# Another comment\n"
            "http://malware-drop-zone.com/dup\n"
        )
        service = ThreatFeedService(timeout_sec=5)
        with patch("requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = mock_text_feed
            mock_get.return_value = mock_resp

            results = service.fetch_urlhaus_domains(limit=10)
            domains = [r["domain"] for r in results]
            assert "malware-drop-zone.com" in domains
            assert "infected-host.net" in domains
            assert len(domains) == 2  # duplicate skipped

    def test_openphish_parsing_with_mock(self):
        mock_feed = (
            "https://fake-login-bank.xyz/auth\n"
            "http://steal-card-credentials.top/\n"
            "# Comment\n"
        )
        service = ThreatFeedService(timeout_sec=5)
        with patch("requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = mock_feed
            mock_get.return_value = mock_resp

            results = service.fetch_openphish_domains(limit=10)
            domains = [r["domain"] for r in results]
            assert "fake-login-bank.xyz" in domains
            assert "steal-card-credentials.top" in domains

    def test_offline_resilience_fallback(self):
        """Khi mất mạng hoàn toàn, service vẫn đồng bộ an toàn qua Offline Seeds không gây crash."""
        service = ThreatFeedService(timeout_sec=1)
        db = SessionLocal()
        try:
            with patch("requests.get", side_effect=Exception("No internet connection")):
                res = service.sync_all_feeds(db=db, limit_per_feed=10, include_offline_seeds=True)
                assert res["success"] is True
                assert res["total_domains_in_memory"] >= 9
                assert "musictoyourhome.com" in threat_intel._blacklist_domains
        finally:
            db.close()

    def test_api_v1_threat_intel_endpoints(self):
        admin_headers = {"X-Admin-API-Key": "psieve-admin-secret-key-2024"}

        # 1. Test POST sync endpoint without auth (must fail with 401)
        resp_unauth = client.post("/api/v1/threat-intel/sync", json={"limit_per_feed": 5})
        assert resp_unauth.status_code == 401

        # 2. Test POST sync endpoint with wrong key (must fail with 401)
        resp_wrong = client.post(
            "/api/v1/threat-intel/sync",
            json={"limit_per_feed": 5},
            headers={"X-Admin-API-Key": "wrong-key"}
        )
        assert resp_wrong.status_code == 401

        # 3. Test POST sync endpoint with valid key (must succeed with 200)
        resp_sync = client.post(
            "/api/v1/threat-intel/sync",
            json={"limit_per_feed": 5},
            headers=admin_headers
        )
        assert resp_sync.status_code == 200
        data_sync = resp_sync.json()
        assert data_sync["success"] is True
        assert "total_domains_in_memory" in data_sync
        assert data_sync["total_domains_in_memory"] > 0

        # 4. Test GET stats endpoint
        resp_stats = client.get("/api/v1/threat-intel/stats")
        assert resp_stats.status_code == 200
        data_stats = resp_stats.json()
        assert "total_domains_in_memory" in data_stats
        assert "total_domains_in_database" in data_stats
        assert "source_distribution" in data_stats

