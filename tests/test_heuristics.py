import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.detector.heuristics import evaluate_heuristics

client = TestClient(app)


class TestHeuristicsEngine:
    def test_legit_bank_domain_passes(self):
        res = evaluate_heuristics("https://vietcombank.com.vn")
        assert res["safety_score"] == 100
        assert res["verdict"] == "SAFE"
        assert res["is_trusted"] is True
        assert res["latency_ms"] < 25.0
        assert res["total_criteria"] == 21
        assert res["fail_count"] == 0

    def test_phishing_domain_fails_brand_and_criteria(self):
        res = evaluate_heuristics(
            "http://vietcombank-login-update.top/ebank/smartotp",
            dom={
                "has_otp_input": True,
                "sfh_risk": True,
                "favicon_external": True,
                "has_hidden_iframe": True
            }
        )
        assert res["safety_score"] < 40
        assert res["verdict"] == "DANGEROUS"
        failed_ids = [c["id"] for c in res["criteria"] if c["status"] == "FAIL"]
        assert "brand_spoofing" in failed_ids
        assert "sfh" in failed_ids
        assert "credential_harvesting" in failed_ids
        assert "https" in failed_ids
        assert "iframes" in failed_ids

    def test_ip_address_detection(self):
        res = evaluate_heuristics("http://185.220.101.5/login")
        failed_ids = [c["id"] for c in res["criteria"] if c["status"] == "FAIL"]
        assert "ip_address" in failed_ids

    def test_tiny_url_detection(self):
        res = evaluate_heuristics("https://bit.ly/scam-link")
        failed_ids = [c["id"] for c in res["criteria"] if c["status"] == "FAIL"]
        assert "tiny_url" in failed_ids

    def test_api_inspect_heuristics_endpoint(self):
        resp = client.post(
            "/api/v1/inspect-heuristics",
            json={
                "url": "https://mbbank.com.vn",
                "dom": {}
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["safety_score"] == 100
        assert "benchmark" in data
        assert len(data["criteria"]) == 21

    def test_compromised_blacklisted_domain_fails_criterion_21(self):
        resp = client.post(
            "/api/v1/inspect-heuristics",
            json={
                "url": "https://www.musictoyourhome.com/",
                "dom": {}
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["verdict"] == "DANGEROUS"
        assert data["safety_score"] < 40
        failed_ids = [c["id"] for c in data["criteria"] if c["status"] == "FAIL"]
        assert "blacklist_match" in failed_ids

    def test_inspect_page_blacklisted_domain_compromised(self):
        resp = client.post(
            "/api/v1/inspect-page",
            json={
                "url": "https://www.musictoyourhome.com/",
                "title": "Music To Your Home - Music Lessons NYC",
                "text_snippet": "Music lessons in NYC in your home or online.",
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["score"] >= 90
        assert data["is_scam"] is True
        assert data["signals"]["in_blacklist"] is True

    def test_brand_typosquatting_detection(self):
        # Transposition squatting: veitcombank instead of vietcombank
        res_transposition = evaluate_heuristics("http://veitcombank.net/login")
        failed_ids = [c["id"] for c in res_transposition["criteria"] if c["status"] == "FAIL"]
        assert "brand_spoofing" in failed_ids

        # Hyphenation squatting: viet-com-bank.xyz
        res_hyphen = evaluate_heuristics("https://viet-com-bank.xyz/portal")
        failed_ids_hyphen = [c["id"] for c in res_hyphen["criteria"] if c["status"] == "FAIL"]
        assert "brand_spoofing" in failed_ids_hyphen

        # Omission squatting: techcombnk
        res_omission = evaluate_heuristics("http://techcombnk.com/ebank")
        failed_ids_omission = [c["id"] for c in res_omission["criteria"] if c["status"] == "FAIL"]
        assert "brand_spoofing" in failed_ids_omission

        # Visual replacement (rn -> m) with subdomain/hyphen
        res_visual = evaluate_heuristics("http://vietcornbank-ebank.xyz/otp")
        failed_ids_visual = [c["id"] for c in res_visual["criteria"] if c["status"] == "FAIL"]
        assert "brand_spoofing" in failed_ids_visual

    def test_ssrf_protection_in_unshortener(self):
        from app.services.domain_intel import domain_intel
        # Loopback IPv4
        url_loopback, chain = domain_intel.resolve_multi_hop_redirects("http://127.0.0.1:8000/secret")
        assert url_loopback == "http://127.0.0.1:8000/secret"
        assert len(chain) == 1

        # Localhost
        url_local, chain_local = domain_intel.resolve_multi_hop_redirects("http://localhost:3000/api")
        assert url_local == "http://localhost:3000/api"
        assert len(chain_local) == 1

        # Cloud Metadata IP
        url_meta, chain_meta = domain_intel.resolve_multi_hop_redirects("http://169.254.169.254/latest/meta-data")
        assert url_meta == "http://169.254.169.254/latest/meta-data"
        assert len(chain_meta) == 1

        # Private LAN IP
        url_lan, chain_lan = domain_intel.resolve_multi_hop_redirects("http://192.168.1.1/admin")
        assert url_lan == "http://192.168.1.1/admin"
        assert len(chain_lan) == 1

        # Disallowed scheme
        is_safe, msg = domain_intel.is_safe_public_url("file:///etc/passwd")
        assert is_safe is False

    def test_vnptpay_and_play_app_googl_not_typosquatting(self):
        from app.detector.patterns.url_patterns import check_brand_impersonation
        # vnptpay.vn không bị gán nhầm là typosquatting vnpay
        r_vnpt = check_brand_impersonation("vnptpay.vn")
        assert r_vnpt["is_impersonation"] is False
        assert r_vnpt.get("is_authorized") is True

        # play.app.goo.gl không bị gán nhầm là typosquatting apple
        r_goo = check_brand_impersonation("play.app.goo.gl")
        assert r_goo["is_impersonation"] is False
        assert r_goo.get("is_authorized") is True


