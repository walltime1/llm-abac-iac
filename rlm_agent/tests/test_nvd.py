"""Tests for NVD version-range checker."""

import pytest
from rlm_agent.encoder.nvd import (
    _normalize_to_upstream,
    _parse_version,
    _version_in_range,
    nvd_check_affects,
)


class TestNormalizeToUpstream:
    def test_debian_epoch_and_revision(self):
        assert _normalize_to_upstream("1:9.6p1-3ubuntu1") == "9.6"

    def test_pgdg_version(self):
        assert _normalize_to_upstream("16.2-1.pgdg22.04+1") == "16.2"

    def test_ubuntu_version(self):
        assert _normalize_to_upstream("1.24.0-2ubuntu1") == "1.24.0"

    def test_rpm_release(self):
        assert _normalize_to_upstream("5.5.68-1.el7") == "5.5.68"

    def test_openssh_portable_suffix(self):
        assert _normalize_to_upstream("9.6p1") == "9.6"

    def test_dfsg_suffix(self):
        assert _normalize_to_upstream("1.20.0+dfsg1") == "1.20.0"

    def test_plain_version(self):
        assert _normalize_to_upstream("2.4.49") == "2.4.49"

    def test_focal_suffix(self):
        assert _normalize_to_upstream("1.20.0-1~focal") == "1.20.0"


class TestVersionInRange:
    """Test _version_in_range against NVD cpeMatch structures."""

    def test_exact_match(self):
        match = {"criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}
        assert _version_in_range("2.4.49", match) is True
        assert _version_in_range("2.4.50", match) is False

    def test_wildcard_matches_all(self):
        match = {"criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                 "versionEndExcluding": "4.4"}
        assert _version_in_range("4.3", match) is True
        assert _version_in_range("4.4", match) is False
        assert _version_in_range("9.6", match) is False

    def test_range_inclusive(self):
        match = {"criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                 "versionStartIncluding": "8.6",
                 "versionEndIncluding": "9.8"}
        assert _version_in_range("8.6", match) is True
        assert _version_in_range("9.6", match) is True
        assert _version_in_range("9.8", match) is True
        assert _version_in_range("8.5", match) is False
        assert _version_in_range("9.9", match) is False

    def test_range_exclusive_end(self):
        match = {"criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                 "versionStartIncluding": "0.6.18",
                 "versionEndExcluding": "1.20.1"}
        assert _version_in_range("1.20.0", match) is True
        assert _version_in_range("1.20.1", match) is False
        assert _version_in_range("1.24.0", match) is False

    def test_semver_numeric_comparison(self):
        """GenericVersion got this wrong (lexicographic: 16.4 < 9.0)."""
        match = {"criteria": "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
                 "versionEndExcluding": "9.0.19"}
        assert _version_in_range("16.4", match) is False  # 16.4 > 9.0.19
        assert _version_in_range("8.4", match) is True    # 8.4 < 9.0.19

    def test_openssh_portable_stripped(self):
        """9.6p1 normalizes to 9.6 for range comparison."""
        match = {"criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                 "versionStartIncluding": "8.6",
                 "versionEndIncluding": "9.8"}
        assert _version_in_range("1:9.6p1-3ubuntu1", match) is True

    def test_debian_version_stripped(self):
        match = {"criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                 "versionStartIncluding": "0.6.18",
                 "versionEndExcluding": "1.20.1"}
        assert _version_in_range("1.20.0-1~focal", match) is True
        assert _version_in_range("1.24.0-2ubuntu1", match) is False

    def test_cpe_update_field_exact_match(self):
        """cpe:...:openssh:8.5:p1:... should match 8.5p1."""
        match = {"criteria": "cpe:2.3:a:openbsd:openssh:8.5:p1:*:*:*:*:*:*"}
        assert _version_in_range("8.5p1", match) is True
        assert _version_in_range("8.5", match) is True  # both normalize to 8.5


class TestNvdCheckAffects:
    """Integration tests using cached NVD data."""

    def test_unpinned_rejected(self):
        affects, reason = nvd_check_affects("CVE-2021-41773", "httpd", "")
        assert affects is False
        assert "no pinned version" in reason

    def test_unknown_rejected(self):
        affects, _ = nvd_check_affects("CVE-2021-41773", "httpd", "unpinned")
        assert affects is False

    @pytest.mark.timeout(30)
    def test_apache_2_4_49_affected(self):
        """CVE-2021-41773 affects exactly Apache 2.4.49."""
        affects, reason = nvd_check_affects("CVE-2021-41773", "httpd", "2.4.49-1")
        assert affects is True

    @pytest.mark.timeout(30)
    def test_nginx_1_20_0_affected(self):
        """CVE-2021-23017 affects nginx 0.6.18 – <1.20.1."""
        affects, _ = nvd_check_affects("CVE-2021-23017", "nginx", "1.20.0-1~focal")
        assert affects is True

    @pytest.mark.timeout(30)
    def test_nginx_1_24_0_not_affected(self):
        affects, _ = nvd_check_affects("CVE-2021-23017", "nginx", "1.24.0-2ubuntu1")
        assert affects is False

    @pytest.mark.timeout(30)
    def test_openssh_9_6_affected_by_regresshion(self):
        """CVE-2024-6387 affects OpenSSH 8.6–9.8."""
        affects, _ = nvd_check_affects("CVE-2024-6387", "openssh", "1:9.6p1-3ubuntu1")
        assert affects is True

    @pytest.mark.timeout(30)
    def test_openssh_9_9_not_affected(self):
        affects, _ = nvd_check_affects("CVE-2024-6387", "openssh", "1:9.9p1-3ubuntu1")
        assert affects is False

    @pytest.mark.timeout(30)
    def test_postgresql_16_not_affected_by_old_cve(self):
        """CVE-2015-0243 affects PostgreSQL <9.4.1 — not 16.4."""
        affects, _ = nvd_check_affects("CVE-2015-0243", "postgresql", "16.4-1.pgdg24.04+1")
        assert affects is False

    @pytest.mark.timeout(30)
    def test_cpe_product_mismatch(self):
        """CVE-2024-1597 is pgjdbc, not postgresql server."""
        affects, reason = nvd_check_affects("CVE-2024-1597", "postgresql", "16.2-1")
        assert affects is False
        assert "CPE product mismatch" in reason
