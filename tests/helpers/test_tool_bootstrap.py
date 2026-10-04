from unittest.mock import patch

import pytest

from helpers import tool_bootstrap
from utils import BootstrapError


@pytest.fixture(autouse=True)
def _clear_bootstrap_caches():
    """Both checks are functools.cache-wrapped for real process-lifetime
    caching; tests need a clean slate each time or they'd see whatever the
    first test in the session happened to resolve."""
    tool_bootstrap.verify_tools_available.cache_clear()
    tool_bootstrap.resolve_gitleaks_bin.cache_clear()
    yield
    tool_bootstrap.verify_tools_available.cache_clear()
    tool_bootstrap.resolve_gitleaks_bin.cache_clear()


class TestResolveGitleaksBin:
    def test_prefers_bundled_asset_when_present(self):
        with patch("os.path.isfile", return_value=True):
            result = tool_bootstrap.resolve_gitleaks_bin()
        assert result == tool_bootstrap._BUNDLED_GITLEAKS

    def test_falls_back_to_path_when_bundled_missing(self):
        with patch("os.path.isfile", return_value=False), patch("shutil.which", return_value="/usr/bin/gitleaks"):
            result = tool_bootstrap.resolve_gitleaks_bin()
        assert result == "/usr/bin/gitleaks"

    def test_returns_none_when_both_missing(self):
        with patch("os.path.isfile", return_value=False), patch("shutil.which", return_value=None):
            result = tool_bootstrap.resolve_gitleaks_bin()
        assert result is None

    def test_result_is_cached_across_calls(self):
        with patch("os.path.isfile", return_value=True) as mock_isfile:
            tool_bootstrap.resolve_gitleaks_bin()
            tool_bootstrap.resolve_gitleaks_bin()
        assert mock_isfile.call_count == 1


class TestVerifyToolsAvailable:
    def test_all_present_returns_all_true(self):
        with patch("shutil.which", return_value="/usr/bin/tool"), patch("os.path.isfile", return_value=True):
            result = tool_bootstrap.verify_tools_available()
        assert result == {tool: True for tool in tool_bootstrap.REQUIRED_TOOLS}

    def test_raises_bootstrap_error_listing_every_missing_tool(self):
        missing = {"ruff", "pyright", "bandit"}

        def fake_which(binary_name: str):
            tool_by_binary = {"pip-audit": "pip_audit"}
            tool = tool_by_binary.get(binary_name, binary_name)
            return None if tool in missing else "/usr/bin/" + binary_name

        with (
            patch("shutil.which", side_effect=fake_which),
            patch("os.path.isfile", return_value=False),
            pytest.raises(BootstrapError) as exc_info,
        ):
            tool_bootstrap.verify_tools_available()

        message = str(exc_info.value)
        for tool in missing:
            assert tool in message
        # gitleaks resolves via resolve_gitleaks_bin (isfile=False, which=None -> also missing)
        assert "gitleaks" in message

    def test_pip_audit_resolved_via_hyphenated_binary_name(self):
        def fake_which(binary_name: str):
            return "/usr/bin/pip-audit" if binary_name == "pip-audit" else None

        # gitleaks resolves via the bundled asset (isfile=True), everything
        # else must resolve via the hyphenated "pip-audit" binary name.
        with (
            patch("shutil.which", side_effect=fake_which),
            patch("os.path.isfile", return_value=True),
            pytest.raises(BootstrapError) as exc_info,
        ):
            tool_bootstrap.verify_tools_available()
        assert "pip_audit" not in str(exc_info.value)

    def test_success_is_cached_and_not_rechecked(self):
        with (
            patch("shutil.which", return_value="/usr/bin/tool") as mock_which,
            patch("os.path.isfile", return_value=True),
        ):
            tool_bootstrap.verify_tools_available()
            tool_bootstrap.verify_tools_available()
        # one shutil.which() call per non-gitleaks tool, only on the first invocation
        assert mock_which.call_count == len(tool_bootstrap.REQUIRED_TOOLS) - 1

    def test_failure_is_not_cached_and_retried(self):
        with (
            patch("shutil.which", return_value=None),
            patch("os.path.isfile", return_value=False),
            pytest.raises(BootstrapError),
        ):
            tool_bootstrap.verify_tools_available()

        # resolve_gitleaks_bin() never raises (missing just means it returns
        # None), so functools.cache *does* memoize that outcome permanently —
        # by design, once resolved (even to "not found") it isn't rechecked
        # per analyze() call. Simulating "the environment got fixed" between
        # these two blocks means clearing that nested cache explicitly, same
        # as a real process restart would.
        tool_bootstrap.resolve_gitleaks_bin.cache_clear()

        with patch("shutil.which", return_value="/usr/bin/tool"), patch("os.path.isfile", return_value=True):
            result = tool_bootstrap.verify_tools_available()
        assert result == {tool: True for tool in tool_bootstrap.REQUIRED_TOOLS}
