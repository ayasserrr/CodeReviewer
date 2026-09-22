"""Tool availability bootstrap for Static Analysis + Security Engine.

Every one of the 10 required CLI tools must be resolvable before the
Static Analysis node touches the repository, the Discovery manifest, or
anything else. This module never attempts to install anything at
runtime — installing the tools is a build/deployment-time responsibility
(see pyproject.toml's ``analysis-tools`` dependency group for the 8
pip-installable tools, and ``src/assets/gitleaks[.exe]`` for the bundled
Go binary that isn't pip-installable).

``verify_tools_available`` and ``resolve_gitleaks_bin`` are both
``functools.cache``-wrapped module-level functions rather than instance
methods, so the check genuinely runs once per process — controllers are
constructed fresh per pipeline run (matching every other controller in
this codebase), so instance-level caching would not actually persist
across requests. ``functools.cache`` does not memoize exceptions, so a
failed check is retried on the next call rather than being cached forever;
that's intentional — once tools are actually installed, the very next
call succeeds without a process restart.
"""

import os
import shutil
from functools import cache

from config import settings
from utils import BootstrapError

REQUIRED_TOOLS: tuple[str, ...] = (
    "ruff",
    "pyright",
    "radon",
    "vulture",
    "lizard",
    "jscpd",
    "pip_audit",
    "semgrep",
    "bandit",
    "gitleaks",
)

# pip-audit's installed console script is spelled with a hyphen; every other
# tool key already matches its binary name.
_BINARY_NAMES: dict[str, str] = {"pip_audit": "pip-audit"}

_BUNDLED_GITLEAKS = os.path.join(
    str(settings.PROJECT_ROOT), "src", "assets", "gitleaks.exe" if os.name == "nt" else "gitleaks"
)


def _binary_name(tool: str) -> str:
    return _BINARY_NAMES.get(tool, tool)


@cache
def resolve_gitleaks_bin() -> str | None:
    """Resolve the gitleaks binary: bundled asset first, then PATH, else ``None``.

    Bundled-first so deployment never depends on gitleaks having been
    separately installed and put on PATH — it ships with the project.
    """
    if os.path.isfile(_BUNDLED_GITLEAKS):
        return _BUNDLED_GITLEAKS
    return shutil.which("gitleaks")


def _resolve(tool: str) -> bool:
    """True if ``tool`` is resolvable right now."""
    if tool == "gitleaks":
        return resolve_gitleaks_bin() is not None
    return shutil.which(_binary_name(tool)) is not None


@cache
def verify_tools_available() -> dict[str, bool]:
    """Check every required tool, once per process lifetime (on success).

    Returns:
        ``{tool_name: True}`` for all of ``REQUIRED_TOOLS`` — every value
        is always ``True``, since any ``False`` raises instead.

    Raises:
        BootstrapError: Listing every missing tool in one message (not
            just the first one found), so a broken environment can be
            fixed in one pass instead of one tool at a time.
    """
    missing = [tool for tool in REQUIRED_TOOLS if not _resolve(tool)]
    if missing:
        raise BootstrapError(
            "Missing required static-analysis/security tools: "
            f"{', '.join(missing)}. Install them before running the Static "
            "Analysis node — see pyproject.toml's 'analysis-tools' dependency "
            "group and src/assets/gitleaks for the bundled binary."
        )
    return {tool: True for tool in REQUIRED_TOOLS}
