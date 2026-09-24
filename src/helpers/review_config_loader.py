"""Loads and validates ``review_config.toml`` into a ``ReviewConfig``."""

import hashlib
import tomllib
from functools import cache
from pathlib import Path

from utils import InvalidInputError, ReviewConfig


def parse_review_config(raw: bytes) -> ReviewConfig:
    """Parse raw TOML bytes into a validated ``ReviewConfig``.

    Raises:
        InvalidInputError: If the TOML is malformed or fails schema validation.
    """
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise InvalidInputError(f"review_config: invalid TOML: {exc}") from exc

    static = data.get("static_analysis", {})
    try:
        return ReviewConfig.model_validate(
            {
                "review": data.get("review", {}),
                "static_tool_owners": static.get("owners", {}),
                "categories": data.get("categories", []),
                "security_kpis": data.get("security_kpis", []),
                "config_hash": hashlib.sha256(raw).hexdigest(),
            }
        )
    except ValueError as exc:
        raise InvalidInputError(f"review_config: {exc}") from exc


@cache
def load_review_config(path: str) -> ReviewConfig:
    """Load the review config at ``path`` once per process.

    Cached on the path — edit the file and restart to pick up changes (its
    hash is part of the review cache key, so stale cached reports are never
    served for a changed config).
    """
    return parse_review_config(Path(path).read_bytes())
