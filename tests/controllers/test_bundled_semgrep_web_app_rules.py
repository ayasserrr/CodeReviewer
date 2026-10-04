"""Bundled web-application rules (python-web-app.yml + the browser rules): each fires on its
defect and stays quiet on the safe variant next to it. Skipped when semgrep is not installed."""

import json
import os
import shutil
import subprocess

import pytest

from config import settings

pytestmark = pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")

_PYTHON = 'import jwt, tarfile, zipfile, shutil, sqlite3, logging, hmac\nfrom fastapi.responses import RedirectResponse\nfrom sqlalchemy.orm import sessionmaker\nlogger = logging.getLogger(__name__)\nSessionLocal = sessionmaker()\ndb = SessionLocal()                                   # BAD module-level session\nconn = sqlite3.connect("x.db")                        # BAD\n\ndef update_user(user, payload):\n    for key, value in payload.dict(exclude_unset=True).items():   # BAD mass assignment\n        setattr(user, key, value)\n\ndef create(payload):\n    return User(**payload.model_dump())               # BAD mass assignment\n\ndef go(request):\n    return RedirectResponse(request.query_params.get("next"))   # BAD open redirect\n\ndef delete(user, item):\n    assert user.id == item.owner_id, "forbidden"      # BAD assert guard\n    assert len(item.name) < 100                        # ok (not a guard word)\n\ndef login(resp, token):\n    resp.set_cookie("session", token)                  # BAD\n    resp.set_cookie("session", token, httponly=True, secure=True)   # ok\n\ndef verify(token, key):\n    jwt.decode(token, key)                             # BAD\n    jwt.decode(token, key, algorithms=["HS256"])       # ok\n\ndef check(api_key, provided):\n    if provided == api_key:                            # hmm: $A is provided -> not matched\n        return True\n    if api_key == provided:                            # BAD\n        return True\n    if api_key == None:                                # ok\n        return False\n    return hmac.compare_digest(api_key, provided)\n\ndef unpack(path):\n    tarfile.open(path).extractall("/tmp/x")            # BAD\n    tarfile.open(path).extractall("/tmp/x", filter="data")   # ok\n    zipfile.ZipFile(path).extractall("/tmp/x")         # BAD\n\ndef log_it(password, user):\n    logger.info(f"login {user} with {password}")       # BAD\n    logger.info("user %s", user)                       # ok\n\ndef fetch():\n    try:\n        risky()\n    except Exception:\n        pass                                           # BAD\n\ndef acc(items=[]):                                    # BAD\n    items.append(1)\n\ndef bill():\n    total_price = float("1.10")                        # BAD\n    ratio = float("0.5")                               # ok\n\ndef more(user, form, settings):\n    if user.password == form.password:                 # BAD plaintext\n        return 1\n    if form.token_type == "bearer":                    # ok\n        return 2\n    if settings.api_key != request_key:                # BAD\n        return 3\n'

_TS = 'const params = new URLSearchParams(window.location.search);\nwindow.location.href = params.get("next");\nparent.postMessage({token}, "*");\nwindow.addEventListener("message", (e) => { doIt(e.data); });\nwindow.addEventListener("message", (e) => { if (e.origin !== ORIGIN) return; doIt(e.data); });\n'


@pytest.fixture(scope="module")
def hits(tmp_path_factory) -> dict[str, list[int]]:
    repo = tmp_path_factory.mktemp("sgweb")
    (repo / "service.py").write_text(_PYTHON)
    (repo / "client.ts").write_text(_TS)
    completed = subprocess.run(
        [
            "semgrep",
            "scan",
            "--json",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
            f"--config={settings.SEMGREP_CONFIG}",
            "service.py",
            "client.ts",
        ],
        cwd=repo,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
        check=False,
        env={**os.environ, "SEMGREP_ENABLE_VERSION_CHECK": "0"},
    )
    assert completed.returncode in (0, 1), completed.stderr[-2000:]
    out = json.loads(completed.stdout)
    assert not [e for e in out["errors"] if e.get("level") == "error"], out["errors"]
    found: dict[str, list[int]] = {}
    for result in out["results"]:
        found.setdefault(result["check_id"].rsplit(".", 1)[-1], []).append(result["start"]["line"])
    return found


@pytest.mark.parametrize(
    ("rule", "fires", "quiet"),
    [
        ("python-module-level-db-session", [6, 7], [5]),
        ("python-mass-assignment", [10, 14], []),
        ("python-open-redirect", [17], []),
        ("python-assert-as-guard", [20], [21]),
        ("python-cookie-missing-flags", [24], [25]),
        ("python-jwt-decode-without-algorithms", [28], [29]),
        ("python-secret-compared-with-equality", [32, 34, 63, 67], [36, 65]),
        ("python-archive-extract-all", [41, 43], [42]),
        ("python-secret-written-to-log", [46], [47]),
        ("python-exception-swallowed", [50], []),
        ("python-mutable-default-argument", [55], []),
        ("python-float-for-money", [59], [60]),
        ("web-redirect-from-url-param", [2], []),
        ("web-postmessage-any-origin", [3, 4], [5]),
    ],
)
def test_rule_fires_on_the_defect_only(hits, rule, fires, quiet):
    lines = hits.get(rule, [])
    assert set(fires) <= set(lines), (rule, lines)
    assert not set(quiet) & set(lines), (rule, lines)
