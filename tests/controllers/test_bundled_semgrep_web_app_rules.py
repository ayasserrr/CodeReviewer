"""Bundled web-application rules (python-web-app.yml + the browser rules): each fires on its
defect and stays quiet on the safe variant next to it. Skipped when semgrep is not installed."""

import json
import os
import shutil
import subprocess

import pytest

from config import settings

pytestmark = pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")

_PYTHON = """\
import jwt, tarfile, zipfile, shutil, sqlite3, logging, hmac
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import sessionmaker
logger = logging.getLogger(__name__)
SessionLocal = sessionmaker()
db = SessionLocal()                                   # BAD module-level session
conn = sqlite3.connect("x.db")                        # BAD

def update_user(user, payload):
    for key, value in payload.dict(exclude_unset=True).items():   # BAD mass assignment
        setattr(user, key, value)

def create(payload):
    return User(**payload.model_dump())               # BAD mass assignment

def go(request):
    return RedirectResponse(request.query_params.get("next"))   # BAD open redirect

def delete(user, item):
    assert user.id == item.owner_id, "forbidden"      # BAD assert guard
    assert len(item.name) < 100                        # ok (not a guard word)

def login(resp, token):
    resp.set_cookie("session", token)                  # BAD
    resp.set_cookie("session", token, httponly=True, secure=True)   # ok

def verify(token, key):
    jwt.decode(token, key)                             # BAD
    jwt.decode(token, key, algorithms=["HS256"])       # ok

def check(api_key, provided):
    if provided == api_key:                            # hmm: $A is provided -> not matched
        return True
    if api_key == provided:                            # BAD
        return True
    if api_key == None:                                # ok
        return False
    return hmac.compare_digest(api_key, provided)

def unpack(path):
    tarfile.open(path).extractall("/tmp/x")            # BAD
    tarfile.open(path).extractall("/tmp/x", filter="data")   # ok
    zipfile.ZipFile(path).extractall("/tmp/x")         # BAD

def log_it(password, user):
    logger.info(f"login {user} with {password}")       # BAD
    logger.info("user %s", user)                       # ok

def fetch():
    try:
        risky()
    except Exception:
        pass                                           # BAD

def acc(items=[]):                                    # BAD
    items.append(1)

def bill():
    total_price = float("1.10")                        # BAD
    ratio = float("0.5")                               # ok

def more(user, form, settings):
    if user.password == form.password:                 # BAD plaintext
        return 1
    if form.token_type == "bearer":                    # ok
        return 2
    if settings.api_key != request_key:                # BAD
        return 3
"""

_TS = """\
const params = new URLSearchParams(window.location.search);
window.location.href = params.get("next");
parent.postMessage({token}, "*");
window.addEventListener("message", (e) => { doIt(e.data); });
window.addEventListener("message", (e) => { if (e.origin !== ORIGIN) return; doIt(e.data); });
"""


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
