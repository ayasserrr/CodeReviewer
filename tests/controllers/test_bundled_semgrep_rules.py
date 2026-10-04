"""Runs the real semgrep binary over the bundled rulesets (skipped when semgrep is not installed).

A YAML or pattern error in a bundled rule file makes semgrep reject the whole
config, which silently turns the security scan off — so the rulesets are
exercised end to end here, against fixtures that each rule must catch.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from config import settings

pytestmark = pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")

_PYTHON = """\
import os
import requests
import random
import re
import tempfile
from datetime import datetime
from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.staticfiles import StaticFiles

app = FastAPI()
app.mount("/static/uploads", StaticFiles(directory="uploads"), name="uploads")
SECRET_KEY = os.getenv("SECRET_KEY", "secret")


async def upload(f: UploadFile):
    path = os.path.join("uploads", f.filename)
    with open(path, "wb") as out:
        out.write(await f.read())
    safe = os.path.join("uploads", os.path.basename(f.filename))
    return safe


def send(msg, name):
    msg.add_header("Content-Disposition", "attachment", filename=name)
    df.to_excel("out.xlsx")


def correct_years(text):
    current_year = datetime.now().year
    return re.sub(r"\\d{4}", lambda m: str(current_year), text)


def _generate_random_id():
    return str(random.randint(100000, 999999))


async def upload_endpoint(db, thread_id):
    if not await try_mark_job_in_progress(db, thread_id):
        return None


def _rerank_all_orders(pool):
    return pool


def extract_text(path):
    raw = open(path).read()
    return raw.lower()


def call():
    try:
        return requests.get("https://example.com")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
"""

_TSX = """\
import ExcelJS from 'exceljs'

const key = import.meta.env.VITE_API_KEY

export function Frame({ html }: { html: string }) {
  return <iframe sandbox="allow-same-origin allow-scripts" title="x" />
}

export async function exportRows(rows: string[][]) {
  const workbook = new ExcelJS.Workbook()
  const sheet = workbook.addWorksheet('Orders')
  rows.forEach((r) => sheet.addRow(r))
  return workbook.xlsx.writeBuffer()
}
"""


@pytest.fixture(scope="module")
def results(tmp_path_factory) -> dict:
    repo = tmp_path_factory.mktemp("sg")
    (repo / "app.py").write_text(_PYTHON)
    (repo / "web.tsx").write_text(_TSX)
    completed = subprocess.run(
        [
            "semgrep",
            "scan",
            "--json",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
            f"--config={settings.SEMGREP_CONFIG}",
            "app.py",
            "web.tsx",
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
    return json.loads(completed.stdout)


def _hits(results: dict) -> dict[str, list[int]]:
    hits: dict[str, list[int]] = {}
    for result in results["results"]:
        hits.setdefault(result["check_id"].rsplit(".", 1)[-1], []).append(result["start"]["line"])
    return hits


def test_rulesets_load_without_config_errors(results):
    config_errors = [
        e for e in results["errors"] if "Invalid" in str(e.get("message", "")) or e.get("level") == "error"
    ]
    assert config_errors == []
    assert Path(settings.SEMGREP_CONFIG, "web-security.yml").is_file()


@pytest.mark.parametrize(
    ("rule", "line"),
    [
        ("python-static-files-mount", 11),
        ("python-insecure-secret-default", 12),
        ("python-upload-filename-path-traversal", 16),
        ("python-content-disposition-header", 24),
        ("python-spreadsheet-export", 25),
        ("python-random-identifier", 34),
        ("python-claim-flag-or-lock", 38),
        ("python-whole-collection-recompute", 42),
        ("python-http-request-without-timeout", 53),
        ("python-exception-text-returned-to-client", 55),
        ("web-secret-in-client-env", 3),
        ("web-iframe-sandbox-escape", 6),
        ("web-spreadsheet-export", 11),
    ],
)
def test_rule_fires(results, rule, line):
    assert line in _hits(results).get(rule, []), _hits(results)


def test_basename_sanitizes_the_upload_filename(results):
    assert 19 not in _hits(results).get("python-upload-filename-path-traversal", [])
