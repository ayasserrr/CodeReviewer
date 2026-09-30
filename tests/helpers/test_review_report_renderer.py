from helpers.review_report_renderer import _exposure_line, _verification_line
from utils import ReviewFinding
from utils.review import Verification


def _finding(severity, original):
    return ReviewFinding(
        id="SEC-1", category_id="security", severity=severity, confidence="high", title="t",
        description="d", impact="i", verification=Verification(verdict="adjusted", original_severity=original, note="n"),
    )


def test_adjusted_line_names_the_severity_change():
    assert _verification_line(_finding("High", "Critical")) == "*Verification:* severity adjusted Critical → High — n"


def test_adjustment_that_kept_the_severity_reads_as_confirmed():
    assert _verification_line(_finding("High", "High")) == "*Verification:* confirmed — n"


def test_exposure_line_only_for_findings_that_are_not_live():
    live = _finding("High", "High")
    assert _exposure_line(live) is None
    latent = live.model_copy(update={"exposure": "latent"})
    assert _exposure_line(latent).startswith("*Exposure:* latent — present in the code, not reachable")
