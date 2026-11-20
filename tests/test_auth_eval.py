"""Held-out labeled evaluation of the failures-then-success rules (ARG-AUTH-003 v2 + ARG-AUTH-004).
Labels live in fixtures/ground_truth/ and are read only by the evaluator, never by the detector."""
import sys

from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import auth_eval  # noqa: E402


def test_heldout_detections_preserved_and_benign_reduced():
    v1 = auth_eval.evaluate("heldout", "v1")
    v2 = auth_eval.evaluate("heldout", "v2")
    per = v2["per_scenario"]
    for sc in ("M1_fast_guessing", "M2_slow_guessing", "M3_guessing_with_interleaved_legit_user", "M4_rotating_source_per_attempt"):
        assert per[sc]["sequences_with_alert"] == per[sc]["identity_sequences"], sc  # no malicious sequence lost vs v1
    for sc in ("B1_typo_then_success", "B5_shared_nat_users", "B6_cross_tenant_same_username"):
        assert per[sc]["sequences_with_alert"] == 0, sc
    # residual ambiguity is surfaced, not hidden: own-device typos alert at LOW confidence only
    assert set(per["B2_many_typos_own_device"]["alert_confidence"]) == {"low"}
    assert v2["benign_sequences_alerted"] < v1["benign_sequences_alerted"]
    assert v2["malicious_sequences_alerted"] == v1["malicious_sequences_alerted"]
    assert v2["alerts_not_mapped_to_a_labeled_sequence"] == 0
