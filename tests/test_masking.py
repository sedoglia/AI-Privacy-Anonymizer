from privacy_anonymizer.masking import build_masking_plan
from privacy_anonymizer.models import DetectionSpan


def test_build_masking_plan_returns_replacements() -> None:
    plan = build_masking_plan("email mario.rossi@example.com", [DetectionSpan(6, 29, "EMAIL", "pattern")])

    assert plan.text == "email [EMAIL_1]"
    assert plan.replacements[0].original == "mario.rossi@example.com"
    assert plan.replacements[0].replacement == "[EMAIL_1]"
