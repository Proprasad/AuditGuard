"""Memory Policy & Reflexion Loop Tests"""
from src.memory.store import LongTermMemoryStore, ReflexionLesson, trim_messages_with_summary
from src.reflexion.loop import run_dev_reflexion


def test_short_term_rolling_12_message_window():
    msgs = [{"role": "user", "content": f"message {i}"} for i in range(18)]
    trimmed, summary = trim_messages_with_summary(msgs, "", window_size=12)
    assert len(trimmed) == 12
    assert trimmed[0]["content"] == "message 6"
    assert "message 0" in summary


def test_long_term_memory_approval_gate_and_forget_api():
    store = LongTermMemoryStore()
    store.save_entity_profile("CUST-101", {"risk": "LOW", "gst": "ACTIVE"})
    assert store.save_case_episode("CUST-101", {"case_id": "C1"}, human_approved=False) is False
    assert store.save_case_episode("CUST-101", {"case_id": "C1"}, human_approved=True) is True
    assert len(store.get_case_episodes("CUST-101")) == 1

    res = store.forget_customer("CUST-101")
    assert res["profile_removed"] is True
    assert res["episodes_removed"] == 1
    assert store.get_entity_profile("CUST-101") is None
    assert store.get_case_episodes("CUST-101") == []


def test_reflexion_dev_only_and_human_review_freeze():
    store = LongTermMemoryStore()
    cases = {
        "CASE-0001": {"case_id": "CASE-0001", "category": "staggered_timing", "expected_disposition": "escalate_str", "is_held_out": False},
        "CASE-0002": {"case_id": "CASE-0002", "category": "staggered_timing", "expected_disposition": "escalate_str", "is_held_out": True},
    }
    eval_results = [
        {"case_id": "CASE-0001", "correct": False, "actual": "request_info"},
        {"case_id": "CASE-0002", "correct": False, "actual": "request_info"},
    ]
    lessons = run_dev_reflexion(eval_results, cases, store=store)
    # Held-out case must be ignored by Reflexion
    assert len(lessons) == 1
    assert store.review_lesson(lessons[0].lesson_id, approve=True, rationale="Valid heuristic") is True

    store.freeze_playbook()
    assert store.add_lesson(
        ReflexionLesson(
            lesson_id="LES-FROZEN",
            trigger_precondition="x",
            observed_failure="y",
            actionable_rule="z",
        )
    ) is False
