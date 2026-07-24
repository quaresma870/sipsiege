import json

from sipsiege.core.audit_log import AuditLog, verify_log_integrity


def test_empty_log_is_valid(tmp_path):
    path = tmp_path / "audit.jsonl"
    valid, broken_at, count = verify_log_integrity(path)
    assert valid
    assert broken_at is None
    assert count == 0


def test_record_and_verify_valid_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record("scenario:baseline_probe", "10.10.10.50", allowed=True)
    log.record("scenario:register_flood", "10.10.10.50", allowed=False, reason="no confirm")
    log.record("scenario:register_flood", "10.10.10.50", allowed=True, details={"rate": 50})

    valid, broken_at, count = verify_log_integrity(path)
    assert valid
    assert broken_at is None
    assert count == 3


def test_tampering_a_field_breaks_the_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record("scenario:baseline_probe", "10.10.10.50", allowed=True)
    log.record("scenario:register_flood", "10.10.10.50", allowed=True)
    log.record("scenario:register_flood", "10.10.10.50", allowed=True)

    lines = path.read_text().splitlines()
    entry = json.loads(lines[0])
    entry["target"] = "9.9.9.9"  # tamper first entry's content
    lines[0] = json.dumps(entry, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")

    valid, broken_at, count = verify_log_integrity(path)
    assert not valid
    assert broken_at == 1
    assert count == 0  # nothing verified before the very first entry


def test_tampering_a_later_entry_reports_correct_line(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record("scenario:a", "t1", allowed=True)
    log.record("scenario:b", "t1", allowed=True)
    log.record("scenario:c", "t1", allowed=True)

    lines = path.read_text().splitlines()
    entry = json.loads(lines[2])
    entry["target"] = "tampered"
    lines[2] = json.dumps(entry, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")

    valid, broken_at, count = verify_log_integrity(path)
    assert not valid
    assert broken_at == 3
    assert count == 2  # first two entries verify fine before the break


def test_reordering_entries_breaks_the_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record("scenario:a", "t1", allowed=True)
    log.record("scenario:b", "t1", allowed=True)

    lines = path.read_text().splitlines()
    lines = [lines[1], lines[0]]  # swap order
    path.write_text("\n".join(lines) + "\n")

    valid, broken_at, count = verify_log_integrity(path)
    assert not valid


def test_deleting_an_entry_breaks_the_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record("scenario:a", "t1", allowed=True)
    log.record("scenario:b", "t1", allowed=True)
    log.record("scenario:c", "t1", allowed=True)

    lines = path.read_text().splitlines()
    del lines[1]  # delete the middle entry
    path.write_text("\n".join(lines) + "\n")

    valid, broken_at, count = verify_log_integrity(path)
    assert not valid
    assert broken_at == 2
    assert count == 1


def test_truncating_most_recent_entries_is_not_detected():
    """
    Documents the known, inherent limitation stated in docs/legal-and-ethics.md:
    a pure hash chain can't detect truncation of the *most recent* entries,
    since nothing after the cut remains to reference what's missing. This
    test exists so that limitation stays true and visible, not silently
    "fixed" by an unrelated future change without updating the docs.
    """
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "audit.jsonl"
        log = AuditLog(path)
        log.record("scenario:a", "t1", allowed=True)
        log.record("scenario:b", "t1", allowed=True)
        log.record("scenario:c", "t1", allowed=True)

        lines = path.read_text().splitlines()
        path.write_text("\n".join(lines[:2]) + "\n")  # drop the last entry

        valid, broken_at, count = verify_log_integrity(path)
        assert valid  # truncation of the tail is NOT detected - this is expected
        assert count == 2
