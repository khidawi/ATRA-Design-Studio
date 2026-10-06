"""
Tests for ingestion.py: text handling, quote verification, and a full run with the model stubbed.

    docker compose exec backend python -m tests.test_ingestion
"""
import sys
import time

import ingestion
from ingestion import has_obligation, html_to_text, normalise, quote_in_source, split_passages

PAGE = """<html><head><title>x</title><script>var a = 'shall not appear';</script></head><body><nav>Menu shall be skipped</nav>
<h1>Article 35</h1><p>Where a type of processing is likely to result in a high risk, the controller shall, prior to the
processing, carry out an assessment of the impact of the envisaged processing operations on the protection of personal data.</p>
<p>Some background without duties.</p></body></html>"""
QUOTE = "the controller shall, prior to the processing, carry out an assessment of the impact"


def test_html_to_text_drops_scripts_and_navigation():
    t = html_to_text(PAGE)
    assert "Article 35" in t and "controller shall" in t
    assert "var a" not in t and "Menu" not in t


def test_quote_must_appear_in_the_source_word_for_word():
    t = html_to_text(PAGE)
    assert quote_in_source(QUOTE, t)
    assert quote_in_source("The controller SHALL,  prior to the processing, carry out an assessment of the impact.", t)   # case, spacing, final dot
    assert not quote_in_source("the controller must carry out an impact assessment before processing begins", t)       # reworded
    assert not quote_in_source("shall", t)                                                                             # too short to prove anything


def test_typographic_punctuation_is_normalised():
    assert normalise("\u201cA\u2014B\u201d\u00a0c") == '"a-b" c'
    assert quote_in_source("the controller\u2019s duty \u2013 as stated here shall apply", "The controller's duty - as stated here shall apply.")


def test_passages_are_bounded_and_complete():
    text = "\n".join(f"Paragraph {i}. " + "word " * 120 for i in range(30))
    passages = split_passages(text, 2800)
    assert all(len(p) <= 2900 for p in passages) and len(passages) > 3
    assert "Paragraph 0." in passages[0] and "Paragraph 29." in passages[-1]
    assert len(split_passages("x" * 9000 + "\n" + "y", 2800)) >= 4                  # a long paragraph is cut, nothing lost


def test_obligation_filter():
    assert has_obligation("The provider shall ensure logging.") and not has_obligation("This section gives background.")


def test_private_addresses_are_refused():
    for url in ("http://127.0.0.1/x", "http://localhost:8765/health", "ftp://example.com/x", "http://169.254.169.254/latest"):
        try:
            ingestion.check_fetchable(url)
        except ValueError:
            continue
        raise AssertionError(url)


def test_full_run_keeps_only_verified_candidates():
    from db.models import IngestionRun, Regulation, Rule, RuleCandidate
    from db.session import SessionLocal
    from sqlalchemy import select

    text = html_to_text(PAGE) + "\n" + "Padding sentence that the provider shall keep. " * 6
    calls = []

    def fake(instrument, passage):
        calls.append(passage)
        return [{"title": "Impact assessment", "citation": "Art. 35", "quote": QUOTE, "severity": "REQUIRED"},
                {"title": "Invented", "citation": "Art. 99", "quote": "operators must register every model with the regulator within 24 hours", "severity": "REQUIRED"},
                {"title": "Same again", "citation": "Art. 35", "quote": QUOTE.upper(), "severity": "REQUIRED"}]

    real = ingestion.propose
    ingestion.propose = fake
    with SessionLocal() as s:
        reg = s.scalar(select(Regulation).where(Regulation.instrument == "GDPR"))
        run = IngestionRun(regulation_id=reg.id, source_url=None, source_kind="PASTE", status="RUNNING", model="stub",
                           passage_offset=0, passages_planned=1)
        s.add(run)
        s.commit()
        run_id = run.id
    try:
        ingestion.execute_run(run_id, text)
        with SessionLocal() as s:
            run = s.get(IngestionRun, run_id)
            cands = list(s.scalars(select(RuleCandidate).where(RuleCandidate.run_id == run_id)))
            assert run.status == "DONE", run.error
            assert (run.proposed, run.kept, run.dropped_unverified, run.dropped_duplicate) == (3, 1, 1, 1)
            assert len(cands) == 1 and cands[0].status == "PENDING" and cands[0].quote == QUOTE
            assert not s.scalar(select(Rule.id).where(Rule.source_quote == QUOTE))          # nothing is a rule until approved
    finally:
        ingestion.propose = real
        with SessionLocal() as s:
            s.delete(s.get(IngestionRun, run_id))                                           # cascades to the candidates
            s.commit()


def test_unreadable_source_fails_the_run_with_a_reason():
    from db.models import IngestionRun, Regulation
    from db.session import SessionLocal
    from sqlalchemy import select

    with SessionLocal() as s:
        reg = s.scalar(select(Regulation).where(Regulation.instrument == "GDPR"))
        run = IngestionRun(regulation_id=reg.id, source_url="http://127.0.0.1/x", source_kind="URL", status="RUNNING", model="stub",
                           passage_offset=0, passages_planned=1)
        s.add(run)
        s.commit()
        run_id = run.id
    ingestion.execute_run(run_id, None)
    with SessionLocal() as s:
        run = s.get(IngestionRun, run_id)
        assert run.status == "FAILED" and "private network" in run.error
        s.delete(run)
        s.commit()


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for n, f in tests:
        try:
            f()
            print("PASS ", n)
        except Exception as exc:
            failed += 1
            print("FAIL ", n, repr(exc))
    print(f"{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
