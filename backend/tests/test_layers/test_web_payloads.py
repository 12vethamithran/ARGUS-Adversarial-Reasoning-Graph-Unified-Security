"""Unit tests for L1 web payload taxonomy + detection helpers."""
from app.layers import web_payloads as wp


def test_match_sql_error_engines():
    assert wp.match_sql_error(
        "You have an error in your SQL syntax; check the manual that "
        "corresponds to your MySQL server version") == "MySQL"
    assert wp.match_sql_error("PostgreSQL ERROR: unterminated quoted string") == "PostgreSQL"
    assert wp.match_sql_error("Microsoft SQL Server: Incorrect syntax near ''.") == "MSSQL"
    assert wp.match_sql_error("ORA-00933: SQL command not properly ended") == "Oracle"
    assert wp.match_sql_error("sqlite3.OperationalError: near \"'\": syntax error") == "SQLite"
    # A normal page must not match.
    assert wp.match_sql_error("<html><body>Welcome to our shop</body></html>") is None
    assert wp.match_sql_error("") is None


def test_traversal_signature():
    assert wp.TRAVERSAL_SIGNATURE.search("root:x:0:0:root:/root:/bin/bash")
    assert wp.TRAVERSAL_SIGNATURE.search("[fonts]\n[extensions]")
    assert not wp.TRAVERSAL_SIGNATURE.search("<html>not found</html>")


def test_cmdi_signature():
    assert wp.CMDI_SIGNATURE.search("uid=0(root) gid=0(root) groups=0(root)")
    assert not wp.CMDI_SIGNATURE.search("user id is unknown")


def test_stacktrace_signature():
    assert wp.STACKTRACE_SIGNATURE.search("Traceback (most recent call last):\n  File ...")
    assert wp.STACKTRACE_SIGNATURE.search("at com.app.Main(Main.java:42)")
    assert not wp.STACKTRACE_SIGNATURE.search("All systems operational")


def test_reflects_token():
    tok = wp.proof_token("xss")
    assert wp.reflects_token(f"<p>echo {tok}</p>", tok)
    assert not wp.reflects_token("<p>nothing here</p>", tok)
    assert not wp.reflects_token("", tok)


def test_body_similarity():
    base = "<html><body>Product list: A B C</body></html>"
    same = "<html><body>Product   list: A B C</body></html>"   # whitespace only
    diff = "<html><body>No results found</body></html>"
    assert wp.body_similarity(base, same) > 0.95
    assert wp.body_similarity(base, diff) < 0.8


def test_latency_confirms():
    # baseline 0.2s, delayed 5.4s, expecting a 5s sleep -> confirmed.
    assert wp.latency_confirms(0.2, 5.4, 5)
    # ordinary jitter must not confirm.
    assert not wp.latency_confirms(0.2, 0.9, 5)
    # expected delay is clamped to MAX_TIME_BASED_DELAY.
    assert wp.latency_confirms(0.0, wp.MAX_TIME_BASED_DELAY - 0.2, 30)


def test_ssti_payloads_have_expect_and_literal():
    for pd in wp.SSTI_PAYLOADS:
        assert pd["expect"] == "49"
        assert pd["literal"] == pd["payload"]
        assert pd["detect"] == "ssti_eval"


def test_taxonomy_payloads_well_formed():
    families = [wp.SQLI_PAYLOADS, wp.XSS_PAYLOADS, wp.TRAVERSAL_PAYLOADS,
               wp.CMDI_PAYLOADS, wp.SSTI_PAYLOADS, wp.SSRF_PAYLOADS,
               wp.OPEN_REDIRECT_PAYLOADS]
    seen_ids = set()
    for fam in families:
        assert fam, "payload family must be non-empty"
        for pd in fam:
            for key in ("id", "name", "family", "technique", "payload", "detect", "owasp"):
                assert key in pd, f"{pd.get('id')} missing {key}"
            assert pd["id"] not in seen_ids, f"duplicate id {pd['id']}"
            seen_ids.add(pd["id"])
            # time-based payloads never exceed the safety ceiling.
            if pd["detect"] == "time":
                assert pd["delay"] <= wp.MAX_TIME_BASED_DELAY


def test_time_based_delay_cap():
    for pd in wp.SQLI_PAYLOADS + wp.CMDI_PAYLOADS:
        if pd.get("detect") == "time":
            assert pd["delay"] <= wp.MAX_TIME_BASED_DELAY
