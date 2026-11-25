from dmesg_agent.llm import parse_json_response


def test_plain():
    assert parse_json_response('{"summary": "ok", "findings": []}')["summary"] == "ok"


def test_fenced():
    assert parse_json_response('```json\n{"summary": "ok"}\n```')["summary"] == "ok"


def test_preamble():
    assert parse_json_response('好的,结果如下:\n{"summary": "ok"}')["summary"] == "ok"


def test_garbage():
    assert parse_json_response("我不确定") is None
    assert parse_json_response("") is None
    assert parse_json_response("[1,2") is None
    # 可修复的截断会带 flag,而不是被丢弃
    r = parse_json_response('{"broken": ')
    assert r == {"broken": None, "_repaired_truncation": True}


def test_non_dict_rejected():
    assert parse_json_response("[1,2,3]") is None


def test_truncated_repaired():
    s = '{"summary": "ok", "findings": [{"title": "x", "evidence": [{"line": 2, "quote": "abc'
    r = parse_json_response(s)
    assert r is not None and r["summary"] == "ok"
    assert r["findings"][0]["evidence"][0]["line"] == 2


def test_truncated_dangling_key():
    s = '{"summary": "ok", "findings": '
    r = parse_json_response(s)
    assert r is not None
