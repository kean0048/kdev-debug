from dmesg_agent.cli import _run_cli, build_parser
from dmesg_agent.ingest_catalog import resolve_ids, selected_entries
from dmesg_agent.plugins.learn import build_parser as build_learn_parser
from dmesg_agent.plugins.learn import learn


def test_positional_log_path_parses():
    args = build_parser().parse_args(["dmesg.log", "-o", "report.md"])
    assert args.input == "dmesg.log"
    assert args.file is None


def test_learn_short_aliases_map_to_the_same_options():
    args = build_learn_parser().parse_args([
        "--max-mb", "64", "--max-queries", "2", "--since-year", "2024",
        "--only", "iwlwifi", "--extract"])
    assert args.auto_max_mb == 64
    assert args.auto_max_queries == 2
    assert args.auto_since_year == 2024
    assert args.auto_only == ["iwlwifi"]
    assert args.extract is True


def test_only_resolves_prefix_and_substring():
    resolved, unknown = resolve_ids(["iwlwifi"])
    assert {"iwlwifi-firmware", "iwlwifi-be200"} <= resolved
    assert unknown == []
    resolved, unknown = resolve_ids(["nope"])
    assert resolved == set() and unknown == ["nope"]
    assert selected_entries(0, set()) == []


def test_learn_list_prints_catalog_without_network(capsys):
    assert learn(["--list"]) == 0
    out = capsys.readouterr().out
    assert "iwlwifi-firmware" in out and "storage" in out


def test_unknown_command_keeps_helpful_error(capsys):
    assert _run_cli(["definitely-not-a-command-xyz"]) == 2
    assert "unknown command" in capsys.readouterr().err
