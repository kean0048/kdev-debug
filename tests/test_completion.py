from dmesg_agent.completion import bash_script, complete, zsh_script


def test_complete_top_level_commands():
    assert "learn" in complete(["le"])
    assert "completion" in complete(["comp"])


def test_complete_top_level_options():
    candidates = complete(["--know"])
    assert "--known-issues-db" in candidates
    assert "--knowledge-db" in candidates


def test_complete_learn_options_and_values():
    assert "--extract" in complete(["learn", "--ex"])
    ids = complete(["learn", "--only", "iwl"])
    assert "iwlwifi-firmware" in ids and "iwlwifi-be200" in ids
    providers = complete(["learn", "--provider", "l"])
    assert "local" in providers
    assert complete(["completion", ""]) == ["bash", "zsh", "words"]


def test_completion_scripts_reference_the_dispatcher():
    assert "dmesg-agent completion words" in bash_script()
    assert "complete -o" in bash_script()
    assert "#compdef dmesg-agent" in zsh_script()
    assert "compadd" in zsh_script()


def test_completion_command_prints_script(capsys):
    from dmesg_agent.cli import _run_cli
    assert _run_cli(["completion", "bash"]) == 0
    assert "complete -o" in capsys.readouterr().out
