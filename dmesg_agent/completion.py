"""Shell completion for the dmesg-agent CLI (bash / zsh).

`dmesg-agent completion bash|zsh` prints a shell script. At Tab time that
script calls `dmesg-agent completion words ...`; this module introspects the
real argparse parsers (core diagnosis, learn, web) so candidates stay in sync
with the CLI instead of being a hand-maintained list.

Completion covers: subcommands at the top level, every option of the current
command, argparse choices (e.g. --provider), catalog ids for `learn --only`,
and file paths (left to the shell).
"""

from __future__ import annotations

import sys

BUILTIN_COMMANDS = ("config", "check", "eval", "cases", "score", "plugins",
                    "completion")


def _command_names() -> list[str]:
    names = set(BUILTIN_COMMANDS)
    try:
        from . import plugins as plugin_framework
        for meta in plugin_framework.load_plugins().all_meta():
            if meta.kind == "command":
                names.add(meta.name)
    except Exception:  # completion must never break the shell
        pass
    return sorted(names)


def _parsers() -> dict:
    parsers: dict = {}
    try:
        from .cli import build_parser
        parsers[""] = build_parser()
    except Exception:
        pass
    try:
        from .plugins.learn import build_parser as learn_parser
        parsers["learn"] = learn_parser()
    except Exception:
        pass
    try:
        from .plugins.web import build_parser as web_parser
        parsers["web"] = web_parser()
    except Exception:
        pass
    return parsers


def _option_strings(parser) -> list[str]:
    if parser is None:
        return []
    return [opt for action in parser._actions for opt in action.option_strings]


def _action_for(parser, option: str):
    if parser is None:
        return None
    for action in parser._actions:
        if option in action.option_strings:
            return action
    return None


def complete(words: list[str]) -> list[str]:
    """Candidates for a (possibly partial) command line, last word = prefix."""
    words = list(words)
    if words and words[0] == "dmesg-agent":
        words = words[1:]
    if not words:
        return _command_names()
    current = words[-1]
    prior = words[:-1]
    commands = _command_names()
    command = prior[0] if prior and prior[0] in commands else ""
    parsers = _parsers()
    parser = parsers.get(command) if command else parsers.get("")

    if command == "completion" and len(prior) == 1 \
            and not current.startswith("-"):
        return [shell for shell in ("bash", "zsh", "words")
                if shell.startswith(current)]

    if prior:
        previous = prior[-1]
        if command == "learn" and previous in ("--only", "--auto-only"):
            try:
                from .ingest_catalog import CATALOG
                ids = [entry["id"] for entry in CATALOG]
            except Exception:
                ids = []
            return [item for item in ids if item.startswith(current)] or ids
        action = _action_for(parser, previous)
        takes_value = (action is not None and action.nargs != 0
                       and action.const is None)
        if takes_value:
            if action.choices:
                return [str(choice) for choice in action.choices
                        if str(choice).startswith(current)]
            return []  # path value: let the shell complete files

    if current.startswith("-"):
        return [opt for opt in _option_strings(parser) if opt.startswith(current)]
    if not prior:
        return [name for name in commands if name.startswith(current)]
    return []


def bash_script() -> str:
    return """# dmesg-agent bash completion
_dmesg_agent_completion() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local -a args=("${COMP_WORDS[@]:1:$((COMP_CWORD - 1))}")
    local out
    out=$(dmesg-agent completion words "${args[@]}" "$cur" 2>/dev/null)
    COMPREPLY=()
    if [ -n "$out" ]; then
        mapfile -t COMPREPLY <<< "$out"
    fi
    local files
    files=$(compgen -f -- "$cur")
    if [ -n "$files" ]; then
        mapfile -t -O "${#COMPREPLY[@]}" COMPREPLY <<< "$files"
    fi
}
complete -o bashdefault -o default -F _dmesg_agent_completion dmesg-agent
"""


def zsh_script() -> str:
    return """#compdef dmesg-agent
_dmesg_agent_completion() {
    local -a candidates
    candidates=(${(f)"$(dmesg-agent completion words "${(@)words[2,CURRENT]}" 2>/dev/null)"})
    if (( ${#candidates} )); then
        compadd -a candidates
    else
        _files
    fi
}
compdef _dmesg_agent_completion dmesg-agent
"""


def completion_main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help", "help"):
        print("usage: dmesg-agent completion bash|zsh\n"
              "\n"
              "  bash:  eval \"$(dmesg-agent completion bash)\"\n"
              "  zsh:   eval \"$(dmesg-agent completion zsh)\"   # after compinit\n"
              "\n"
              "Permanent install:\n"
              "  bash: write the script to "
              "~/.local/share/bash-completion/completions/dmesg-agent\n"
              "  zsh:  write it to a directory in $fpath as _dmesg-agent")
        return 0
    if argv[0] == "words":
        words = argv[1:]
        if words and words[0] == "--":
            words = words[1:]
        try:
            for candidate in complete(words):
                print(candidate)
        except Exception:
            return 1
        return 0
    if argv[0] == "bash":
        print(bash_script())
        return 0
    if argv[0] == "zsh":
        print(zsh_script())
        return 0
    print(f"error: unsupported shell {argv[0]!r} (bash|zsh)", file=sys.stderr)
    return 2
