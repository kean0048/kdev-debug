import os

from dmesg_agent import paths


def test_data_dir_prefers_writable_xdg_data(tmp_path, monkeypatch, capsys):
    home = tmp_path / "home"
    (home / ".local" / "share").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
    monkeypatch.setattr(paths, "_warned", False)
    assert paths.data_dir() == home / ".local" / "share" / "dmesg-agent"
    assert "not writable" not in capsys.readouterr().err


def test_data_dir_falls_back_when_data_root_unwritable(tmp_path, monkeypatch, capsys):
    home = tmp_path / "home"
    blocked = home / "data" / "dmesg-agent"
    blocked.mkdir(parents=True)
    os.chmod(blocked, 0o500)  # readable but not writable (tests run unprivileged)
    state = home / "state"
    state.mkdir()
    monkeypatch.setenv("XDG_DATA_HOME", str(home / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(state))
    monkeypatch.setattr(paths, "_warned", False)
    try:
        chosen = paths.data_dir()
        assert chosen == state / "dmesg-agent"
        err = capsys.readouterr().err
        assert "not writable" in err and "chown" in err
    finally:
        os.chmod(blocked, 0o700)


def test_data_dir_uses_nonexistent_dir_under_writable_parent(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "share").mkdir(parents=True)
    monkeypatch.setenv("XDG_DATA_HOME", str(home / "share"))
    monkeypatch.setattr(paths, "_warned", False)
    assert paths.data_dir() == home / "share" / "dmesg-agent"
