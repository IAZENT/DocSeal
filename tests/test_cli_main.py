from types import SimpleNamespace

import pytest

import docseal.cli.main as cli_main


def test_main_handles_keyboard_interrupt(monkeypatch):
    def raise_keyboard(args):
        raise KeyboardInterrupt()

    class FakeParser:
        def parse_args(self):
            return SimpleNamespace(func=raise_keyboard)

    monkeypatch.setattr(cli_main, "create_parser", lambda: FakeParser())

    with pytest.raises(SystemExit) as exc:
        cli_main.main()

    assert exc.value.code == 130


def test_main_handles_unexpected_exception(monkeypatch, capsys):
    def raise_error(args):
        raise RuntimeError("boom")

    class FakeParser:
        def parse_args(self):
            return SimpleNamespace(func=raise_error)

    monkeypatch.setattr(cli_main, "create_parser", lambda: FakeParser())

    with pytest.raises(SystemExit) as exc:
        cli_main.main()

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "[ERROR] boom" in captured.err


def test_main_success_exit_code_zero(monkeypatch):
    def ok(args):
        # do nothing
        return None

    class FakeParser:
        def parse_args(self):
            return SimpleNamespace(func=ok)

    monkeypatch.setattr(cli_main, "create_parser", lambda: FakeParser())

    with pytest.raises(SystemExit) as exc:
        cli_main.main()

    assert exc.value.code == 0
