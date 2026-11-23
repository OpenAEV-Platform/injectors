from types import SimpleNamespace

from strix.helpers.strix_command_builder import StrixCommandBuilder


def _configs(**over):
    base = dict(
        scan_mode="deep",
        max_turns=60,
        max_budget_usd=None,
    )
    base.update(over)
    return SimpleNamespace(**base)


def test_build_basic_network_targets():
    args = StrixCommandBuilder(
        _configs(), content={}, targets=["https://a.example", "10.0.0.1"]
    ).build()
    assert args[:2] == ["strix", "--non-interactive"]
    assert args.count("--target") == 2
    assert "https://a.example" in args and "10.0.0.1" in args
    assert "--scan-mode" in args and args[args.index("--scan-mode") + 1] == "deep"
    assert args[args.index("--max-turns") + 1] == "60"
    assert "--max-budget" not in args


def test_blank_targets_skipped():
    args = StrixCommandBuilder(
        _configs(), content={}, targets=["  ", "https://ok"]
    ).build()
    assert args.count("--target") == 1


def test_scan_mode_override_from_content_wins():
    args = StrixCommandBuilder(
        _configs(scan_mode="deep"), content={"scan_mode": "quick"}, targets=["x"]
    ).build()
    assert args[args.index("--scan-mode") + 1] == "quick"


def test_scan_mode_override_as_list():
    args = StrixCommandBuilder(
        _configs(), content={"scan_mode": ["standard"]}, targets=["x"]
    ).build()
    assert args[args.index("--scan-mode") + 1] == "standard"


def test_invalid_override_falls_back_to_default():
    args = StrixCommandBuilder(
        _configs(scan_mode="standard"), content={"scan_mode": "bogus"}, targets=["x"]
    ).build()
    assert args[args.index("--scan-mode") + 1] == "standard"


def test_budget_and_instruction_included():
    args = StrixCommandBuilder(
        _configs(max_budget_usd=12.5),
        content={"instruction": "Focus on auth"},
        targets=["x"],
    ).build()
    assert args[args.index("--max-budget") + 1] == "12.5"
    assert args[args.index("--instruction") + 1] == "Focus on auth"


def test_blank_instruction_omitted():
    args = StrixCommandBuilder(
        _configs(), content={"instruction": "   "}, targets=["x"]
    ).build()
    assert "--instruction" not in args
