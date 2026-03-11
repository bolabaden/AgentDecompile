from __future__ import annotations

from click.testing import CliRunner

from agentdecompile_cli.cli import main


def test_search_symbols_help_omits_result_limiter_flags() -> None:
    runner = CliRunner()

    result = runner.invoke(main, ["search-symbols", "--help"])

    assert result.exit_code == 0
    assert "--limit" not in result.output
    assert "--max-results" not in result.output


def test_references_help_omits_result_limiter_flags() -> None:
    runner = CliRunner()

    result = runner.invoke(main, ["references", "to", "--help"])

    assert result.exit_code == 0
    assert "--limit" not in result.output
    assert "--max-results" not in result.output


def test_list_imports_help_omits_result_limiter_flags() -> None:
    runner = CliRunner()

    result = runner.invoke(main, ["list", "imports", "--help"])

    assert result.exit_code == 0
    assert "--max-results" not in result.output


def test_search_symbols_rejects_limit_flag() -> None:
    runner = CliRunner()

    result = runner.invoke(
        main,
        ["search-symbols", "--program_path", "/test.exe", "--query", "main", "--limit", "5"],
    )

    assert result.exit_code != 0
    assert "No such option: --limit" in result.output


def test_references_rejects_limit_flag() -> None:
    runner = CliRunner()

    result = runner.invoke(
        main,
        ["references", "to", "--binary", "/test.exe", "--target", "main", "--limit", "5"],
    )

    assert result.exit_code != 0
    assert "No such option: --limit" in result.output


def test_list_imports_rejects_max_results_flag() -> None:
    runner = CliRunner()

    result = runner.invoke(
        main,
        ["list", "imports", "--binary", "/test.exe", "--max-results", "5"],
    )

    assert result.exit_code != 0
    assert "No such option: --max-results" in result.output