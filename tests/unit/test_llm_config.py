from pathlib import Path

from mcpaegis.core.session import LLMConfig, load_dotenv


def _skip_repo_dotenv(monkeypatch) -> None:
    import mcpaegis.core.session as session_mod

    monkeypatch.setattr(session_mod, "_ENV_LOADED", True)


def test_from_env_reads_model(monkeypatch):
    _skip_repo_dotenv(monkeypatch)
    monkeypatch.setenv("MCPAEGIS_LLM_API_KEY", "sk-test")
    monkeypatch.setenv("MCPAEGIS_LLM_MODEL", "gpt-4.1")
    monkeypatch.delenv("MCPAEGIS_LLM_BASE_URL", raising=False)
    cfg = LLMConfig.from_env()
    assert cfg.enabled
    assert cfg.model == "gpt-4.1"
    assert cfg.api_key == "sk-test"


def test_explicit_model_overrides_env(monkeypatch):
    _skip_repo_dotenv(monkeypatch)
    monkeypatch.setenv("MCPAEGIS_LLM_API_KEY", "sk-test")
    monkeypatch.setenv("MCPAEGIS_LLM_MODEL", "gpt-4o-mini")
    cfg = LLMConfig.from_env(model="o4-mini")
    assert cfg.model == "o4-mini"


def test_missing_key_disables_llm(monkeypatch):
    _skip_repo_dotenv(monkeypatch)
    monkeypatch.delenv("MCPAEGIS_LLM_API_KEY", raising=False)
    monkeypatch.setenv("MCPAEGIS_LLM_MODEL", "gpt-4.1")
    cfg = LLMConfig.from_env()
    assert not cfg.enabled
    assert cfg.model == "gpt-4.1"


def test_load_dotenv_fills_missing_keys(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        "MCPAEGIS_LLM_API_KEY=sk-from-file\n"
        "MCPAEGIS_LLM_MODEL=qwen/qwen3.8-27b\n"
        "MCPAEGIS_LLM_BASE_URL=https://openrouter.ai/api/v1\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("MCPAEGIS_LLM_API_KEY", raising=False)
    monkeypatch.delenv("MCPAEGIS_LLM_MODEL", raising=False)
    monkeypatch.delenv("MCPAEGIS_LLM_BASE_URL", raising=False)
    import mcpaegis.core.session as session_mod

    monkeypatch.setattr(session_mod, "_ENV_LOADED", False)
    load_dotenv()
    cfg = LLMConfig.from_env()
    assert cfg.api_key == "sk-from-file"
    assert cfg.model == "qwen/qwen3.8-27b"
    assert cfg.base_url == "https://openrouter.ai/api/v1"


def test_process_env_wins_over_dotenv(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("MCPAEGIS_LLM_MODEL=from-file\n", encoding="utf-8")
    monkeypatch.setenv("MCPAEGIS_LLM_MODEL", "from-process")
    import mcpaegis.core.session as session_mod

    monkeypatch.setattr(session_mod, "_ENV_LOADED", False)
    load_dotenv()
    assert Path.cwd().joinpath(".env").is_file()
    cfg = LLMConfig.from_env(model=None)
    assert cfg.model == "from-process"
