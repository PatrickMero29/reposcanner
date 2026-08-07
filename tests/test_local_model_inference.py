import dataclasses

import pytest

import vulnscan.local_model.inference as inference_module
from vulnscan.config import settings as real_settings
from vulnscan.schemas import Language


@pytest.mark.asyncio
async def test_predict_returns_empty_when_no_checkpoint(tmp_path, monkeypatch):
    """Regardless of any real checkpoint sitting in the actual working
    directory, predict() must quietly return [] when pointed at a directory
    with no trained model — never raise."""
    fake_settings = dataclasses.replace(
        real_settings, local_model_checkpoint_dir=str(tmp_path / "no_checkpoint_here")
    )
    monkeypatch.setattr(inference_module, "settings", fake_settings)
    monkeypatch.setattr(inference_module, "_checkpoint_missing_logged", False)

    results = await inference_module.predict(code="def foo(): pass", function_name="foo", language=Language.PYTHON)
    assert results == []


def test_is_checkpoint_available_true_only_with_config_json(tmp_path, monkeypatch):
    checkpoint_dir = tmp_path / "checkpoint"
    checkpoint_dir.mkdir()
    fake_settings = dataclasses.replace(real_settings, local_model_checkpoint_dir=str(checkpoint_dir))
    monkeypatch.setattr(inference_module, "settings", fake_settings)

    assert inference_module.is_checkpoint_available() is False
    (checkpoint_dir / "config.json").write_text("{}")
    assert inference_module.is_checkpoint_available() is True


def test_severity_from_confidence_thresholds():
    from vulnscan.schemas import Severity
    assert inference_module._severity_from_confidence(0.95) == Severity.HIGH
    assert inference_module._severity_from_confidence(0.75) == Severity.MEDIUM
    assert inference_module._severity_from_confidence(0.55) == Severity.LOW
