import json

import pytest

from lasa_service.config import Configuration
from lasa_service.errors import LasaError

from .conftest import configuration, documents


def test_prompt_file_is_loaded_from_service_config_at_startup(tmp_path):
    raw = documents(tmp_path)
    prompts = dict(configuration(raw).prompts)
    prompts["execution_developer"] = "Execute the configured bounded task."
    prompt_path = tmp_path / "prompts.json"
    prompt_path.write_text(json.dumps(prompts), encoding="utf-8")
    raw["prompts_file"] = str(prompt_path)
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(raw), encoding="utf-8")

    loaded = Configuration.load(config_path, environ={"MODEL_KEY": "test-model-key"})
    prompt_path.unlink()

    assert loaded.prompts == prompts


@pytest.mark.parametrize(
    "changes",
    [
        {"integration": None},
        {"integration": "   "},
        {"assessment_developer": "Missing the required placeholder."},
        {"outcome_verfication": "Misspelled prompt key."},
    ],
)
def test_invalid_prompt_file_is_rejected_at_startup(tmp_path, changes):
    raw = documents(tmp_path)
    prompts = configuration(raw).prompts | changes
    prompt_path = tmp_path / "prompts.json"
    prompt_path.write_text(
        json.dumps({key: value for key, value in prompts.items() if value is not None}),
        encoding="utf-8",
    )
    raw["prompts_file"] = str(prompt_path)

    with pytest.raises(LasaError, match="invalid_input"):
        configuration(raw)
