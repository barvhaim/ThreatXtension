"""Prompt template loading module."""

import glob
import os
from typing import Any, Dict
import yaml


def get_prompts(prompt_file: str = None) -> Dict[str, Any]:
    """Load and return prompt templates from YAML files in the prompts directory.

    Args:
        prompt_file: Optional specific prompt file name (without .yaml extension).
                    If provided, loads only that file. If None, loads all YAML files.

    Returns:
        Dictionary containing the loaded prompt templates.
    """
    prompts = {}

    current_dir = os.path.dirname(__file__)

    if prompt_file:
        if not prompt_file.endswith(".yaml"):
            prompt_file = f"{prompt_file}.yaml"

        yaml_file_path = os.path.join(current_dir, prompt_file)

        try:
            with open(yaml_file_path, "r", encoding="utf-8") as f:
                file_content = yaml.safe_load(f)
                if file_content:
                    prompts.update(file_content)
        except (yaml.YAMLError, IOError) as e:
            print(f"Warning: Failed to load {yaml_file_path}: {e}")

        return prompts

    # Every YAML is merged into one flat dict, so a top-level key duplicated across two
    # files silently overwrites — keep prompt keys unique.
    yaml_pattern = os.path.join(current_dir, "*.yaml")
    yaml_files = glob.glob(yaml_pattern)

    for yaml_file in yaml_files:
        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                file_content = yaml.safe_load(f)
                if file_content:
                    prompts.update(file_content)
        except (yaml.YAMLError, IOError) as e:
            # Continue loading other files even if one fails
            print(f"Warning: Failed to load {yaml_file}: {e}")

    return prompts
