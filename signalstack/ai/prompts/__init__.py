"""
Prompt templates live as plain .txt files in this folder so they are
trivially editable and versionable in git. `load_prompt(name)` reads
them on demand. Later we can move them into the ss_prompt_templates
table for in-app editing without changing this interface.
"""
import os

_HERE = os.path.dirname(__file__)


def load_prompt(name: str) -> str:
    path = os.path.join(_HERE, f"{name}.txt")
    if not os.path.exists(path):
        raise FileNotFoundError(f"Prompt template not found: {name}")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()
