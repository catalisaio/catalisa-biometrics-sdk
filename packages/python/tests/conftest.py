import json
import pathlib

import pytest

VECTORS = pathlib.Path(__file__).resolve().parents[3] / "vectors" / "vectors.json"


@pytest.fixture(scope="session")
def vectors():
    return json.loads(VECTORS.read_text(encoding="utf-8"))
