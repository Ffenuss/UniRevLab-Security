import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modkit.analyze.rules import load as load_rules          # noqa: E402
from modkit.dumper.dumpcs import DumpParser                   # noqa: E402
from modkit.selftest import fixtures                          # noqa: E402


@pytest.fixture(scope="session")
def inputs(tmp_path_factory) -> dict:
    return fixtures.write_all(tmp_path_factory.mktemp("target"))


# program/rules/plan are per-test on purpose: several tests mutate them (drop RVAs,
# tighten limits) and a session-scoped fixture would leak that into unrelated tests.
@pytest.fixture
def program(inputs):
    return DumpParser().parse_file(inputs["dump"])


@pytest.fixture
def rules():
    return load_rules(ROOT / "rules" / "default.json")


@pytest.fixture
def plan(program, rules):
    from modkit.analyze.features import analyze
    return analyze(program, rules)
