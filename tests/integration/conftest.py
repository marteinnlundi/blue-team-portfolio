"""Shared fixtures for the full-pipeline tests.

The tests run the real tools as subprocesses, exactly as a user would pipe
them together. Paths can be overridden with environment variables, which is
how CI points at binaries it has already built.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "tools"

GENERATE = TOOLS / "eventgen" / "generate.py"
SIGMA_LITE = TOOLS / "sigma-lite" / "main.py"
AUTH_ANOM = TOOLS / "auth-anom" / "main.py"
IOC_FEED_DIR = TOOLS / "ioc-feed"
IOC_FEED_CLI = Path(os.environ.get("IOC_FEED_CLI", IOC_FEED_DIR / "dist" / "cli.js"))
IOC_FEED_SAMPLE = IOC_FEED_DIR / "samples" / "feed.stix.json"


def pytest_configure(config):
    config.addinivalue_line("markers", "integration: full-pipeline tests that need the built tools")


@pytest.fixture(scope="session")
def logpipe_bin(tmp_path_factory):
    """Path to a logpipe binary: $LOGPIPE_BIN if set, otherwise built from source."""
    preset = os.environ.get("LOGPIPE_BIN")
    if preset:
        if not Path(preset).is_file():
            pytest.fail(f"LOGPIPE_BIN does not exist: {preset}")
        return preset

    if shutil.which("go") is None:
        pytest.skip("Go is not installed and LOGPIPE_BIN is not set")

    out = tmp_path_factory.mktemp("bin") / "logpipe"
    result = subprocess.run(
        ["go", "build", "-o", str(out), "./cmd/logpipe"],
        cwd=TOOLS / "logpipe",
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"Failed to build logpipe:\n{result.stderr}")
    return str(out)


@pytest.fixture(scope="session")
def ioc_feed_cmd():
    """Command prefix for ioc-feed, or skip when it has not been built."""
    node = shutil.which("node")
    if node is None or not IOC_FEED_CLI.is_file():
        pytest.skip("ioc-feed is not built (run: npm ci && npm run build in tools/ioc-feed)")
    return [node, str(IOC_FEED_CLI)]


@pytest.fixture(scope="session")
def python():
    return sys.executable
