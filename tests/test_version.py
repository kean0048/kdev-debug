import importlib.metadata
import re

from dmesg_agent import __version__


def test_version_is_pep440():
    assert re.fullmatch(r"\d+\.\d+\.\d+((a|b|rc)\d+)?(\.post\d+|\.dev\d+)?", __version__)


def test_installed_metadata_matches_package():
    # catches a stale/duplicated version: pyproject reads version dynamically
    # from dmesg_agent.__version__, so installed metadata must agree
    assert importlib.metadata.version("dmesg-agent") == __version__
