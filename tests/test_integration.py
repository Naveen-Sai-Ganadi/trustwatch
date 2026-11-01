"""End-to-end checks against real software. Each test skips when its dependency is not available on this machine."""
import re
import shutil
import subprocess
import sys

import pytest

from trustwatch import feed as feedmod
from trustwatch.analyze import analyze
from trustwatch.image import scan_image
from trustwatch.osverify import macos_verifier


def have_image(ref: str) -> bool:
    return bool(shutil.which("docker")) and subprocess.run(["docker", "image", "inspect", ref], capture_output=True).returncode == 0


@pytest.fixture(scope="module")
def real():
    return feedmod.load()


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
def test_macos_verifier_answers_for_every_chain(real):
    s = macos_verifier()
    ev = real.events[0]
    answers = [s.verifier(h, c, ev.verify_time(c)) for h, c in ev.test_chains]
    assert None not in answers  # the verifier gave a definite verdict for each chain
    assert answers.count(False) >= 1  # Apple blocks at least part of the incident


@pytest.mark.skipif(not have_image("eclipse-temurin:21-jre"), reason="docker image eclipse-temurin:21-jre not present")
def test_jdk_image_reads_cacerts_blocklist_and_policies(real):
    stores, _ = scan_image("eclipse-temurin:21-jre", real)
    java = next(s for s in stores if s.kind == "java")
    assert len(java.certs) > 100 and len(java.blocked) > 10
    assert "ENTRUST_TLS" in java.distrust_policies and java.version
    # Roots the JDK distrusts itself (Entrust and others) are not reported; others Mozilla limits still are.
    partial = [c for f in analyze(java, real).findings if f.code == "PARTIAL_DISTRUST" for c in f.certs]
    assert not [c for c in partial if re.search(r"entrust|affirmtrust|symantec|chunghwa", c, re.I)], partial


@pytest.mark.skipif(not have_image("oven/bun:1-slim"), reason="docker image oven/bun:1-slim not present")
def test_bun_image_compiled_roots_found(real):
    stores, _ = scan_image("oven/bun:1-slim", real)
    bun = next(s for s in stores if s.location == "/usr/local/bin/bun")
    assert bun.kind == "embedded" and len(bun.certs) > 100 and bun.version
