"""FU-PARTNER-ISSUER-GUIDE — the issuer partner's guide is published, reachable, and every error `type` it can get
lands on an anchor of /errors.

The codes are the backend's (`zuppy/api_v2/partner/errors.py` PARTNER_ERRORS + the gate's 403s in
`zuppy/api_v2/partner/permissions.py`), copied here because this repo cannot import the backend: when the backend adds
a code, add it here and document it.
"""

import json
import os
import re

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
GUIDE = os.path.join(ROOT, "guides", "partner-issuer.mdx")

MOVEMENT_CODES = [
    "partner-reference-conflict",
    "partner-identity-conflict",
    "insufficient-balance",
    "partner-not-funded-on-chain",
    "partner-deactivated-during-request",
    "campaign-not-found",
    "campaign-not-creditable",
    "customer-not-identified",
    "invalid-quantity",
    "invalid-reference",
    "credit-limit-exceeded",
    "transfer-limit-exceeded",
    "invalid-transfer-destination",
    "invalid-transfer",
    "transfer-refused",
    "credit-refused",
    "movement-refused",
]
GATE_CODES = [
    "partner-key-required",
    "partner-key-inactive",
    "partner-key-ip-not-allowed",
    "partner-scope-undeclared",
    "partner-scope-insufficient",
    "partner-not-active",
    "partner-key-outside-partner-namespace",
]


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as handle:
        return handle.read()


def test_the_guide_is_in_the_navigation():
    pages = json.dumps(json.load(open(os.path.join(ROOT, "docs.json")))["navigation"])
    assert '"guides/partner-issuer"' in pages


@pytest.mark.parametrize("code", MOVEMENT_CODES + GATE_CODES)
def test_every_partner_code_is_in_the_guide(code):
    assert f"`{code}`" in read("guides", "partner-issuer.mdx")


@pytest.mark.parametrize("code", MOVEMENT_CODES)
def test_every_movement_error_type_has_an_anchor_on_the_errors_page(code):
    # The body's `type` is https://docs.zupy.com/errors#<error_code>: the anchor must exist.
    headings = re.findall(r"^#{2,3} (\S+)\s*$", read("errors.mdx"), flags=re.M)
    assert code in headings


def test_the_guide_covers_every_partner_route():
    guide = read("guides", "partner-issuer.mdx")
    for route in ["/api/v2/partner/profile/", "/api/v2/partner/credits/", "/api/v2/partner/credits/{credit_id}/",
                  "/api/v2/partner/transfers/"]:
        assert route in guide


def test_the_guide_says_empresa_never_restaurante():
    assert not re.search(r"restaura", read("guides", "partner-issuer.mdx"), flags=re.I)


def test_the_old_integration_onboarding_points_to_the_issuer_guide():
    assert "/guides/partner-issuer" in read("guides", "partner-onboarding.mdx")
