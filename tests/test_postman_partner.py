"""FU-PARTNER-ISSUER-GUIDE — the Postman collection carries the issuer partner's routes.

The partner key only reaches /api/v2/partner/* (any other v2 route answers 403), so its folder authenticates with its
own variable, never the collection's `api_key`. Every body uses only the fields the backend serializers accept.
"""

import json
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
COLLECTION = os.path.join(HERE, "..", "postman", "zupy-partner-api.postman_collection.json")
ENVIRONMENT = os.path.join(HERE, "..", "postman", "zupy-production.postman_environment.json")
SPEC = os.path.join(HERE, "..", "api-reference", "openapi.json")

FOLDER = "Issuer Partner (Z$ credits and transfers)"
OPERATIONS = {
    ("GET", "/api/v2/partner/profile/"),
    ("GET", "/api/v2/partner/credits/"),
    ("POST", "/api/v2/partner/credits/"),
    ("GET", "/api/v2/partner/credits/{credit_id}/"),
    ("POST", "/api/v2/partner/transfers/"),
    ("GET", "/api/v2/partner/actions/"),  # Story 3.6
}


@pytest.fixture(scope="module")
def folder():
    collection = json.load(open(COLLECTION))
    found = [item for item in collection["item"] if item["name"] == FOLDER]
    assert found, f"missing folder {FOLDER!r}"
    return found[0]


def _path(request):
    raw = request["url"]["raw"].split("?")[0]
    return raw.replace("{{base_url}}", "").replace("{{credit_id}}", "{credit_id}")


def test_every_partner_operation_has_a_request(folder):
    seen = {(item["request"]["method"], _path(item["request"])) for item in folder["item"]}
    assert seen >= OPERATIONS
    assert {path for _, path in seen} <= {path for _, path in OPERATIONS}


def test_the_folder_authenticates_with_the_partner_key(folder):
    auth = {entry["key"]: entry["value"] for entry in folder["auth"]["apikey"]}
    assert auth == {"key": "X-API-Key", "value": "{{partner_api_key}}", "in": "header"}
    for item in folder["item"]:
        assert "auth" not in item["request"], f"{item['name']} overrides the folder auth"


@pytest.mark.parametrize("schema", ["PartnerCreditRequest", "PartnerTransferRequest"])
def test_bodies_use_only_serializer_fields(folder, schema):
    spec = json.load(open(SPEC))
    allowed = set(spec["components"]["schemas"][schema]["properties"])
    path = "/api/v2/partner/credits/" if schema == "PartnerCreditRequest" else "/api/v2/partner/transfers/"
    bodies = [
        json.loads(item["request"]["body"]["raw"])
        for item in folder["item"]
        if item["request"]["method"] == "POST" and _path(item["request"]) == path
    ]
    assert bodies
    for body in bodies:
        assert set(body) <= allowed, set(body) - allowed


def test_the_environment_has_the_partner_variables():
    keys = {value["key"] for value in json.load(open(ENVIRONMENT))["values"]}
    assert {"partner_api_key", "action_id", "credit_id"} <= keys  # Story 2.13: was campaign_id
    assert "campaign_id" not in keys
