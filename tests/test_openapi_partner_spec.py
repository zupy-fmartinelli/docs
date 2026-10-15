"""
Tests for the partner-facing OpenAPI spec in docs-mintlify.
Validates that the spec is clean, correct, and matches partner API requirements.
"""

import json
import os
import pytest

SPEC_PATH = os.environ.get(
    "OPENAPI_SPEC_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "api-reference", "openapi.json"),
)


@pytest.fixture
def spec():
    with open(SPEC_PATH) as f:
        return json.load(f)


class TestOpenAPISpecMetadata:
    def test_title_is_partner_api(self, spec):
        assert spec["info"]["title"] == "Zupy API v2"

    def test_version(self, spec):
        assert spec["info"]["version"] == "2.0.0"

    def test_openapi_version(self, spec):
        assert spec["openapi"] == "3.0.3"


class TestExcludedEndpoints:
    """AC 6: Excluded endpoints must NOT appear in partner spec."""

    EXCLUDED_KEYWORDS = [
        "scan",
        "dlocal",
        "whatsapp",
        "erase",
        "export",
        "reduce",
        "segment-counts",
    ]

    def test_no_excluded_endpoints(self, spec):
        for path in spec["paths"]:
            path_lower = path.lower()
            for keyword in self.EXCLUDED_KEYWORDS:
                assert keyword not in path_lower, f"Excluded endpoint found: {path} (matched: {keyword})"


class TestSecuritySchemes:
    """Partner spec should only have apiKeyAuth."""

    def test_only_api_key_auth(self, spec):
        schemes = spec["components"]["securitySchemes"]
        assert list(schemes.keys()) == ["apiKeyAuth"]

    def test_api_key_config(self, spec):
        scheme = spec["components"]["securitySchemes"]["apiKeyAuth"]
        assert scheme["type"] == "apiKey"
        assert scheme["in"] == "header"
        assert scheme["name"] == "X-API-Key"

    def test_no_jwt_in_endpoint_security(self, spec):
        for path, methods in spec["paths"].items():
            for method, details in methods.items():
                if method in ("get", "post", "put", "patch", "delete"):
                    security = details.get("security", [])
                    for sec_item in security:
                        assert "jwtAuth" not in sec_item, f"jwtAuth found on {method.upper()} {path}"
                        assert "cookieAuth" not in sec_item, f"cookieAuth found on {method.upper()} {path}"
                        assert "tokenAuth" not in sec_item, f"tokenAuth found on {method.upper()} {path}"


class TestPartnerEndpoints:
    """AC 1: All 23 partner endpoints must be present and no extras."""

    EXPECTED_PATHS = [
        ("POST", "/api/v2/auth/request-otp/"),
        ("POST", "/api/v2/auth/verify-otp/"),
        ("GET", "/api/v2/companies/"),
        ("GET", "/api/v2/companies/{id}/"),
        ("GET", "/api/v2/customers/"),
        ("GET", "/api/v2/customers/{id}/"),
        ("GET", "/api/v2/customers/{id}/points/"),
        ("GET", "/api/v2/customers/{id}/points/history/"),
        ("POST", "/api/v2/customers/{id}/points/add/"),
        ("POST", "/api/v2/customers/{id}/coupons/{coupon_id}/validate/"),
        ("POST", "/api/v2/customers/{id}/rewards/{reward_id}/redeem/"),
        ("GET", "/api/v2/customers/{id}/z-balance/"),
        ("GET", "/api/v2/loyalty/programs/"),
        ("GET", "/api/v2/loyalty/programs/{id}/"),
        ("GET", "/api/v2/rewards/"),
        ("GET", "/api/v2/rewards/{id}/"),
        ("GET", "/api/v2/rewards/coupons/"),
        ("POST", "/api/v2/wallet/notifications/"),
        ("GET", "/api/v2/wallet/passes/"),
        ("POST", "/api/v2/wallet/passes/coupons/"),
        ("POST", "/api/v2/wallet/passes/loyalty/"),
        ("GET", "/api/v2/wallet/passes/{pass_id}/status/"),
        ("POST", "/api/v2/webhooks/integrations/{partner}/"),
        # agency-partnership FU-PARTNER-ISSUER-GUIDE: the issuer partner's API (X-API-Key with partner.* scopes).
        ("GET", "/api/v2/partner/profile/"),
        ("GET", "/api/v2/partner/credits/"),
        ("POST", "/api/v2/partner/credits/"),
        ("GET", "/api/v2/partner/credits/{credit_id}/"),
        ("POST", "/api/v2/partner/transfers/"),
        # Story 3.6: the partner's actions (campaigns inside) by key.
        ("GET", "/api/v2/partner/actions/"),
    ]

    @pytest.mark.parametrize("method,path", EXPECTED_PATHS)
    def test_endpoint_present(self, spec, method, path):
        assert path in spec["paths"], f"Missing path: {path}"
        assert method.lower() in spec["paths"][path], f"Missing method {method} on {path}"

    def test_no_unexpected_paths(self, spec):
        expected = {path for _, path in self.EXPECTED_PATHS}
        actual = set(spec["paths"].keys())
        unexpected = actual - expected
        assert not unexpected, f"Unexpected paths in spec: {unexpected}"


class TestResponseEnvelope:
    """AC 3: Every endpoint response uses {data, meta} envelope."""

    def test_envelope_schemas_exist(self, spec):
        schemas = spec["components"]["schemas"]
        envelope_schemas = [name for name in schemas if name.startswith("Envelope")]
        assert len(envelope_schemas) >= 10, (
            f"Expected 10+ envelope schemas, found {len(envelope_schemas)}: {envelope_schemas}"
        )

    def test_envelope_has_data_and_meta(self, spec):
        schemas = spec["components"]["schemas"]
        for name, schema in schemas.items():
            if name.startswith("Envelope"):
                props = schema.get("properties", {})
                assert "data" in props, f"{name} missing 'data' property"
                assert "meta" in props, f"{name} missing 'meta' property"


class TestRFC7807Errors:
    """AC 4: Error responses use RFC 7807 format."""

    def test_error_schema_has_rfc7807_fields(self, spec):
        error_schema = spec["components"]["schemas"]["Error"]
        props = error_schema["properties"]
        for field in ["type", "title", "status", "detail", "instance"]:
            assert field in props, f"Error schema missing RFC 7807 field: {field}"

    def test_validation_error_schema(self, spec):
        schema = spec["components"]["schemas"]["ValidationError"]
        props = schema["properties"]
        assert "errors" in props, "ValidationError missing 'errors' field"
        for field in ["type", "title", "status", "detail"]:
            assert field in props, f"ValidationError missing: {field}"


class TestRedeemableFilter:
    """AC 7: Redeemable filter documented on rewards endpoint."""

    def test_redeemable_query_param(self, spec):
        rewards = spec["paths"]["/api/v2/rewards/"]["get"]
        params = rewards.get("parameters", [])
        param_names = [p["name"] for p in params]
        assert "redeemable" in param_names, "Missing redeemable query param"
        assert "customer_id" in param_names, "Missing customer_id query param"

    def test_redeemable_is_boolean(self, spec):
        rewards = spec["paths"]["/api/v2/rewards/"]["get"]
        params = rewards.get("parameters", [])
        redeemable = next(p for p in params if p["name"] == "redeemable")
        assert redeemable["schema"]["type"] == "boolean"
        assert redeemable["in"] == "query"


class TestEnrollmentUrl:
    """AC 8: enrollment_url visible in loyalty program responses."""

    def test_enrollment_url_in_schema(self, spec):
        lp_schema = spec["components"]["schemas"]["LoyaltyProgram"]
        assert "enrollment_url" in lp_schema["properties"], "LoyaltyProgram schema missing enrollment_url"

    def test_enrollment_url_format(self, spec):
        field = spec["components"]["schemas"]["LoyaltyProgram"]["properties"]["enrollment_url"]
        assert field.get("format") == "uri"


class TestZBalance:
    """AC 9: Z$ balance endpoint documented."""

    def test_z_balance_endpoint_exists(self, spec):
        path = "/api/v2/customers/{id}/z-balance/"
        assert path in spec["paths"]
        assert "get" in spec["paths"][path]

    def test_z_balance_schema(self, spec):
        zbal = spec["components"]["schemas"]["ZBalance"]
        props = zbal["properties"]
        assert "z_balance" in props
        assert "wallet_address" in props
        assert "has_wallet" in props


class TestNoOrphanedSchemas:
    """Verify no orphaned schemas referencing internal-only models."""

    INTERNAL_SCHEMAS = [
        "ActiveCoupon",
        "EnvelopeErasureResponse",
        "EnvelopeExportResponse",
        "EnvelopeExportStatusResponse",
        "EnvelopeScannerLookupResponse",
        "EnvelopeScannerPointsResponse",
        "ErasureResponse",
        "ErasureResponseStatusEnum",
        "ExportResponse",
        "ExportResponseStatusEnum",
        "ExportStatusResponse",
        "ExportStatusResponseStatusEnum",
        "OperationEnum",
        "PointsReduceRequest",
        "ScannerLookupRequest",
        "ScannerLookupResponse",
        "ScannerPointsRequest",
        "ScannerPointsResponse",
        "SegmentCountsResponse",
    ]

    def test_no_internal_schemas(self, spec):
        schemas = spec["components"]["schemas"]
        for name in self.INTERNAL_SCHEMAS:
            assert name not in schemas, f"Internal schema found: {name}"


class TestIssuerPartnerEndpoints:
    """FU-PARTNER-ISSUER-GUIDE: the issuer partner's routes, as the backend contract defines them, for the public."""

    PARTNER_OPERATIONS = [
        ("get", "/api/v2/partner/profile/", "partner_profile_retrieve"),
        ("get", "/api/v2/partner/credits/", "partner_credits_list"),
        ("post", "/api/v2/partner/credits/", "partner_credits_create"),
        ("get", "/api/v2/partner/credits/{credit_id}/", "partner_credits_retrieve"),
        ("post", "/api/v2/partner/transfers/", "partner_transfers_create"),
        ("get", "/api/v2/partner/actions/", "partner_actions_list"),
    ]
    # Internal vocabulary of the backend spec that must never reach the public reference.
    INTERNAL_MARKERS = ["AD-", "FR4", "FR3", "Story ", "context[", "``", "AD-13", "PartnerProfileService"]

    @pytest.mark.parametrize("method,path,operation_id", PARTNER_OPERATIONS)
    def test_operation_is_the_backend_one_with_the_partner_key_only(self, spec, method, path, operation_id):
        operation = spec["paths"][path][method]
        assert operation["operationId"] == operation_id
        assert operation["security"] == [{"apiKeyAuth": []}]
        assert operation["tags"] == ["Partner"]

    def test_the_partner_tag_is_declared(self, spec):
        assert "Partner" in [tag["name"] for tag in spec["tags"]]

    def test_every_referenced_schema_exists(self, spec):
        text = json.dumps(spec)
        import re

        for name in set(re.findall(r'"#/components/schemas/([A-Za-z0-9_]+)"', text)):
            assert name in spec["components"]["schemas"], f"dangling $ref: {name}"

    def test_no_internal_vocabulary_in_partner_operations_and_schemas(self, spec):
        public = {path: spec["paths"][path] for _, path, _ in self.PARTNER_OPERATIONS}
        schemas = {
            name: body
            for name, body in spec["components"]["schemas"].items()
            if name.startswith(("PartnerCredit", "PartnerTransfer", "PartnerProfile", "PartnerFeatures",
                                "PartnerConditions", "PaginatedPartnerCredit", "PartnerAction", "PartnerCustomer"))
        }
        text = json.dumps([public, schemas], ensure_ascii=False)
        for marker in self.INTERNAL_MARKERS:
            assert marker not in text, f"internal marker in the public partner reference: {marker!r}"

    def test_the_credit_request_and_response_fields_are_the_serializers(self, spec):
        schemas = spec["components"]["schemas"]
        # Story 2.13: action_id (was campaign_id) and the optional user data that only fills what is empty.
        profile = {"birth_date", "gender", "address"}
        assert set(schemas["PartnerCreditRequest"]["properties"]) == {
            "action_id", "quantity", "external_reference", "phone", "email", "cpf", "wallet_address", "name",
        } | profile
        assert "action_id" in schemas["PartnerCreditRequest"]["required"]
        assert set(schemas["PartnerCredit"]["properties"]) == {
            "id", "external_reference", "action_id", "quantity", "unit", "unit_value", "amount", "customer_id",
            "status", "created_at",
        }
        # Story 6.2 (GR23): the transfer may record an action; the reason left "required" (it may be omitted with one).
        assert set(schemas["PartnerTransferRequest"]["properties"]) == {
            "amount", "external_reference", "reason", "phone", "email", "cpf", "wallet_address", "name", "company_id",
            "action_id", "quantity",
        } | profile
        assert "reason" not in schemas["PartnerTransferRequest"]["required"]
        assert {"action_id", "action_name", "quantity", "unit"} <= set(schemas["PartnerTransfer"]["required"])

    def test_story_2_13_no_campaign_id_in_the_partner_reference(self, spec):
        public = {path: spec["paths"][path] for _, path, _ in self.PARTNER_OPERATIONS}
        schemas = {name: body for name, body in spec["components"]["schemas"].items() if name.startswith("Partner")}
        text = json.dumps([public, schemas], ensure_ascii=False)
        assert "campaign_id" not in text
        assert "campaign-not-" not in text


def test_the_profile_has_the_wallet_balance(spec):
    """Story 3.6 (AC8): the balance of the wallet, a snapshot, in the profile."""
    assert "wallet_balance" in spec["components"]["schemas"]["PartnerProfile"]["properties"]


def test_the_action_item_is_the_panels(spec):
    assert set(spec["components"]["schemas"]["PartnerAction"]["properties"]) == {
        "id", "name", "status", "action_type", "unit_value", "per_user_limit", "per_user_period", "budget_total",
        "budget_spent", "starts_at", "ends_at",
    }


def test_story_6_2_the_actions_list_is_declared_paginated(spec):
    """Story 6.2 (AC7): the API always answered {count, next, previous, results}; the reference said a bare array."""
    operation = spec["paths"]["/api/v2/partner/actions/"]["get"]
    schema = operation["responses"]["200"]["content"]["application/json"]["schema"]
    assert schema == {"$ref": "#/components/schemas/PaginatedPartnerActionList"}
    page = spec["components"]["schemas"]["PaginatedPartnerActionList"]
    assert set(page["properties"]) == {"count", "next", "previous", "results"}
    assert page["properties"]["results"]["items"] == {"$ref": "#/components/schemas/PartnerAction"}
    assert {parameter["name"] for parameter in operation["parameters"]} == {"cursor", "page_size", "status"}
