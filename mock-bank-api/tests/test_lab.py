from __future__ import annotations

from contextlib import contextmanager

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


@contextmanager
def lab_client(**overrides):
    settings = Settings(database_url="sqlite://", **overrides)
    with TestClient(create_app(settings)) as client:
        yield client


def login(client: TestClient, email: str) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "demo1234"},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_role_boundaries_are_enforced_even_with_bugs_on():
    with lab_client() as client:
        teen_headers = login(client, "teen.a@finshield.dev")
        response = client.post(
            "/api/v1/family/allowance",
            headers=teen_headers,
            json={"teen_id": "usr_teen_a", "daily_limit_cents": 1, "blocked_mccs": []},
        )
        assert response.status_code == 403


def test_parent_can_only_touch_own_teen_when_bola_toggle_is_off():
    with lab_client(enable_bola_bug=False) as client:
        headers = login(client, "parent.a@finshield.dev")
        assert client.get("/api/v1/family/allowance/usr_teen_b", headers=headers).status_code == 403
        assert (
            client.post(
                "/api/v1/family/allowance",
                headers=headers,
                json={"teen_id": "usr_teen_b", "daily_limit_cents": 1, "blocked_mccs": []},
            ).status_code
            == 403
        )


def test_bola_toggle_leaks_and_rewrites_another_family_allowance():
    with lab_client(enable_bola_bug=True) as client:
        headers = login(client, "parent.a@finshield.dev")
        read = client.get("/api/v1/family/allowance/usr_teen_b", headers=headers)
        assert read.status_code == 200
        assert read.json()["teen_id"] == "usr_teen_b"

        write = client.post(
            "/api/v1/family/allowance",
            headers=headers,
            json={"teen_id": "usr_teen_b", "daily_limit_cents": 1, "blocked_mccs": []},
        )
        assert write.status_code == 200
        assert write.json()["daily_limit_cents"] == 1
        assert write.json()["parent_id"] == "usr_parent_a"


def test_blocked_mcc_cannot_be_booked_through_array_wrapping_when_fixed():
    with lab_client(enable_mcc_pollution_bug=False) as client:
        headers = login(client, "teen.a@finshield.dev")
        response = client.post(
            "/api/v1/wallet/pay",
            headers=headers,
            json={"amount_cents": 100, "mcc": ["5411", "7995"], "merchant": "Loop Hole"},
        )
        assert response.status_code == 422

        plain = client.post(
            "/api/v1/wallet/pay",
            headers=headers,
            json={"amount_cents": 100, "mcc": "7995", "merchant": "Casino"},
        )
        assert plain.status_code == 403


def test_mcc_pollution_books_gambling_under_grocery_check():
    with lab_client(enable_mcc_pollution_bug=True) as client:
        headers = login(client, "teen.a@finshield.dev")
        response = client.post(
            "/api/v1/wallet/pay",
            headers=headers,
            json={"amount_cents": 100, "mcc": ["5411", "7995"], "merchant": "Loop Hole"},
        )
        assert response.status_code == 200, response.text
        assert response.json()["mcc"] == "7995"


def test_sim_rebind_requires_otp_when_toggle_is_off():
    with lab_client(enable_sim_swap_bug=False) as client:
        headers = login(client, "teen.a@finshield.dev")
        payload = {
            "sim_serial": "89014103211118599999",
            "attestation": {"provider": "software", "strongbox": False, "key_attested": False},
        }
        assert client.post("/api/v1/device/bind", headers=headers, json=payload).status_code == 403
        assert (
            client.post("/api/v1/device/bind", headers=headers, json={**payload, "otp": "246810"}).status_code
            == 200
        )


def test_sim_swap_toggle_accepts_rebind_without_otp():
    with lab_client(enable_sim_swap_bug=True) as client:
        headers = login(client, "teen.a@finshield.dev")
        response = client.post(
            "/api/v1/device/bind",
            headers=headers,
            json={
                "sim_serial": "89014103211118599999",
                "attestation": {"provider": "software", "strongbox": False, "key_attested": False},
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["rebind"] is True
        assert response.json()["sim_serial"] == "89014103211118599999"
