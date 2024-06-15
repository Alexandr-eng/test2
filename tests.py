import pytest
import requests

BASE_URL = "http://127.0.0.1:8000"

@pytest.fixture(scope="module")
def registered_user():
    user_data = {
        "username": "testuser",
        "password": "testpassword"
    }
    response = requests.post(f"{BASE_URL}/register", json=user_data)
    assert response.status_code == 201
    return user_data

def test_register_existing_user():
    user_data = {
        "username": "testuser",
        "password": "testpassword"
    }
    response = requests.post(f"{BASE_URL}/register", json=user_data)
    assert response.status_code == 400
    assert response.json() == {"detail": "Username already registered"}

def test_login(registered_user):
    response = requests.post(f"{BASE_URL}/login", data={"username": registered_user["username"], "password": registered_user["password"]})
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"
    return response.json()["access_token"]

def test_read_users_me(registered_user):
    access_token = test_login(registered_user)
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(f"{BASE_URL}/users/me", headers=headers)
    assert response.status_code == 200
    assert response.json()["username"] == registered_user["username"]

def test_read_users_me_unauthorized():
    response = requests.get(f"{BASE_URL}/users/me")
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}