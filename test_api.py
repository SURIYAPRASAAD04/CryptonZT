import requests
import os
import json
from io import BytesIO
import pandas as pd

BASE_URL = "http://localhost:5000"
API_EMAIL = "suriyajaya6904@gmail.com" 

def test_text_protection():
    print("\n1. Testing text protection...")
    response = requests.post(
        f"{BASE_URL}/api/protectKey",
        data={"data": "Private Key", "metadata": "Validator Key"},
        headers={"X-API-Email": API_EMAIL}
    )
    print_response(response)

def test_json_protection():
    print("\n2. Testing JSON protection...")
    data = {
        "sensitive": True,
        "message": "This will be encrypted",
        "values": [1, 2, 3]
    }
    response = requests.post(
        f"{BASE_URL}/api/protectKey",
        json=data,
        headers={"X-API-Email": API_EMAIL, "Content-Type": "application/json"}
    )
    print_response(response)

def test_csv_protection():
    print("\n3. Testing CSV protection...")
    df = pd.DataFrame({
        "Name": ["Alice", "Bob"],
        "Secret": ["A1", "B2"]
    })
    
    csv_buffer = BytesIO()
    df.to_csv(csv_buffer, index=False)
    csv_buffer.seek(0)
    
    response = requests.post(
        f"{BASE_URL}/api/protectKey",
        files={"file": ("data.csv", csv_buffer, "text/csv")},
        data={"metadata": "Genesis Key"},
        headers={"X-API-Email": API_EMAIL}
    )
    print_response(response)

def test_binary_protection():
    print("\n4. Testing binary file protection...")
    binary_data = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) 
    
    response = requests.post(
        f"{BASE_URL}/api/protectKey",
        files={"file": ("dummy.png", BytesIO(binary_data), "application/octet-stream")},
        headers={"X-API-Email": API_EMAIL}
    )
    print_response(response)

def print_response(response):
    print(f"Status: {response.status_code}")
    try:
        print(json.dumps(response.json(), indent=2))
    except:
        print(response.text)

def test_manage_data():
    print("\nTesting manageData endpoint...")
    response = requests.get(
        f"{BASE_URL}/api/manageData",
        headers={"X-API-Email": API_EMAIL}
    )
    print_response(response)

def test_user_profile():
    print("\nTesting userProfile endpoint...")
    response = requests.get(
        f"{BASE_URL}/api/userProfile",
        headers={"X-API-Email": API_EMAIL}
    )
    print_response(response)

def test_get_data(data_id):
    print(f"\nTesting getData for ID: {data_id}...")
    response = requests.get(
        f"{BASE_URL}/api/data/{data_id}",
        headers={"X-API-Email": API_EMAIL}
    )
    print_response(response)

def test_get_key(key_id):
    print(f"\nTesting getKey for ID: {key_id}...")
    response = requests.get(
        f"{BASE_URL}/api/keys/{key_id}",
        headers={"X-API-Email": API_EMAIL}
    )
    print_response(response)

if __name__ == "__main__":
    
    test_text_protection()
    test_csv_protection()
    test_user_profile()
    
    protection_resp = requests.post(
        f"{BASE_URL}/api/protectKey",
        data={"data": "Test data for management", "metadata": "Recovery Key"},
        headers={"X-API-Email": API_EMAIL}
    )
    
    if protection_resp.status_code == 201:
        data_id = protection_resp.json().get("data_id")
        key_id = protection_resp.json().get("key_id")
        
        test_manage_data()
        test_get_data(data_id)
        test_get_key(key_id)