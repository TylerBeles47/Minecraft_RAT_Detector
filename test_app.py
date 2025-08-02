"""
Simple tests for the Minecraft RAT Detector application
"""
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_api_root():
    """Test the API root endpoint"""
    response = client.get("/api")
    assert response.status_code == 200
    assert "message" in response.json()

def test_root_endpoint():
    """Test the root endpoint returns HTML"""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]

def test_scan_history():
    """Test scan history endpoint"""
    response = client.get("/scan-history/")
    assert response.status_code == 200
    # Should return a list (empty or with data)
    assert isinstance(response.json(), list)

if __name__ == "__main__":
    print("Running basic tests...")
    test_api_root()
    test_root_endpoint() 
    test_scan_history()
    print("All tests passed!")