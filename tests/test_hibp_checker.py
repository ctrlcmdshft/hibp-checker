import pytest
from hibp_checker import HaveIBeenPwnedChecker
import os
import json

def test_validate_email_valid():
    checker = HaveIBeenPwnedChecker()
    assert checker.validate_email('test@example.com')
    assert checker.validate_email('user.name+tag@domain.co.uk')

def test_validate_email_invalid():
    checker = HaveIBeenPwnedChecker()
    assert not checker.validate_email('not-an-email')
    assert not checker.validate_email('user@.com')
    assert not checker.validate_email('user@com')

def test_save_results_to_file(tmp_path):
    checker = HaveIBeenPwnedChecker()
    email = 'test@example.com'
    breaches = [{"Name": "TestBreach", "Domain": "test.com"}]
    file_path = tmp_path / 'results.json'
    checker.save_results_to_file(email, breaches, filename=str(file_path))
    assert os.path.exists(file_path)
    with open(file_path) as f:
        data = json.load(f)
    assert data['email'] == email
    assert data['breach_count'] == 1
    assert data['breaches'][0]['Name'] == 'TestBreach'
