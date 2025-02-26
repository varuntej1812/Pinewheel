import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from models.scope import ScopeDefinition, ScopeValidator

def test_scope_validation():
    scope_def = ScopeDefinition(
        domains=[".example.com", "test.org"],
        ip_ranges=["192.168.1.0/24", "10.0.0.0/8"]
    )
    validator = ScopeValidator(scope_def)
    
    assert validator.validate_target("sub.example.com") is True
    assert validator.validate_target("evil.com") is False
    assert validator.validate_target("192.168.1.5") is True
    assert validator.validate_target("10.10.10.10") is True
    assert validator.validate_target("8.8.8.8") is False