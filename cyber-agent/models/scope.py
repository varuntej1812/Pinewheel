from pydantic import BaseModel
from ipaddress import ip_network, ip_address

class ScopeDefinition(BaseModel):
    domains: list[str]
    ip_ranges: list[str]

class ScopeValidator:
    def __init__(self, definition: ScopeDefinition):
        self.definition = definition
        
    def validate_target(self, target: str) -> bool:
        """Validation logic without workflow dependencies"""
        try:
            ip = ip_address(target)
            for network in self.definition.ip_ranges:
                if ip in ip_network(network):
                    return True
        except ValueError:
            for domain in self.definition.domains:
                if target.endswith(domain):
                    return True
        return False