from pydantic import BaseModel
from ipaddress import ip_network, ip_address

class ScopeDefinition(BaseModel):
    domains: list[str]
    ip_ranges: list[str]

class ScopeValidator:
    def __init__(self, definition: ScopeDefinition):
        self.definition = definition
        
    def validate_target(self, target: str) -> bool:
        """Validate if target matches scope rules"""
        try:
            # Check if target is an IP address
            ip = ip_address(target)
            for network in self.definition.ip_ranges:
                if ip in ip_network(network):
                    return True
        except ValueError:
            # Check if target is a domain
            for domain in self.definition.domains:
                if target.endswith(domain):
                    return True
        return False