from tools.scanners import NmapScanner, GobusterScanner
from models.scope import ScopeDefinition, ScopeValidator
from pathlib import Path

# Create test wordlist
(Path("wordlists") / "common.txt").write_text("test\nadmin\nlogin")

# Test scope
scope = ScopeValidator(ScopeDefinition(domains=[".nmap.org"], ip_ranges=[]))
print("Scope validation for scanme.nmap.org:", scope.validate_target("scanme.nmap.org"))

# Test nmap
nmap_result = NmapScanner.run("scanme.nmap.org")
print("\nNmap open ports:", [p for p in nmap_result.get('ports', []) if p['state'] == 'open'])

# Test gobuster
gobuster_result = GobusterScanner.run("http://scanme.nmap.org")
print("\nGobuster result:", gobuster_result)