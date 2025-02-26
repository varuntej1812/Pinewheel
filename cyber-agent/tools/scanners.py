import subprocess
import json
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any

SCAN_OUTPUT_DIR = Path("scan_results")
SCAN_OUTPUT_DIR.mkdir(exist_ok=True)

class SecurityScanner:
    @staticmethod
    def run_command(cmd: str, timeout: int) -> Dict[str, Any]:
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

class NmapScanner(SecurityScanner):
    @staticmethod
    def run(target: str) -> Dict[str, Any]:
        output_file = SCAN_OUTPUT_DIR / f"nmap_{int(time.time())}.xml"
        cmd = f"nmap -p 1-1000 -T4 -oX {output_file} {target}"
        result = SecurityScanner.run_command(cmd, 300)
        
        if not result["success"]:
            return result
            
        try:
            tree = ET.parse(output_file)
            return {
                "ports": [
                    {
                        "port": port.get("portid"),
                        "state": port.find("state").get("state"),
                        "service": port.find("service").get("name", "unknown")
                    }
                    for port in tree.findall(".//port")
                ]
            }
        except Exception as e:
            return {"error": str(e)}

class GobusterScanner(SecurityScanner):
    @staticmethod
    def run(target: str) -> Dict[str, Any]:
        output_file = SCAN_OUTPUT_DIR / f"gobuster_{int(time.time())}.json"
        wordlist = Path("wordlists/common.txt").absolute()
        
        # Updated command to handle 302 redirects
        cmd = f"gobuster dir -u {target} -w {wordlist} -o {output_file} -b 302,404 --no-error"
        
        return SecurityScanner.run_command(cmd, 600)

class FfufScanner(SecurityScanner):
    @staticmethod
    def run(target: str) -> Dict[str, Any]:
        output_file = SCAN_OUTPUT_DIR / f"ffuf_{int(time.time())}.json"
        cmd = f"ffuf -w wordlists/parameters.txt -u {target}/FUZZ -o {output_file} -of json"
        return SecurityScanner.run_command(cmd, 300)

class SQLMapScanner(SecurityScanner):
    @staticmethod
    def run(target: str) -> Dict[str, Any]:
        output_file = SCAN_OUTPUT_DIR / f"sqlmap_{int(time.time())}.log"
        cmd = f"sqlmap -u {target} --batch --output-dir={SCAN_OUTPUT_DIR}"
        return SecurityScanner.run_command(cmd, 600)