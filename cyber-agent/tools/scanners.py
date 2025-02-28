
import subprocess
import json
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any
from threading import Timer

SCAN_OUTPUT_DIR = Path("scan_results")
SCAN_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

class SecurityScanner:
    @staticmethod
    def run_command(cmd: list[str], timeout: int) -> Dict[str, Any]:
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=True  # Required for Windows
            )
            timer = Timer(timeout, proc.kill)
            timer.start()
            stdout, stderr = proc.communicate()
            timer.cancel()
            
            return {
                "success": proc.returncode == 0,
                "stdout": stdout,
                "stderr": stderr,
                "returncode": proc.returncode
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

class NmapScanner(SecurityScanner):
    @staticmethod
    def run(target: str, timeout: int = 120) -> Dict[str, Any]:
        try:
            output_file = SCAN_OUTPUT_DIR / f"nmap_{int(time.time())}.xml"
            cmd = [
                "nmap",
                "-p", "1-1000",
                "-T4",
                "-oX", str(output_file),
                target
            ]
            
            result = SecurityScanner.run_command(cmd, timeout)
            if not result["success"]:
                return result

            tree = ET.parse(output_file)
            return {
                "success": True,
                "ports": [
                    {
                        "port": port.get("portid"),
                        "state": port.find("state").get("state"),
                        "service": port.find("service").get("name", "unknown")
                    } for port in tree.findall(".//port")
                ]
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

class GobusterScanner(SecurityScanner):
    @staticmethod
    def run(target: str, timeout: int = 180) -> Dict[str, Any]:
        try:
            output_file = SCAN_OUTPUT_DIR / f"gobuster_{int(time.time())}.json"
            wordlist = Path("wordlists/common.txt").absolute()
            
            if not wordlist.exists():
                return {"success": False, "error": f"Wordlist not found at {wordlist}"}

            cmd = [
                "gobuster", "dir",
                "-u", target,
                "-w", str(wordlist),
                "-o", str(output_file),
                "--json",
                "-t", "50",
                "-k",
                "--status-codes", "200,204,301,302,307,401,403"
            ]
            
            result = SecurityScanner.run_command(cmd, timeout)
            
            if not result["success"]:
                error_details = f"STDOUT: {result['stdout']}\nSTDERR: {result['stderr']}"
                return {"success": False, "error": error_details}

            try:
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    directories = [item["path"] for item in data.get("results", [])]
                    return {"success": True, "directories": directories}
            except Exception as e:
                return {"success": False, "error": f"Output parsing failed: {str(e)}"}

        except Exception as e:
            return {"success": False, "error": str(e)}

# [Keep FFUF and SQLMap implementations similar to previous]


        
class FfufScanner(SecurityScanner):
    @staticmethod
    def run(target: str, timeout: int = 180) -> Dict[str, Any]:
        """Parameter fuzzing scanner"""
        try:
            output_file = SCAN_OUTPUT_DIR / f"ffuf_{int(time.time())}.json"
            wordlist = Path("wordlists/parameters.txt").absolute()
            
            if not wordlist.exists():
                return {"success": False, "error": "Wordlist not found"}

            cmd = [
                "ffuf",
                "-w", f"{wordlist}:FUZZ",
                "-u", f"{target}/FUZZ",
                "-o", str(output_file),
                "-of", "json",
                "-t", "50",
                "-mc", "200,301,302"
            ]
            
            result = SecurityScanner.run_command(cmd, timeout)
            
            if not result["success"]:
                return result

            with open(output_file) as f:
                try:
                    results = json.load(f)
                    return {
                        "success": True,
                        "parameters": [res["input"]["FUZZ"] for res in results.get("results", [])]
                    }
                except (KeyError, json.JSONDecodeError):
                    return {"success": False, "error": "Invalid output format"}

        except Exception as e:
            return {"success": False, "error": str(e)}

class SQLMapScanner(SecurityScanner):
    @staticmethod
    def run(target: str, timeout: int = 300) -> Dict[str, Any]:
        """SQL injection vulnerability scanner"""
        try:
            output_dir = SCAN_OUTPUT_DIR / f"sqlmap_{int(time.time())}"
            output_dir.mkdir(exist_ok=True)

            cmd = [
                "sqlmap",
                "-u", target,
                "--batch",
                "--output-dir", str(output_dir),
                "--level", "1",
                "--risk", "1",
                "--timeout", "30",
                "--forms",
                "--crawl", "2"
            ]
            
            result = SecurityScanner.run_command(cmd, timeout)
            
            vulnerable = "sql-injection" in result["stdout"].lower()
            return {
                "success": result["success"],
                "vulnerable": vulnerable,
                "log_path": str(output_dir / "log")
            }

        except Exception as e:
            return {"success": False, "error": str(e)}