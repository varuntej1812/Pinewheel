# scanners.py
import subprocess
import json
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any
from threading import Timer

SCAN_OUTPUT_DIR = Path("scan_results")
SCAN_OUTPUT_DIR.mkdir(exist_ok=True)

class SecurityScanner:
    @staticmethod
    def run_command(cmd: list[str], timeout: int) -> Dict[str, Any]:
        """Execute command with proper subprocess handling"""
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
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
        """Run Nmap scan with validation"""
        try:
            if not any(c in target for c in ['.', ':']):
                return {"success": False, "error": "Invalid target format"}
            
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
                    } 
                    for port in tree.findall(".//port")
                ]
            }
        except ET.ParseError as e:
            return {"success": False, "error": f"XML parse error: {str(e)}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

class GobusterScanner(SecurityScanner):
    @staticmethod
    def run(target: str, timeout: int = 180) -> Dict[str, Any]:
        """Directory/file brute-force scanner"""
        try:
            output_file = SCAN_OUTPUT_DIR / f"gobuster_{int(time.time())}.json"
            wordlist = Path("wordlists/common.txt").absolute()
            
            if not wordlist.exists():
                return {"success": False, "error": "Wordlist not found"}

            cmd = [
                "gobuster", "dir",
                "-u", target,
                "-w", str(wordlist),
                "-o", str(output_file),
                "-b", "302,404,500",
                "--no-error",
                "-z"
            ]
            
            result = SecurityScanner.run_command(cmd, timeout)
            
            if not result["success"]:
                return result

            with open(output_file) as f:
                try:
                    findings = json.load(f)
                    return {
                        "success": True,
                        "directories": [res["path"] for res in findings.get("results", [])]
                    }
                except json.JSONDecodeError:
                    return {"success": False, "error": "Invalid JSON output"}

        except Exception as e:
            return {"success": False, "error": str(e)}



        
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