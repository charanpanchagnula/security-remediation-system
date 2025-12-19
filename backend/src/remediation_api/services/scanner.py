import json
import subprocess
import os
import tarfile
import tempfile
import uuid
from typing import List, Dict, Any
from pathlib import Path
from datetime import datetime
from .storage import get_storage
from ..models.scan import ScanResult, Vulnerability
from ..logger import get_logger

logger = get_logger(__name__)

class ScannerService:
    def __init__(self):
        self.storage = get_storage()

    def _read_context(self, file_path: Path, start_line: int, end_line: int, context_lines: int = 5) -> str:
        """Reads surrounding lines of code."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                
            # 1-indexed conversion
            s = max(0, start_line - 1 - context_lines)
            e = min(len(lines), end_line + context_lines)
            
            return "".join(lines[s:e])
        except Exception:
            return ""

    def run_scan(self, archive_key: str, repo_url: str, scanner_type: str = "semgrep") -> ScanResult:
        scan_id = str(uuid.uuid4())
        logger.info(f"Starting {scanner_type} scan (ID: {scan_id}) on {archive_key}")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            work_dir = Path(temp_dir)
            archive_path = work_dir / "source.tar.gz"
            extract_dir = work_dir / "source"
            extract_dir.mkdir()
            
            # Download archive
            self.storage.download_file(archive_key, str(archive_path))
            
            # Extract
            with tarfile.open(archive_path, "r:gz") as tar:
                tar.extractall(extract_dir)
            
            vulnerabilities = []
            
            if scanner_type == "semgrep":
                vulnerabilities = self._run_semgrep(extract_dir)
            elif scanner_type == "checkov":
                vulnerabilities = self._run_checkov(extract_dir)
            elif scanner_type == "trivy":
                vulnerabilities = self._run_trivy(extract_dir)

            
            return ScanResult(
                scan_id=scan_id,
                repo_url=repo_url,
                timestamp=datetime.utcnow().isoformat(),
                vulnerabilities=vulnerabilities
            )

    def _run_semgrep(self, target_dir: Path) -> List[Vulnerability]:
        # Ensure rules path is absolute
        # rules dir is in the same directory as 'src' (app root)
        # In Docker this is /app/backend/rules
        rules_path = Path("/app/backend/rules")
        if not rules_path.exists():
            # Fallback for local dev
            rules_path = Path(__file__).parent.parent.parent.parent / "rules"
            
        cmd = [
            "semgrep", 
            "scan", 
            "--config", "p/default", # Standard security rules from registry
            "--config", "rules",     # Custom MCP rules from local dir
            "--json", 
            str(target_dir)
        ]
        
        # Add context of where we are running
        logger.info(f"Semgrep rules path: {rules_path.absolute()}")
        logger.info(f"Running Semgrep command: {' '.join(cmd)}")
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(rules_path.parent))
        logger.info(f"Semgrep return code: {result.returncode}")
        
        vulnerabilities = []
        
        if result.returncode in [0, 1]:
            try:
                if not result.stdout.strip():
                    logger.warning("Semgrep returned empty stdout")
                    return []
                output = json.loads(result.stdout)
                results = output.get("results", [])
                
                for item in results:
                    path_str = item.get("path", "")
                    start_line = item.get("start", {}).get("line", 0)
                    end_line = item.get("end", {}).get("line", 0)
                    
                    # Handle absolute paths from Semgrep
                    if os.path.isabs(path_str):
                        try:
                            rel_path = Path(path_str).relative_to(target_dir)
                            path_str = str(rel_path)
                        except ValueError:
                            # Not relative to target_dir, keep as is (unlikely in this context)
                            pass
                    
                    full_path = target_dir / path_str
                    context = self._read_context(full_path, start_line, end_line)
                    
                    vuln = Vulnerability(
                        id=str(uuid.uuid4()),
                        rule_id=item.get("check_id"),
                        message=item.get("extra", {}).get("message", ""),
                        severity=item.get("extra", {}).get("severity", "MEDIUM"),
                        file_path=path_str,
                        start_line=start_line,
                        end_line=end_line,
                        code_snippet=item.get("extra", {}).get("lines", ""),
                        surrounding_context=context,
                        scanner="semgrep",
                        metadata=item.get("extra", {}).get("metadata", {})
                    )
                    vulnerabilities.append(vuln)
            except json.JSONDecodeError:
                logger.error("Failed to parse Semgrep JSON output")
                logger.debug(f"Semgrep stderr: {result.stderr}")
        return vulnerabilities

    def _run_checkov(self, target_dir: Path) -> List[Vulnerability]:
        # Checkov recursive scan
        cmd = ["checkov", "-d", str(target_dir), "--output", "json", "--soft-fail"]
        
        logger.info(f"Running Checkov command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        vulnerabilities = []
        
        try:
            # Checkov might return a single dict or a list of dicts (if multiple frameworks found)
            output = json.loads(result.stdout)
            reports = output if isinstance(output, list) else [output]
            
            for report in reports:
                # 'results' -> 'failed_checks'
                failed_checks = report.get("results", {}).get("failed_checks", [])
                for check in failed_checks:
                    path_str = check.get("file_path", "").lstrip("/") # Checkov returns absolute-ish path starting with /
                    start_line = check.get("file_line_range", [0, 0])[0]
                    end_line = check.get("file_line_range", [0, 0])[1]
                    
                    # Checkov might return absolute paths
                    if os.path.isabs(path_str):
                        try:
                            # Checkov often prefixes with / even if relative, verify against target_dir
                            if str(target_dir) in path_str:
                                rel_path = Path(path_str).relative_to(target_dir)
                                path_str = str(rel_path)
                            else:
                                # Sometimes checkov just gives /file.py
                                path_str = path_str.lstrip("/")
                        except ValueError:
                            pass

                    # Read context manually
                    full_path = target_dir / path_str
                    context = self._read_context(full_path, start_line, end_line)
                    
                    # Code block in checkov is a list of lines with line numbers
                    code_block = check.get("code_block", [])
                    snippet = "".join([line[1] for line in code_block]) # line is [line_num, line_content] checkov format? Usually [int, str]
                    # Verify checkov code_block format: List[List[int, str]]
                    
                    vuln = Vulnerability(
                        id=str(uuid.uuid4()),
                        rule_id=check.get("check_id"),
                        message=check.get("check_name", ""),
                        severity="HIGH", # Checkov usually doesn't give severity in JSON unless enriched, mapping to HIGH default
                        file_path=path_str,
                        start_line=start_line,
                        end_line=end_line,
                        code_snippet=snippet,
                        surrounding_context=context,
                        scanner="checkov",
                        metadata={"resource": check.get("resource")}
                    )
                    vulnerabilities.append(vuln)
        except Exception as e:
            logger.error(f"Failed to parse Checkov output: {e}")
            logger.debug(f"Checkov content (first 500 chars): {result.stdout[:500]}")
            
        return vulnerabilities

    def _run_trivy(self, target_dir: Path) -> List[Vulnerability]:
        """Runs Trivy FS scan for SCA and Misconfigurations."""
        cmd = ["trivy", "fs", str(target_dir), "--format", "json"]
        
        logger.info(f"Running Trivy command: {' '.join(cmd)}")
        # Trivy writes to stdout by default with --format json
        result = subprocess.run(cmd, capture_output=True, text=True)
        vulnerabilities = []

        if result.returncode != 0:
            logger.error(f"Trivy failed: {result.stderr}")
            # Trivy might still output JSON on failure (e.g. found vuln exit code), but we usually check stdout
        
        try:
            output = json.loads(result.stdout)
            results = output.get("Results", [])
            
            for res in results:
                target_file = res.get("Target", "unknown")
                if os.path.isabs(target_file):
                    try:
                        target_file = str(Path(target_file).relative_to(target_dir))
                    except ValueError:
                        pass
                # Handle Vulnerabilities (SCA)
                vulns = res.get("Vulnerabilities", [])
                for v in vulns:
                    pkg_name = v.get("PkgName", "")
                    installed = v.get("InstalledVersion", "")
                    fixed = v.get("FixedVersion", "")
                    
                    vuln = Vulnerability(
                        id=str(uuid.uuid4()),
                        rule_id=v.get("VulnerabilityID"),
                        message=f"{v.get('Title', '')}: {pkg_name} {installed} (Fixed: {fixed})",
                        severity=v.get("Severity", "UNKNOWN"),
                        file_path=target_file,
                        start_line=1, # SCA often doesn't give line numbers
                        end_line=1,
                        code_snippet=f"Package: {pkg_name}\nInstalled: {installed}\nFixed: {fixed}",
                        surrounding_context=v.get("Description", ""),
                        scanner="trivy",
                        metadata={
                            "pkg_name": pkg_name,
                            "installed_version": installed,
                            "fixed_version": fixed,
                            "references": v.get("References", [])
                        }
                    )
                    vulnerabilities.append(vuln)
                
                # Handle Misconfigurations (IaC/Secrets) - optional if relying on Checkov/Semgrep, but Trivy does this too
                # For now focusing on SCA (Vulnerabilities) as per user request
                
        except json.JSONDecodeError:
            logger.error("Failed to parse Trivy JSON output")
            logger.debug(f"Trivy stdout: {result.stdout}")
            
        return vulnerabilities



scanner_service = ScannerService()
