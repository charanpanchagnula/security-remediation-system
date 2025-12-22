import json
import asyncio
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
        """
        Reads lines of code surrounding a vulnerability from the source file.

        Args:
            file_path (Path): Absolute path to the source file.
            start_line (int): The starting line number (1-indexed).
            end_line (int): The ending line number (1-indexed).
            context_lines (int, optional): Number of lines to include before/after. Defaults to 5.

        Returns:
            str: The concatenated code lines.
        """
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                
            # 1-indexed conversion
            s = max(0, start_line - 1 - context_lines)
            e = min(len(lines), end_line + context_lines)
            
            return "".join(lines[s:e])
        except Exception:
            return ""

    async def prepare_workspace(self, archive_key: str) -> tempfile.TemporaryDirectory:
        """
        Prepares the workspace by downloading and extracting the archive.
        Returns the TemporaryDirectory object (context manager).
        The extracted source will be in {tmp.name}/source
        """
        def _setup():
            tmp = tempfile.TemporaryDirectory()
            work_dir = Path(tmp.name)
            archive_path = work_dir / "source.tar.gz"
            extract_dir = work_dir / "source"
            extract_dir.mkdir()
            
            # Download archive
            logger.info(f"Downloading archive {archive_key} to {archive_path}")
            self.storage.download_file(archive_key, str(archive_path))
            logger.info(f"Download complete. Size: {archive_path.stat().st_size} bytes")
            
            # Extract
            logger.info(f"Extracting archive to {extract_dir}")
            with tarfile.open(archive_path, "r:gz") as tar:
                tar.extractall(extract_dir)
            logger.info("Extraction complete")
            return tmp

        return await asyncio.to_thread(_setup)

    async def scan_directory(self, target_dir: Path, repo_url: str, scanner_type: str) -> List[Vulnerability]:
        """
        Runs a specific scanner on the target directory.
        """
        logger.info(f"Running {scanner_type} on {target_dir}")
        try:
            if scanner_type == "semgrep":
                return await self._run_semgrep(target_dir)
            elif scanner_type == "checkov":
                return await self._run_checkov(target_dir)
            elif scanner_type == "trivy":
                return await self._run_trivy(target_dir)
            else:
                logger.warning(f"Unknown scanner type: {scanner_type}")
                return []
        except Exception as e:
            logger.error(f"Scanner {scanner_type} failed: {e}", exc_info=True)
            raise e

    async def run_scan(self, archive_key: str, repo_url: str, scanner_type: str = "semgrep") -> ScanResult:
        """
        Legacy method for backward compatibility / single scan.
        """
        scan_id = str(uuid.uuid4())
        logger.info(f"Starting {scanner_type} scan (ID: {scan_id}) on {archive_key}")
        
        tmp_dir = None
        try:
            tmp_dir = await self.prepare_workspace(archive_key)
            extract_dir = Path(tmp_dir.name) / "source"
            
            vulnerabilities = await self.scan_directory(extract_dir, repo_url, scanner_type)

            return ScanResult(
                scan_id=scan_id,
                repo_url=repo_url,
                timestamp=datetime.utcnow().isoformat(),
                vulnerabilities=vulnerabilities
            )
            
        except Exception as e:
            logger.error(f"Scan failed: {e}", exc_info=True)
            raise e
        finally:
            if tmp_dir:
                await asyncio.to_thread(tmp_dir.cleanup)

    async def _run_semgrep(self, target_dir: Path) -> List[Vulnerability]:
        """
        Executes Semgrep CLI on the target directory asynchronously.
        """
        rules_path = Path("/app/backend/rules")
        if not rules_path.exists():
            rules_path = Path(__file__).parent.parent.parent.parent / "rules"
            
        cmd = [
            "semgrep", 
            "scan", 
            "--config", "p/default", 
            "--config", "rules",     
            "--json", 
            str(target_dir)
        ]
        
        logger.info(f"Running Semgrep command: {' '.join(cmd)}")
        
        # Use asyncio subprocess
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(rules_path.parent)
        )
        
        try:
            # Add timeout to communicate
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
        except asyncio.TimeoutError:
            logger.error(f"Semgrep timed out after 300s")
            try:
                process.kill()
            except Exception:
                pass
            return []
            
        stdout_text = stdout.decode()
        stderr_text = stderr.decode()
        
        logger.info(f"Semgrep return code: {process.returncode}")
        
        vulnerabilities = []
        
        if process.returncode in [0, 1]:
            try:
                if not stdout_text.strip():
                    logger.warning("Semgrep returned empty stdout")
                    return []
                output = json.loads(stdout_text)
                results = output.get("results", [])
                
                for item in results:
                    path_str = item.get("path", "")
                    start_line = item.get("start", {}).get("line", 0)
                    end_line = item.get("end", {}).get("line", 0)
                    
                    if os.path.isabs(path_str):
                        try:
                            rel_path = Path(path_str).relative_to(target_dir)
                            path_str = str(rel_path)
                        except ValueError:
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
                logger.debug(f"Semgrep stderr: {stderr_text}")
        else:
            logger.error(f"Semgrep failed with code {process.returncode}: {stderr_text}")

        return vulnerabilities

    async def _run_checkov(self, target_dir: Path) -> List[Vulnerability]:
        """
        Executes Checkov CLI for IaC scanning asynchronously.
        """
        cmd = ["checkov", "-d", str(target_dir), "--output", "json", "--soft-fail"]
        
        logger.info(f"Running Checkov command: {' '.join(cmd)}")
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
        except asyncio.TimeoutError:
            logger.error(f"Checkov timed out after 300s")
            try:
                process.kill()
            except Exception:
                pass
            return []

        stdout_text = stdout.decode()
        
        vulnerabilities = []
        
        try:
            output = json.loads(stdout_text)
            reports = output if isinstance(output, list) else [output]
            
            for report in reports:
                failed_checks = report.get("results", {}).get("failed_checks", [])
                for check in failed_checks:
                    path_str = check.get("file_path", "").lstrip("/") 
                    start_line = check.get("file_line_range", [0, 0])[0]
                    end_line = check.get("file_line_range", [0, 0])[1]
                    
                    if os.path.isabs(path_str):
                        try:
                            if str(target_dir) in path_str:
                                rel_path = Path(path_str).relative_to(target_dir)
                                path_str = str(rel_path)
                            else:
                                path_str = path_str.lstrip("/")
                        except ValueError:
                            pass

                    full_path = target_dir / path_str
                    context = self._read_context(full_path, start_line, end_line)
                    
                    code_block = check.get("code_block", [])
                    snippet = "".join([line[1] for line in code_block])
                    
                    vuln = Vulnerability(
                        id=str(uuid.uuid4()),
                        rule_id=check.get("check_id"),
                        message=check.get("check_name", ""),
                        severity="HIGH", 
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
            logger.debug(f"Checkov content (first 500 chars): {stdout_text[:500]}")
            
        return vulnerabilities

    async def _run_trivy(self, target_dir: Path) -> List[Vulnerability]:
        """Runs Trivy FS scan asynchronously."""
        cmd = ["trivy", "fs", str(target_dir), "--format", "json"]
        
        logger.info(f"Running Trivy command: {' '.join(cmd)}")
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
        except asyncio.TimeoutError:
            logger.error(f"Trivy timed out after 300s")
            try:
                process.kill()
            except Exception:
                pass
            return []

        stdout_text = stdout.decode()
        
        vulnerabilities = []

        if process.returncode != 0:
            logger.error(f"Trivy failed: {stderr.decode()}")
        
        try:
            output = json.loads(stdout_text)
            results = output.get("Results", [])
            
            for res in results:
                target_file = res.get("Target", "unknown")
                if os.path.isabs(target_file):
                    try:
                        target_file = str(Path(target_file).relative_to(target_dir))
                    except ValueError:
                        pass
                
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
                        start_line=1, 
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
                
        except json.JSONDecodeError:
            logger.error("Failed to parse Trivy JSON output")
            logger.debug(f"Trivy stdout: {stdout_text}")
            
        return vulnerabilities

scanner_service = ScannerService()
