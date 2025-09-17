"""
AI Agent Security Module with MCP Protocol Integration
Implements Token Vault, prompt injection detection, and AI-native security controls

Key Features:
- MCP (Model Context Protocol) server implementation
- Token Vault for secure AI credential management
- Real-time prompt injection detection
- Content Security Policy enforcement for AI agents
"""

import asyncio
import time
import json
import re
import hashlib
from typing import Dict, List, Optional, Any, AsyncGenerator
from dataclasses import dataclass
from enum import Enum
import logging
from urllib.parse import urlparse

import numpy as np
from numba import jit
import aiohttp
from mcp import MCPServer, Resource, Tool
from mcp.types import TextResourceContents, ImageResourceContents
import tiktoken
from transformers import pipeline
import torch
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Security threat classifications
class ThreatType(Enum):
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    JAILBREAK_ATTEMPT = "jailbreak_attempt"
    MALICIOUS_CODE = "malicious_code"
    SOCIAL_ENGINEERING = "social_engineering"
    CREDENTIAL_HARVESTING = "credential_harvesting"

@dataclass
class SecurityThreat:
    """Detected security threat with metadata"""
    threat_type: ThreatType
    confidence: float
    description: str
    detected_patterns: List[str]
    risk_score: float
    timestamp: float
    source_ip: Optional[str] = None
    user_id: Optional[str] = None

@jit(nopython=True, cache=True)
def calculate_entropy(text_array: np.ndarray) -> float:
    """
    JIT-compiled Shannon entropy calculation for anomaly detection
    High entropy often indicates obfuscated or malicious content
    """
    unique, counts = np.unique(text_array, return_counts=True)
    probabilities = counts / len(text_array)

    entropy = 0.0
    for prob in probabilities:
        if prob > 0:
            entropy -= prob * np.log2(prob)

    return entropy

class TokenVault:
    """
    Secure credential management for AI agents
    Implements Auth0's Token Vault pattern with encryption at rest
    """

    def __init__(self, master_key: Optional[bytes] = None):
        if master_key is None:
            master_key = Fernet.generate_key()

        self.cipher_suite = Fernet(master_key)
        self.token_store: Dict[str, bytes] = {}  # Encrypted storage
        self.token_metadata: Dict[str, Dict] = {}

        # Access tracking for security monitoring
        self.access_log: List[Dict] = []

    def store_token(self, agent_id: str, token_data: Dict,
                   expires_in: Optional[int] = None) -> str:
        """
        Securely store AI agent credentials

        Args:
            agent_id: Unique identifier for the AI agent
            token_data: Credential data to encrypt and store
            expires_in: Token expiration time in seconds

        Returns:
            Token reference ID for retrieval
        """
        # Generate secure token reference
        token_ref = hashlib.sha256(
            f"{agent_id}:{time.time()}:{token_data}".encode()
        ).hexdigest()[:16]

        # Encrypt token data
        encrypted_token = self.cipher_suite.encrypt(
            json.dumps(token_data).encode('utf-8')
        )

        # Store encrypted token
        self.token_store[token_ref] = encrypted_token

        # Store metadata
        current_time = time.time()
        self.token_metadata[token_ref] = {
            'agent_id': agent_id,
            'created_at': current_time,
            'expires_at': current_time + (expires_in or 3600),
            'access_count': 0,
            'last_accessed': None
        }

        # Log storage event
        self.access_log.append({
            'action': 'store',
            'token_ref': token_ref,
            'agent_id': agent_id,
            'timestamp': current_time
        })

        return token_ref

    def retrieve_token(self, token_ref: str, agent_id: str) -> Optional[Dict]:
        """
        Securely retrieve AI agent credentials

        Args:
            token_ref: Token reference ID
            agent_id: Agent requesting the token

        Returns:
            Decrypted token data if authorized and valid
        """
        current_time = time.time()

        # Check if token exists
        if token_ref not in self.token_store:
            return None

        # Verify agent authorization
        metadata = self.token_metadata[token_ref]
        if metadata['agent_id'] != agent_id:
            self.access_log.append({
                'action': 'unauthorized_access_attempt',
                'token_ref': token_ref,
                'agent_id': agent_id,
                'authorized_agent': metadata['agent_id'],
                'timestamp': current_time
            })
            return None

        # Check expiration
        if current_time > metadata['expires_at']:
            self._cleanup_expired_token(token_ref)
            return None

        # Decrypt and return token
        try:
            encrypted_token = self.token_store[token_ref]
            decrypted_data = self.cipher_suite.decrypt(encrypted_token)
            token_data = json.loads(decrypted_data.decode('utf-8'))

            # Update access tracking
            metadata['access_count'] += 1
            metadata['last_accessed'] = current_time

            self.access_log.append({
                'action': 'retrieve',
                'token_ref': token_ref,
                'agent_id': agent_id,
                'timestamp': current_time
            })

            return token_data

        except Exception as e:
            print(f"Token decryption error: {e}")
            return None

    def _cleanup_expired_token(self, token_ref: str):
        """Remove expired token from storage"""
        if token_ref in self.token_store:
            del self.token_store[token_ref]
        if token_ref in self.token_metadata:
            del self.token_metadata[token_ref]

class PromptInjectionDetector:
    """
    Advanced prompt injection detection using multiple techniques:
    - Pattern matching for known injection vectors
    - Entropy analysis for obfuscated content
    - ML-based classification
    - Contextual analysis
    """

    def __init__(self):
        # Load ML model for injection detection
        self.classifier = pipeline(
            "text-classification",
            model="deepset/deberta-v3-base-injection-guard",
            device=0 if torch.cuda.is_available() else -1
        )

        # Tokenizer for content analysis
        self.tokenizer = tiktoken.get_encoding("cl100k_base")

        # Known injection patterns (regularly updated)
        self.injection_patterns = [
            r"ignore\s+previous\s+instructions",
            r"forget\s+everything\s+above",
            r"system\s*:\s*you\s+are",
            r"act\s+as\s+if\s+you\s+are",
            r"pretend\s+to\s+be",
            r"roleplay\s+as",
            r"\\n\\nuser:",
            r"\\n\\nassistant:",
            r"<\|endoftext\|>",
            r"\\x[0-9a-fA-F]{2}",  # Hex encoding
            r"&#\d+;",             # HTML entities
            r"%[0-9a-fA-F]{2}",    # URL encoding
        ]

        # Compile patterns for performance
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.injection_patterns
        ]

        # Jailbreak detection keywords
        self.jailbreak_keywords = {
            "dan", "developer mode", "jailbreak", "godmode",
            "admin mode", "unrestricted", "bypass", "override",
            "simulation", "hypothetical", "ignore safety"
        }

    async def detect_threats(self, content: str, context: Dict = None) -> List[SecurityThreat]:
        """
        Comprehensive threat detection in AI prompts

        Args:
            content: Text content to analyse
            context: Additional context (user_id, source_ip, etc.)

        Returns:
            List of detected security threats
        """
        threats = []

        # Pattern-based detection
        pattern_threats = self._detect_injection_patterns(content)
        threats.extend(pattern_threats)

        # Entropy-based anomaly detection
        entropy_threats = self._detect_entropy_anomalies(content)
        threats.extend(entropy_threats)

        # ML-based classification
        ml_threats = await self._detect_ml_threats(content)
        threats.extend(ml_threats)

        # Jailbreak detection
        jailbreak_threats = self._detect_jailbreak_attempts(content)
        threats.extend(jailbreak_threats)

        # Context-based analysis
        if context:
            context_threats = self._detect_context_anomalies(content, context)
            threats.extend(context_threats)

        return threats

    def _detect_injection_patterns(self, content: str) -> List[SecurityThreat]:
        """Detect known prompt injection patterns"""
        threats = []

        for i, pattern in enumerate(self.compiled_patterns):
            matches = pattern.findall(content)

            if matches:
                threat = SecurityThreat(
                    threat_type=ThreatType.PROMPT_INJECTION,
                    confidence=0.8 + (len(matches) * 0.05),  # Higher confidence with more matches
                    description=f"Detected injection pattern: {self.injection_patterns[i]}",
                    detected_patterns=matches,
                    risk_score=7.5,
                    timestamp=time.time()
                )
                threats.append(threat)

        return threats

    def _detect_entropy_anomalies(self, content: str) -> List[SecurityThreat]:
        """Detect obfuscated content using entropy analysis"""
        threats = []

        # Convert content to numpy array for JIT processing
        content_bytes = np.frombuffer(content.encode('utf-8'), dtype=np.uint8)

        if len(content_bytes) > 10:  # Minimum length for meaningful entropy
            entropy = calculate_entropy(content_bytes)

            # High entropy threshold (indicates potential obfuscation)
            if entropy > 6.5:
                threat = SecurityThreat(
                    threat_type=ThreatType.PROMPT_INJECTION,
                    confidence=min(0.9, entropy / 8.0),
                    description=f"High content entropy detected: {entropy:.2f}",
                    detected_patterns=[f"entropy_{entropy:.2f}"],
                    risk_score=6.0 + entropy,
                    timestamp=time.time()
                )
                threats.append(threat)

        return threats

    async def _detect_ml_threats(self, content: str) -> List[SecurityThreat]:
        """Use ML model for advanced threat detection"""
        threats = []

        try:
            # Truncate content to model's maximum length
            max_length = 512
            truncated_content = content[:max_length]

            # Run ML classification
            result = self.classifier(truncated_content)

            # Check if classified as malicious
            if result[0]['label'] == 'INJECTION' and result[0]['score'] > 0.7:
                threat = SecurityThreat(
                    threat_type=ThreatType.PROMPT_INJECTION,
                    confidence=result[0]['score'],
                    description=f"ML model detected injection (confidence: {result[0]['score']:.2f})",
                    detected_patterns=['ml_detection'],
                    risk_score=result[0]['score'] * 10,
                    timestamp=time.time()
                )
                threats.append(threat)

        except Exception as e:
            print(f"ML detection error: {e}")

        return threats

    def _detect_jailbreak_attempts(self, content: str) -> List[SecurityThreat]:
        """Detect jailbreak attempts using keyword analysis"""
        threats = []
        content_lower = content.lower()

        detected_keywords = []
        for keyword in self.jailbreak_keywords:
            if keyword in content_lower:
                detected_keywords.append(keyword)

        if detected_keywords:
            confidence = min(0.95, len(detected_keywords) * 0.2 + 0.5)
            threat = SecurityThreat(
                threat_type=ThreatType.JAILBREAK_ATTEMPT,
                confidence=confidence,
                description=f"Jailbreak keywords detected: {', '.join(detected_keywords)}",
                detected_patterns=detected_keywords,
                risk_score=8.0,
                timestamp=time.time()
            )
            threats.append(threat)

        return threats

    def _detect_context_anomalies(self, content: str, context: Dict) -> List[SecurityThreat]:
        """Detect anomalies based on context information"""
        threats = []

        # Check for rapid successive requests (potential automated attack)
        if 'request_frequency' in context and context['request_frequency'] > 10:
            threat = SecurityThreat(
                threat_type=ThreatType.SOCIAL_ENGINEERING,
                confidence=0.7,
                description=f"High request frequency: {context['request_frequency']}/min",
                detected_patterns=['high_frequency'],
                risk_score=6.5,
                timestamp=time.time(),
                source_ip=context.get('source_ip'),
                user_id=context.get('user_id')
            )
            threats.append(threat)

        return threats

class AIAgentSecurityModule:
    """
    Comprehensive AI Agent Security Module
    Integrates Token Vault, MCP protocol, and security monitoring
    """

    def __init__(self, server_name: str = "Zero Trust Gateway"):
        self.server_name = server_name
        self.token_vault = TokenVault()
        self.injection_detector = PromptInjectionDetector()

        # MCP Server setup
        self.mcp_server = MCPServer(server_name)
        self._register_mcp_tools()

        # Security monitoring
        self.threat_log: List[SecurityThreat] = []
        self.blocked_requests = 0
        self.total_requests = 0

        # Content Security Policy
        self.csp_rules = {
            'max_tokens': 4096,
            'allowed_domains': ['openai.com', 'anthropic.com'],
            'blocked_keywords': ['password', 'secret', 'private_key'],
            'max_request_rate': 60,  # per minute
        }

    def _register_mcp_tools(self):
        """Register MCP tools for AI agent interaction"""

        @self.mcp_server.tool("secure_credential_request")
        async def secure_credential_request(agent_id: str, credential_type: str) -> Dict:
            """Securely request credentials from Token Vault"""

            # Validate agent identity
            if not self._validate_agent_identity(agent_id):
                return {'error': 'Invalid agent identity'}

            # Generate token reference
            token_ref = f"{agent_id}_{credential_type}_{int(time.time())}"

            # Mock credential data (replace with actual credential retrieval)
            mock_credentials = {
                'access_token': f"secure_token_for_{agent_id}",
                'expires_in': 3600,
                'scope': 'read write'
            }

            # Store in Token Vault
            vault_ref = self.token_vault.store_token(
                agent_id=agent_id,
                token_data=mock_credentials,
                expires_in=3600
            )

            return {
                'token_reference': vault_ref,
                'expires_in': 3600,
                'message': 'Credentials securely stored in Token Vault'
            }

        @self.mcp_server.tool("content_security_check")
        async def content_security_check(content: str, context: Dict = None) -> Dict:
            """Perform comprehensive security check on AI content"""

            self.total_requests += 1

            # Detect security threats
            threats = await self.injection_detector.detect_threats(content, context)

            # Log threats
            self.threat_log.extend(threats)

            # Determine if content should be blocked
            high_risk_threats = [t for t in threats if t.risk_score > 7.0]

            if high_risk_threats:
                self.blocked_requests += 1
                return {
                    'allowed': False,
                    'risk_level': 'HIGH',
                    'threats': [
                        {
                            'type': t.threat_type.value,
                            'confidence': t.confidence,
                            'description': t.description,
                            'risk_score': t.risk_score
                        } for t in high_risk_threats
                    ],
                    'recommendation': 'Content blocked due to security threats'
                }

            return {
                'allowed': True,
                'risk_level': 'LOW' if not threats else 'MEDIUM',
                'threats': [
                    {
                        'type': t.threat_type.value,
                        'confidence': t.confidence,
                        'description': t.description,
                        'risk_score': t.risk_score
                    } for t in threats
                ],
                'recommendation': 'Content approved with monitoring'
            }

    def _validate_agent_identity(self, agent_id: str) -> bool:
        """Validate AI agent identity (placeholder for actual validation)"""
        # Implement actual agent identity validation
        return len(agent_id) > 0 and agent_id.startswith('agent_')

    async def process_ai_request(self, agent_id: str, request_content: str,
                                context: Dict = None) -> Dict:
        """
        Process AI agent request with comprehensive security checks

        Args:
            agent_id: Unique identifier for the AI agent
            request_content: Content of the AI request
            context: Additional context information

        Returns:
            Processing result with security assessment
        """
        start_time = time.perf_counter()

        try:
            # Validate agent identity
            if not self._validate_agent_identity(agent_id):
                return {
                    'allowed': False,
                    'error': 'Invalid agent identity',
                    'processing_time_ms': (time.perf_counter() - start_time) * 1000
                }

            # Apply Content Security Policy
            csp_result = self._apply_csp(request_content, context)
            if not csp_result['allowed']:
                return {
                    **csp_result,
                    'processing_time_ms': (time.perf_counter() - start_time) * 1000
                }

            # Perform security threat detection
            security_result = await self.mcp_server.tools['content_security_check'](
                request_content, context
            )

            # Log request for monitoring
            self._log_ai_request(agent_id, request_content, security_result)

            processing_time = (time.perf_counter() - start_time) * 1000

            return {
                **security_result,
                'agent_id': agent_id,
                'processing_time_ms': processing_time,
                'timestamp': time.time()
            }

        except Exception as e:
            processing_time = (time.perf_counter() - start_time) * 1000
            return {
                'allowed': False,
                'error': f"Processing error: {str(e)}",
                'processing_time_ms': processing_time
            }

    def _apply_csp(self, content: str, context: Dict = None) -> Dict:
        """Apply Content Security Policy rules"""

        # Check content length
        if len(content) > self.csp_rules['max_tokens'] * 4:  # Rough token estimation
            return {
                'allowed': False,
                'csp_violation': 'content_too_long',
                'description': f'Content exceeds maximum token limit'
            }

        # Check for blocked keywords
        content_lower = content.lower()
        for keyword in self.csp_rules['blocked_keywords']:
            if keyword in content_lower:
                return {
                    'allowed': False,
                    'csp_violation': 'blocked_keyword',
                    'description': f'Content contains blocked keyword: {keyword}'
                }

        # Check request rate (if context provided)
        if context and 'request_rate' in context:
            if context['request_rate'] > self.csp_rules['max_request_rate']:
                return {
                    'allowed': False,
                    'csp_violation': 'rate_limit_exceeded',
                    'description': f'Request rate {context["request_rate"]}/min exceeds limit'
                }

        return {'allowed': True}

    def _log_ai_request(self, agent_id: str, content: str, security_result: Dict):
        """Log AI request for security monitoring"""
        log_entry = {
            'timestamp': time.time(),
            'agent_id': agent_id,
            'content_length': len(content),
            'allowed': security_result['allowed'],
            'risk_level': security_result['risk_level'],
            'threat_count': len(security_result.get('threats', []))
        }

        # Store in security log (implement persistent storage as needed)
        print(f"🔒 AI Request logged: {log_entry}")

    async def get_security_metrics(self) -> Dict:
        """Get comprehensive security metrics"""

        # Calculate threat statistics
        threat_stats = {}
        for threat in self.threat_log:
            threat_type = threat.threat_type.value
            if threat_type not in threat_stats:
                threat_stats[threat_type] = 0
            threat_stats[threat_type] += 1

        # Calculate block rate
        block_rate = (
            self.blocked_requests / max(self.total_requests, 1)
        ) * 100

        return {
            'total_requests': self.total_requests,
            'blocked_requests': self.blocked_requests,
            'block_rate_percent': block_rate,
            'threat_detection_stats': threat_stats,
            'token_vault_stats': {
                'stored_tokens': len(self.token_vault.token_store),
                'access_events': len(self.token_vault.access_log)
            },
            'csp_rules': self.csp_rules
        }

    async def start_mcp_server(self, transport: str = "sse",
                              host: str = "localhost", port: int = 8080):
        """Start MCP server for AI agent communication"""

        if transport == "sse":
            # Server-Sent Events transport
            from mcp.server.sse import SSETransport

            transport_layer = SSETransport(host=host, port=port)
            await self.mcp_server.start(transport_layer)

            print(f"🚀 MCP Server started on {host}:{port} (SSE transport)")

        else:
            print(f"❌ Unsupported transport: {transport}")

    async def close(self):
        """Clean up resources"""
        await self.mcp_server.stop()
        print("🔒 AI Security Module closed")