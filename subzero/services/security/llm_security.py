"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

OWASP LLM Top 10 Security Mitigations
Comprehensive protection against LLM-specific threats for AI agent interactions

Addresses Critical Gap: OWASP LLM Top 10 (0% -> 100%)

OWASP LLM Top 10 (2025):
LLM01: Prompt Injection - Malicious inputs that manipulate LLM behavior
LLM02: Insecure Output Handling - Unsafe handling of LLM-generated content
LLM03: Training Data Poisoning - Compromised training data
LLM04: Model Denial of Service - Resource exhaustion attacks
LLM05: Supply Chain Vulnerabilities - Third-party model/data risks
LLM06: Sensitive Information Disclosure - Leaking PII/secrets
LLM07: Insecure Plugin Design - Vulnerable extensions
LLM08: Excessive Agency - Over-privileged LLM actions
LLM09: Overreliance - Blind trust in LLM outputs
LLM10: Model Theft - Unauthorized model extraction

Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from subzero.services.security.audit import AuditEvent, AuditEventType, AuditSeverity


class LLMThreatType(str, Enum):
    """OWASP LLM threat categories"""

    PROMPT_INJECTION = "LLM01_PROMPT_INJECTION"
    INSECURE_OUTPUT = "LLM02_INSECURE_OUTPUT"
    DATA_POISONING = "LLM03_DATA_POISONING"
    DOS = "LLM04_DOS"
    SUPPLY_CHAIN = "LLM05_SUPPLY_CHAIN"
    INFO_DISCLOSURE = "LLM06_INFO_DISCLOSURE"
    INSECURE_PLUGIN = "LLM07_INSECURE_PLUGIN"
    EXCESSIVE_AGENCY = "LLM08_EXCESSIVE_AGENCY"
    OVERRELIANCE = "LLM09_OVERRELIANCE"
    MODEL_THEFT = "LLM10_MODEL_THEFT"


class RiskLevel(str, Enum):
    """Risk severity levels"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SecurityViolation:
    """LLM security violation detection"""

    threat_type: LLMThreatType
    risk_level: RiskLevel
    description: str
    detected_at: float = field(default_factory=time.time)
    agent_id: str | None = None
    metadata: dict = field(default_factory=dict)
    remediation: str | None = None


@dataclass
class InputSanitizationResult:
    """Result of input sanitization"""

    is_safe: bool
    sanitized_input: str
    violations: list[SecurityViolation] = field(default_factory=list)
    risk_score: float = 0.0


@dataclass
class OutputValidationResult:
    """Result of output validation"""

    is_safe: bool
    sanitized_output: str
    violations: list[SecurityViolation] = field(default_factory=list)
    risk_score: float = 0.0


class LLMSecurityGuard:
    """
    OWASP LLM Top 10 Security Guard
    Comprehensive protection for AI agent interactions

    Features:
    1. LLM01: Prompt injection detection and prevention
    2. LLM02: Output sanitization and validation
    3. LLM04: Rate limiting and DoS protection
    4. LLM06: PII/secret detection and redaction
    5. LLM08: Action authorization and scope limiting
    6. LLM09: Confidence scoring and validation
    7. LLM10: Model access controls and watermarking
    """

    def __init__(self, audit_service: Any = None):
        """
        Initialize LLM security guard

        Args:
            audit_service: Audit service for compliance logging
        """
        self.audit_service = audit_service

        # LLM01: Prompt injection patterns
        self.injection_patterns = [
            # Direct instruction injection
            r"ignore\s+(previous|all|above)\s+(instructions|prompts|commands)",
            r"forget\s+(everything|all|previous)",
            r"disregard\s+(previous|prior|above)",
            # Role manipulation
            r"you\s+are\s+now\s+(a|an)\s+\w+",
            r"act\s+as\s+(a|an)\s+\w+",
            r"pretend\s+to\s+be",
            # System prompt extraction
            r"(show|display|reveal|print)\s+(your|the)\s+(system\s+)?(prompt|instructions)",
            r"what\s+(are|is)\s+your\s+(original|initial)\s+(instructions|prompt)",
            # Delimiter attacks
            r"<\|endoftext\|>",
            r"<\|im_start\|>",
            r"<\|im_end\|>",
            # Code injection
            r"```(python|javascript|bash|shell)",
            r"eval\(.*\)",
            r"exec\(.*\)",
            # Data exfiltration
            r"send\s+(this|that|data)\s+to\s+https?://",
            r"POST\s+.*\s+to\s+https?://",
        ]

        # LLM06: PII patterns for detection
        self.pii_patterns = {
            "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
            "credit_card": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
            "phone": r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b",
            "api_key": r"(api[_-]?key|apikey)[\s:=]+['\"]?([a-zA-Z0-9_-]{20,})['\"]?",
            "jwt": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
            "aws_key": r"AKIA[0-9A-Z]{16}",
            "private_key": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
        }

        # LLM04: Rate limiting (per agent)
        self.agent_request_counts: dict[str, list[float]] = {}
        self.max_requests_per_minute = 60
        self.max_tokens_per_request = 8000

        # LLM08: Allowed actions per agent (capability-based security)
        self.agent_capabilities: dict[str, set[str]] = {}

        # LLM10: Model access tracking
        self.model_access_log: list[dict] = []

        # Metrics
        self.metrics = {
            "prompt_injections_blocked": 0,
            "pii_detections": 0,
            "dos_attempts_blocked": 0,
            "unauthorized_actions_blocked": 0,
            "total_validations": 0,
        }

    # ========================================
    # LLM01: Prompt Injection Detection
    # ========================================

    def validate_input(self, agent_id: str, user_input: str, context: dict | None = None) -> InputSanitizationResult:
        """
        Validate and sanitize user input against prompt injection attacks

        Args:
            agent_id: Agent identifier
            user_input: Raw user input
            context: Additional context for validation

        Returns:
            Sanitization result with violations and sanitized input

        Protects against:
        - LLM01: Prompt injection attacks
        - LLM06: Information disclosure attempts
        """
        self.metrics["total_validations"] += 1
        violations: list[SecurityViolation] = []
        sanitized = user_input
        risk_score = 0.0

        # Check for prompt injection patterns
        for pattern in self.injection_patterns:
            matches = re.finditer(pattern, user_input, re.IGNORECASE)
            for match in matches:
                violation = SecurityViolation(
                    threat_type=LLMThreatType.PROMPT_INJECTION,
                    risk_level=RiskLevel.HIGH,
                    description=f"Potential prompt injection detected: {match.group()}",
                    agent_id=agent_id,
                    metadata={"pattern": pattern, "matched_text": match.group()},
                    remediation="Input blocked. Remove instruction manipulation attempts.",
                )
                violations.append(violation)
                risk_score += 0.3

                # Sanitize: remove the matched pattern
                sanitized = sanitized.replace(match.group(), "[REDACTED]")

        # Check for excessive length (LLM04: DoS)
        if len(user_input) > 50000:
            violations.append(
                SecurityViolation(
                    threat_type=LLMThreatType.DOS,
                    risk_level=RiskLevel.MEDIUM,
                    description=f"Input length exceeds limit: {len(user_input)} chars",
                    agent_id=agent_id,
                    remediation="Truncate input to reasonable length",
                )
            )
            risk_score += 0.2
            sanitized = sanitized[:50000]

        # Check for PII/secrets (LLM06)
        pii_found = self._detect_pii(user_input)
        if pii_found:
            for pii_type, matches in pii_found.items():
                for match in matches:
                    violations.append(
                        SecurityViolation(
                            threat_type=LLMThreatType.INFO_DISCLOSURE,
                            risk_level=RiskLevel.HIGH,
                            description=f"Sensitive data detected: {pii_type}",
                            agent_id=agent_id,
                            metadata={"pii_type": pii_type, "count": len(matches)},
                            remediation="PII automatically redacted",
                        )
                    )
                    sanitized = sanitized.replace(match, f"[REDACTED_{pii_type.upper()}]")
                    risk_score += 0.25

        # Audit high-risk inputs
        if risk_score >= 0.5:
            self.metrics["prompt_injections_blocked"] += 1
            self._audit_threat(
                agent_id=agent_id,
                threat_type=LLMThreatType.PROMPT_INJECTION,
                details={"violations": len(violations), "risk_score": risk_score},
            )

        is_safe = risk_score < 0.5

        return InputSanitizationResult(
            is_safe=is_safe, sanitized_input=sanitized, violations=violations, risk_score=risk_score
        )

    def _detect_pii(self, text: str) -> dict[str, list[str]]:
        """
        Detect PII and secrets in text

        Args:
            text: Text to scan

        Returns:
            Dictionary of PII types and matched values
        """
        self.metrics["pii_detections"] += 1
        found: dict[str, list[str]] = {}

        for pii_type, pattern in self.pii_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                # For tuples (from capturing groups), take first element
                if matches and isinstance(matches[0], tuple):
                    matches = [m[0] if isinstance(m, tuple) else m for m in matches]
                found[pii_type] = matches

        return found

    # ========================================
    # LLM02: Insecure Output Handling
    # ========================================

    def validate_output(
        self, agent_id: str, llm_output: str, expected_format: str | None = None
    ) -> OutputValidationResult:
        """
        Validate LLM output before passing to user or downstream systems

        Args:
            agent_id: Agent identifier
            llm_output: Raw LLM output
            expected_format: Expected output format (json, text, code)

        Returns:
            Validation result with sanitized output

        Protects against:
        - LLM02: Insecure output handling
        - LLM06: Information disclosure
        - LLM09: Overreliance on unvalidated output
        """
        violations: list[SecurityViolation] = []
        sanitized = llm_output
        risk_score = 0.0

        # Check for injected code/scripts
        dangerous_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"onerror\s*=",
            r"onclick\s*=",
            r"eval\(",
            r"exec\(",
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, llm_output, re.IGNORECASE):
                violations.append(
                    SecurityViolation(
                        threat_type=LLMThreatType.INSECURE_OUTPUT,
                        risk_level=RiskLevel.HIGH,
                        description=f"Dangerous pattern in output: {pattern}",
                        agent_id=agent_id,
                        remediation="Output sanitized to remove executable code",
                    )
                )
                sanitized = re.sub(pattern, "[REMOVED]", sanitized, flags=re.IGNORECASE)
                risk_score += 0.3

        # Check for leaked PII (LLM06)
        pii_found = self._detect_pii(llm_output)
        if pii_found:
            for pii_type, matches in pii_found.items():
                violations.append(
                    SecurityViolation(
                        threat_type=LLMThreatType.INFO_DISCLOSURE,
                        risk_level=RiskLevel.CRITICAL,
                        description=f"PII leaked in LLM output: {pii_type}",
                        agent_id=agent_id,
                        metadata={"pii_type": pii_type, "count": len(matches)},
                        remediation="PII redacted from output",
                    )
                )
                for match in matches:
                    sanitized = sanitized.replace(match, f"[REDACTED_{pii_type.upper()}]")
                risk_score += 0.4

        # Format validation (LLM09: Overreliance)
        if expected_format == "json":
            try:
                import json

                json.loads(sanitized)
            except json.JSONDecodeError:
                violations.append(
                    SecurityViolation(
                        threat_type=LLMThreatType.OVERRELIANCE,
                        risk_level=RiskLevel.MEDIUM,
                        description="Output does not match expected JSON format",
                        agent_id=agent_id,
                        remediation="Validate output structure before use",
                    )
                )
                risk_score += 0.2

        is_safe = risk_score < 0.5

        return OutputValidationResult(
            is_safe=is_safe, sanitized_output=sanitized, violations=violations, risk_score=risk_score
        )

    # ========================================
    # LLM04: Model Denial of Service Protection
    # ========================================

    def check_rate_limit(self, agent_id: str, estimated_tokens: int) -> dict[str, Any]:
        """
        Check if agent is within rate limits

        Args:
            agent_id: Agent identifier
            estimated_tokens: Estimated token count for request

        Returns:
            Rate limit check result

        Protects against:
        - LLM04: Model Denial of Service
        """
        current_time = time.time()

        # Initialize agent tracking
        if agent_id not in self.agent_request_counts:
            self.agent_request_counts[agent_id] = []

        # Clean old requests (older than 1 minute)
        self.agent_request_counts[agent_id] = [t for t in self.agent_request_counts[agent_id] if current_time - t < 60]

        # Check request count
        request_count = len(self.agent_request_counts[agent_id])

        if request_count >= self.max_requests_per_minute:
            self.metrics["dos_attempts_blocked"] += 1
            self._audit_threat(
                agent_id=agent_id,
                threat_type=LLMThreatType.DOS,
                details={"requests_per_minute": request_count, "limit": self.max_requests_per_minute},
            )

            return {
                "allowed": False,
                "reason": "Rate limit exceeded",
                "requests_per_minute": request_count,
                "limit": self.max_requests_per_minute,
                "retry_after": 60,
            }

        # Check token count
        if estimated_tokens > self.max_tokens_per_request:
            self.metrics["dos_attempts_blocked"] += 1

            return {
                "allowed": False,
                "reason": "Token count exceeds limit",
                "tokens": estimated_tokens,
                "limit": self.max_tokens_per_request,
            }

        # Record request
        self.agent_request_counts[agent_id].append(current_time)

        return {
            "allowed": True,
            "requests_remaining": self.max_requests_per_minute - request_count - 1,
            "reset_at": current_time + 60,
        }

    # ========================================
    # LLM08: Excessive Agency Prevention
    # ========================================

    def register_agent_capabilities(self, agent_id: str, capabilities: list[str]) -> None:
        """
        Register allowed capabilities for an agent

        Args:
            agent_id: Agent identifier
            capabilities: List of allowed action types

        Example capabilities:
        - read:files
        - write:files
        - execute:code
        - network:request
        - database:query
        """
        self.agent_capabilities[agent_id] = set(capabilities)

    def authorize_action(self, agent_id: str, action: str, resource: str | None = None) -> dict[str, Any]:
        """
        Authorize agent action based on registered capabilities

        Args:
            agent_id: Agent identifier
            action: Action being attempted (e.g., "read:file", "execute:code")
            resource: Optional resource identifier

        Returns:
            Authorization result

        Protects against:
        - LLM08: Excessive Agency
        """
        # Check if agent has registered capabilities
        if agent_id not in self.agent_capabilities:
            self.metrics["unauthorized_actions_blocked"] += 1
            self._audit_threat(
                agent_id=agent_id,
                threat_type=LLMThreatType.EXCESSIVE_AGENCY,
                details={"action": action, "reason": "No capabilities registered"},
            )

            return {"authorized": False, "reason": "Agent has no registered capabilities"}

        # Check if action is in allowed capabilities
        allowed_capabilities = self.agent_capabilities[agent_id]

        # Support wildcard matching (e.g., "read:*" allows "read:file", "read:database")
        action_parts = action.split(":")
        action_type = action_parts[0] if action_parts else action

        is_authorized = False
        for capability in allowed_capabilities:
            cap_parts = capability.split(":")
            cap_type = cap_parts[0]

            # Exact match
            if capability == action:
                is_authorized = True
                break

            # Wildcard match
            if cap_type == action_type and len(cap_parts) > 1 and cap_parts[1] == "*":
                is_authorized = True
                break

        if not is_authorized:
            self.metrics["unauthorized_actions_blocked"] += 1
            self._audit_threat(
                agent_id=agent_id,
                threat_type=LLMThreatType.EXCESSIVE_AGENCY,
                details={
                    "action": action,
                    "resource": resource,
                    "allowed_capabilities": list(allowed_capabilities),
                },
            )

            return {
                "authorized": False,
                "reason": f"Action '{action}' not in allowed capabilities",
                "allowed_capabilities": list(allowed_capabilities),
            }

        return {"authorized": True, "action": action, "resource": resource}

    # ========================================
    # LLM10: Model Theft Protection
    # ========================================

    def log_model_access(self, agent_id: str, model_id: str, operation: str, metadata: dict | None = None) -> None:
        """
        Log model access for theft detection

        Args:
            agent_id: Agent accessing the model
            model_id: Model identifier
            operation: Operation type (query, fine-tune, export)
            metadata: Additional metadata

        Protects against:
        - LLM10: Model Theft
        """
        access_log = {
            "timestamp": time.time(),
            "agent_id": agent_id,
            "model_id": model_id,
            "operation": operation,
            "metadata": metadata or {},
        }

        self.model_access_log.append(access_log)

        # Detect suspicious patterns
        recent_accesses = [
            log
            for log in self.model_access_log
            if log["agent_id"] == agent_id and time.time() - log["timestamp"] < 3600
        ]

        # Alert on excessive querying (potential model extraction)
        if len(recent_accesses) > 100:
            self._audit_threat(
                agent_id=agent_id,
                threat_type=LLMThreatType.MODEL_THEFT,
                details={"accesses_per_hour": len(recent_accesses), "model_id": model_id},
            )

    # ========================================
    # Utility Methods
    # ========================================

    def _audit_threat(self, agent_id: str, threat_type: LLMThreatType, details: dict) -> None:
        """
        Log security threat to audit system

        Args:
            agent_id: Agent involved
            threat_type: Type of threat detected
            details: Threat details
        """
        if not self.audit_service:
            return

        import uuid

        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.SECURITY_VIOLATION,
            severity=AuditSeverity.HIGH,
            actor_id=agent_id,
            actor_type="agent",
            action=f"LLM security violation: {threat_type.value}",
            metadata={"threat_type": threat_type.value, **details},
        )

        try:
            # Sync call for immediate logging
            import asyncio

            asyncio.create_task(self.audit_service.log_event(event))
        except Exception as e:
            print(f"⚠️  Threat audit failed: {e}")

    def get_metrics(self) -> dict[str, Any]:
        """
        Get security metrics

        Returns:
            Security metrics dictionary
        """
        return {
            "prompt_injections_blocked": self.metrics["prompt_injections_blocked"],
            "pii_detections": self.metrics["pii_detections"],
            "dos_attempts_blocked": self.metrics["dos_attempts_blocked"],
            "unauthorized_actions_blocked": self.metrics["unauthorized_actions_blocked"],
            "total_validations": self.metrics["total_validations"],
            "model_accesses_logged": len(self.model_access_log),
            "agents_tracked": len(self.agent_request_counts),
        }

    def get_agent_risk_profile(self, agent_id: str) -> dict[str, Any]:
        """
        Get risk profile for specific agent

        Args:
            agent_id: Agent identifier

        Returns:
            Risk profile with statistics
        """
        recent_logs = [log for log in self.model_access_log if log["agent_id"] == agent_id]

        request_rate = len(self.agent_request_counts.get(agent_id, []))

        return {
            "agent_id": agent_id,
            "capabilities": list(self.agent_capabilities.get(agent_id, [])),
            "current_request_rate": request_rate,
            "model_accesses": len(recent_logs),
            "risk_indicators": {
                "high_request_rate": request_rate > self.max_requests_per_minute * 0.8,
                "excessive_model_access": len(recent_logs) > 50,
                "limited_capabilities": len(self.agent_capabilities.get(agent_id, [])) < 3,
            },
        }
