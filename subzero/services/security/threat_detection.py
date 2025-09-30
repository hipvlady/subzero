"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

Advanced Threat Detection Module
Detection for Auth0's 2025 threat landscape

Addresses:
- Signup Attack Prevention (46.1% fraudulent registrations)
- Account Takeover (ATO) Protection (16.9% malicious logins)
- MFA Abuse Detection (7.3% malicious MFA events)
- AI Hallucination Detection
"""

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum


class ThreatType(str, Enum):
    """Types of threats"""

    SIGNUP_FRAUD = "signup_fraud"
    ACCOUNT_TAKEOVER = "account_takeover"
    MFA_ABUSE = "mfa_abuse"
    CREDENTIAL_STUFFING = "credential_stuffing"
    BOT_ATTACK = "bot_attack"
    HALLUCINATION = "ai_hallucination"


@dataclass
class ThreatSignal:
    """Individual threat signal"""

    signal_id: str
    threat_type: ThreatType
    confidence: float  # 0.0-1.0
    severity: int  # 1-10
    evidence: dict
    detected_at: float = field(default_factory=time.time)


@dataclass
class ThreatAssessment:
    """Complete threat assessment"""

    entity_id: str  # Agent/user/IP
    threat_score: float  # 0.0-1.0
    signals: list[ThreatSignal]
    recommendation: str
    should_block: bool = False


class SignupFraudDetector:
    """
    Detect fraudulent signup attempts
    Target: 46.1% fraudulent registrations
    """

    def __init__(self):
        # Known fraud patterns
        self.suspicious_domains = {
            "tempmail.com",
            "guerrillamail.com",
            "mailinator.com",
            "10minutemail.com",
            "throwaway.email",
        }

        # IP reputation cache
        self.ip_reputation: dict[str, float] = {}

        # Signup velocity tracking: email_domain -> signup_count
        self.signup_velocity: dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

        # Device fingerprint tracking
        self.device_fingerprints: set[str] = set()

    async def detect(
        self, email: str, ip_address: str, user_agent: str, metadata: dict | None = None
    ) -> list[ThreatSignal]:
        """
        Detect signup fraud signals

        Args:
            email: Email address
            ip_address: Source IP
            user_agent: User agent string
            metadata: Additional signup metadata

        Returns:
            List of threat signals
        """
        signals = []

        # Check disposable email
        domain = email.split("@")[-1].lower()

        if domain in self.suspicious_domains:
            signals.append(
                ThreatSignal(
                    signal_id=f"signup_fraud_{int(time.time())}",
                    threat_type=ThreatType.SIGNUP_FRAUD,
                    confidence=0.9,
                    severity=8,
                    evidence={"reason": "disposable_email", "domain": domain},
                )
            )

        # Check IP reputation
        ip_risk = await self._check_ip_reputation(ip_address)

        if ip_risk > 0.7:
            signals.append(
                ThreatSignal(
                    signal_id=f"signup_fraud_ip_{int(time.time())}",
                    threat_type=ThreatType.SIGNUP_FRAUD,
                    confidence=ip_risk,
                    severity=7,
                    evidence={"reason": "suspicious_ip", "ip": ip_address, "risk": ip_risk},
                )
            )

        # Check signup velocity
        self.signup_velocity[domain].append(time.time())

        recent_signups = sum(1 for ts in self.signup_velocity[domain] if time.time() - ts < 3600)  # Last hour

        if recent_signups > 10:  # >10 signups/hour from domain
            signals.append(
                ThreatSignal(
                    signal_id=f"signup_velocity_{int(time.time())}",
                    threat_type=ThreatType.SIGNUP_FRAUD,
                    confidence=0.8,
                    severity=6,
                    evidence={"reason": "high_velocity", "signups_per_hour": recent_signups},
                )
            )

        # Check bot indicators in user agent
        if self._is_bot_user_agent(user_agent):
            signals.append(
                ThreatSignal(
                    signal_id=f"bot_signup_{int(time.time())}",
                    threat_type=ThreatType.BOT_ATTACK,
                    confidence=0.85,
                    severity=7,
                    evidence={"reason": "bot_user_agent", "user_agent": user_agent},
                )
            )

        return signals

    async def _check_ip_reputation(self, ip_address: str) -> float:
        """Check IP reputation (0.0 = good, 1.0 = bad)"""
        # Check cache
        if ip_address in self.ip_reputation:
            return self.ip_reputation[ip_address]

        # Placeholder - integrate with IP reputation service
        # For now, flag Tor/VPN ranges as medium risk
        if ip_address.startswith(("10.", "192.168.", "172.")):
            risk = 0.1  # Internal IP = low risk
        else:
            risk = 0.3  # Default medium-low risk

        self.ip_reputation[ip_address] = risk

        return risk

    def _is_bot_user_agent(self, user_agent: str) -> bool:
        """Detect bot user agents"""
        bot_indicators = [
            "bot",
            "crawler",
            "spider",
            "scraper",
            "curl",
            "wget",
            "python-requests",
            "go-http-client",
            "okhttp",
        ]

        user_agent_lower = user_agent.lower()

        return any(indicator in user_agent_lower for indicator in bot_indicators)


class AccountTakeoverDetector:
    """
    Detect account takeover attempts
    Target: 16.9% malicious logins
    """

    def __init__(self):
        # Normal login patterns: user_id -> login_history
        self.login_patterns: dict[str, list[dict]] = defaultdict(list)

        # Failed login tracking: user_id -> failed_attempts
        self.failed_logins: dict[str, deque] = defaultdict(lambda: deque(maxlen=50))

    async def detect(
        self, user_id: str, ip_address: str, location: str | None = None, device_fingerprint: str | None = None
    ) -> list[ThreatSignal]:
        """
        Detect ATO signals

        Args:
            user_id: User identifier
            ip_address: Login IP
            location: Geographic location
            device_fingerprint: Device fingerprint

        Returns:
            List of threat signals
        """
        signals = []

        # Check for impossible travel
        if location and user_id in self.login_patterns:
            if self._detect_impossible_travel(user_id, location):
                signals.append(
                    ThreatSignal(
                        signal_id=f"ato_travel_{int(time.time())}",
                        threat_type=ThreatType.ACCOUNT_TAKEOVER,
                        confidence=0.9,
                        severity=9,
                        evidence={"reason": "impossible_travel", "location": location},
                    )
                )

        # Check for new device
        if device_fingerprint:
            if self._is_new_device(user_id, device_fingerprint):
                signals.append(
                    ThreatSignal(
                        signal_id=f"ato_device_{int(time.time())}",
                        threat_type=ThreatType.ACCOUNT_TAKEOVER,
                        confidence=0.6,
                        severity=5,
                        evidence={"reason": "new_device", "fingerprint": device_fingerprint},
                    )
                )

        # Check failed login history
        failed_count = len(
            [attempt for attempt in self.failed_logins[user_id] if time.time() - attempt < 3600]  # Last hour
        )

        if failed_count >= 3:
            signals.append(
                ThreatSignal(
                    signal_id=f"ato_brute_force_{int(time.time())}",
                    threat_type=ThreatType.ACCOUNT_TAKEOVER,
                    confidence=0.8,
                    severity=8,
                    evidence={"reason": "brute_force", "failed_attempts": failed_count},
                )
            )

        # Record login
        self.login_patterns[user_id].append(
            {"timestamp": time.time(), "ip": ip_address, "location": location, "device": device_fingerprint}
        )

        # Keep only last 100 logins
        if len(self.login_patterns[user_id]) > 100:
            self.login_patterns[user_id] = self.login_patterns[user_id][-100:]

        return signals

    def record_failed_login(self, user_id: str):
        """Record failed login attempt"""
        self.failed_logins[user_id].append(time.time())

    def _detect_impossible_travel(self, user_id: str, current_location: str) -> bool:
        """Detect impossible travel between locations"""
        if user_id not in self.login_patterns:
            return False

        recent_logins = [
            login for login in self.login_patterns[user_id] if time.time() - login["timestamp"] < 3600  # Last hour
        ]

        if not recent_logins:
            return False

        last_login = recent_logins[-1]
        last_location = last_login.get("location")

        if not last_location or last_location == current_location:
            return False

        # Simplified - in production, calculate actual distance
        return True  # Different locations within an hour

    def _is_new_device(self, user_id: str, device_fingerprint: str) -> bool:
        """Check if device is new for user"""
        if user_id not in self.login_patterns:
            return True

        known_devices = {login.get("device") for login in self.login_patterns[user_id] if login.get("device")}

        return device_fingerprint not in known_devices


class MFAAbuseDetector:
    """
    Detect MFA abuse
    Target: 7.3% malicious MFA events
    """

    def __init__(self):
        # MFA attempt tracking: user_id -> attempts
        self.mfa_attempts: dict[str, deque] = defaultdict(lambda: deque(maxlen=50))

        # Push notification bombing detection
        self.push_bombing: dict[str, deque] = defaultdict(lambda: deque(maxlen=20))

    async def detect(self, user_id: str, mfa_method: str, success: bool) -> list[ThreatSignal]:
        """
        Detect MFA abuse

        Args:
            user_id: User identifier
            mfa_method: MFA method (sms, totp, push)
            success: Whether MFA succeeded

        Returns:
            List of threat signals
        """
        signals = []

        # Record attempt
        self.mfa_attempts[user_id].append({"timestamp": time.time(), "method": mfa_method, "success": success})

        # Check for MFA fatigue/bombing
        if mfa_method == "push":
            self.push_bombing[user_id].append(time.time())

            recent_pushes = sum(1 for ts in self.push_bombing[user_id] if time.time() - ts < 300)  # Last 5 minutes

            if recent_pushes >= 5:
                signals.append(
                    ThreatSignal(
                        signal_id=f"mfa_bombing_{int(time.time())}",
                        threat_type=ThreatType.MFA_ABUSE,
                        confidence=0.9,
                        severity=8,
                        evidence={"reason": "push_bombing", "push_count": recent_pushes},
                    )
                )

        # Check for repeated failures
        recent_attempts = [
            attempt for attempt in self.mfa_attempts[user_id] if time.time() - attempt["timestamp"] < 3600  # Last hour
        ]

        failed_count = sum(1 for a in recent_attempts if not a["success"])

        if failed_count >= 10:
            signals.append(
                ThreatSignal(
                    signal_id=f"mfa_brute_force_{int(time.time())}",
                    threat_type=ThreatType.MFA_ABUSE,
                    confidence=0.8,
                    severity=7,
                    evidence={"reason": "mfa_brute_force", "failed_count": failed_count},
                )
            )

        return signals


class HallucinationDetector:
    """
    Detect AI hallucinations
    """

    def __init__(self):
        # Hallucination patterns
        self.known_hallucinations = {
            "fake_api_endpoints",
            "nonexistent_features",
            "false_statistics",
            "invented_quotes",
        }

    async def detect(self, generated_text: str, source_documents: list[str] | None = None) -> list[ThreatSignal]:
        """
        Detect AI hallucinations

        Args:
            generated_text: AI-generated text
            source_documents: Source documents used

        Returns:
            List of threat signals
        """
        signals = []

        # Check for confidence markers indicating uncertainty
        uncertainty_phrases = ["i think", "probably", "might be", "could be", "not sure", "it seems", "appears to be"]

        text_lower = generated_text.lower()
        found_uncertainty = [p for p in uncertainty_phrases if p in text_lower]

        if len(found_uncertainty) >= 2:
            signals.append(
                ThreatSignal(
                    signal_id=f"hallucination_{int(time.time())}",
                    threat_type=ThreatType.HALLUCINATION,
                    confidence=0.6,
                    severity=4,
                    evidence={"reason": "high_uncertainty", "phrases": found_uncertainty},
                )
            )

        # Check grounding if sources provided
        if source_documents:
            grounding_score = self._calculate_grounding(generated_text, source_documents)

            if grounding_score < 0.3:  # Low grounding
                signals.append(
                    ThreatSignal(
                        signal_id=f"hallucination_grounding_{int(time.time())}",
                        threat_type=ThreatType.HALLUCINATION,
                        confidence=0.8,
                        severity=7,
                        evidence={"reason": "poor_grounding", "grounding_score": grounding_score},
                    )
                )

        return signals

    def _calculate_grounding(self, text: str, sources: list[str]) -> float:
        """Calculate how well text is grounded in sources"""
        text_words = set(text.lower().split())
        source_words = set(" ".join(sources).lower().split())

        if not text_words:
            return 0.0

        overlap = len(text_words & source_words)
        return overlap / len(text_words)


class AdvancedThreatDetector:
    """
    Unified threat detection system
    """

    def __init__(self):
        self.signup_detector = SignupFraudDetector()
        self.ato_detector = AccountTakeoverDetector()
        self.mfa_detector = MFAAbuseDetector()
        self.hallucination_detector = HallucinationDetector()

        # Metrics
        self.detections_count = 0
        self.blocks_count = 0

    async def assess_threat(self, entity_id: str, context: dict) -> ThreatAssessment:
        """
        Comprehensive threat assessment

        Args:
            entity_id: Entity being assessed
            context: Assessment context

        Returns:
            Threat assessment
        """
        self.detections_count += 1
        all_signals = []

        # Run applicable detectors based on context
        if context.get("type") == "signup":
            signals = await self.signup_detector.detect(
                email=context["email"],
                ip_address=context["ip_address"],
                user_agent=context.get("user_agent", ""),
                metadata=context.get("metadata"),
            )
            all_signals.extend(signals)

        elif context.get("type") == "login":
            signals = await self.ato_detector.detect(
                user_id=entity_id,
                ip_address=context["ip_address"],
                location=context.get("location"),
                device_fingerprint=context.get("device_fingerprint"),
            )
            all_signals.extend(signals)

        elif context.get("type") == "mfa":
            signals = await self.mfa_detector.detect(
                user_id=entity_id, mfa_method=context["mfa_method"], success=context.get("success", False)
            )
            all_signals.extend(signals)

        elif context.get("type") == "ai_generation":
            signals = await self.hallucination_detector.detect(
                generated_text=context["generated_text"], source_documents=context.get("source_documents")
            )
            all_signals.extend(signals)

        # Calculate composite threat score
        threat_score = self._calculate_threat_score(all_signals)

        # Determine recommendation
        should_block = threat_score >= 0.7
        recommendation = self._generate_recommendation(all_signals, threat_score)

        if should_block:
            self.blocks_count += 1

        assessment = ThreatAssessment(
            entity_id=entity_id,
            threat_score=threat_score,
            signals=all_signals,
            recommendation=recommendation,
            should_block=should_block,
        )

        return assessment

    def _calculate_threat_score(self, signals: list[ThreatSignal]) -> float:
        """Calculate composite threat score"""
        if not signals:
            return 0.0

        # Weight by confidence and severity
        weighted_sum = sum(s.confidence * (s.severity / 10) for s in signals)

        return min(1.0, weighted_sum / len(signals))

    def _generate_recommendation(self, signals: list[ThreatSignal], score: float) -> str:
        """Generate recommendation based on signals"""
        if not signals:
            return "Allow - no threats detected"

        if score >= 0.9:
            return "BLOCK - Critical threat detected"
        elif score >= 0.7:
            return "BLOCK - High risk detected"
        elif score >= 0.5:
            return "CHALLENGE - Require additional verification"
        elif score >= 0.3:
            return "MONITOR - Elevated risk, monitor closely"
        else:
            return "ALLOW - Low risk"

    def get_metrics(self) -> dict:
        """Get threat detection metrics"""
        block_rate = (self.blocks_count / max(self.detections_count, 1)) * 100

        return {
            "detections_count": self.detections_count,
            "blocks_count": self.blocks_count,
            "block_rate_percent": block_rate,
        }
