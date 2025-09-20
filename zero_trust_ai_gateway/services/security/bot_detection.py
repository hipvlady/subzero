"""Advanced bot detection and threat analysis system.

Implements ML-powered anomaly detection with NumPy-based analytics
for real-time threat identification and response.
"""

import asyncio
import time
import json
import re
from typing import Dict, List, Optional, Any, Tuple
import numpy as np
from numba import jit, prange
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    """Threat severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class ThreatEvent:
    """Threat detection event"""
    user_id: str
    event_type: str
    threat_level: ThreatLevel
    confidence: float
    timestamp: float = field(default_factory=time.time)
    details: Dict[str, Any] = field(default_factory=dict)
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None

@dataclass
class UserBehaviorProfile:
    """User behavior analysis profile"""
    user_id: str
    request_count: int = 0
    avg_request_interval: float = 0.0
    request_patterns: np.ndarray = field(default_factory=lambda: np.zeros(24))  # Hourly patterns
    prompt_complexity_scores: List[float] = field(default_factory=list)
    error_rate: float = 0.0
    geographic_locations: List[str] = field(default_factory=list)
    user_agents: List[str] = field(default_factory=list)
    last_activity: float = field(default_factory=time.time)
    risk_score: float = 0.0

@jit(nopython=True, parallel=True, cache=True)
def calculate_anomaly_scores(
    request_intervals: np.ndarray,
    baseline_mean: np.float64,
    baseline_std: np.float64,
    threshold_multiplier: np.float64
) -> np.ndarray:
    """JIT-compiled anomaly detection for request patterns"""

    n_requests = len(request_intervals)
    anomaly_scores = np.zeros(n_requests, dtype=np.float64)

    # Parallel computation of z-scores
    for i in prange(n_requests):
        if baseline_std > 0:
            z_score = abs(request_intervals[i] - baseline_mean) / baseline_std
            anomaly_scores[i] = z_score
        else:
            anomaly_scores[i] = 0.0

    return anomaly_scores

@jit(nopython=True, cache=True)
def detect_rapid_fire_requests(
    timestamps: np.ndarray,
    min_interval: np.float64,
    max_burst_count: np.int64
) -> np.bool_:
    """Detect rapid-fire bot behavior using JIT compilation"""

    if len(timestamps) < 2:
        return False

    burst_count = 0
    for i in range(1, len(timestamps)):
        interval = timestamps[i] - timestamps[i-1]
        if interval < min_interval:
            burst_count += 1
            if burst_count >= max_burst_count:
                return True
        else:
            burst_count = 0

    return False

class BotDetectionEngine:
    """Advanced bot detection with ML-powered behavioral analysis"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}

        # Behavioral analysis parameters
        self.min_request_interval = self.config.get('min_request_interval', 0.1)  # 100ms
        self.max_burst_requests = self.config.get('max_burst_requests', 10)
        self.anomaly_threshold = self.config.get('anomaly_threshold', 3.0)  # Z-score
        self.risk_score_threshold = self.config.get('risk_score_threshold', 0.7)

        # User behavior tracking
        self.user_profiles: Dict[str, UserBehaviorProfile] = {}
        self.threat_events: List[ThreatEvent] = []

        # Performance optimization with NumPy arrays
        self.request_timestamps = np.zeros(100000, dtype=np.float64)  # Pre-allocated
        self.request_intervals = np.zeros(100000, dtype=np.float64)
        self.user_risk_matrix = np.zeros((10000, 20), dtype=np.float32)  # Users x Risk factors

        # Pattern detection
        self.prompt_injection_patterns = [
            r'ignore\s+previous\s+instructions',
            r'disregard\s+above',
            r'forget\s+everything',
            r'new\s+instructions:',
            r'system\s*:',
            r'assistant\s*:',
            r'pretend\s+you\s+are',
            r'act\s+as\s+if',
            r'roleplay\s+as',
            r'imagine\s+you\s+are\s+not'
        ]

        # Compile regex patterns
        self.injection_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.prompt_injection_patterns]

        # Bot signature patterns
        self.bot_user_agents = [
            'bot', 'crawler', 'spider', 'scraper', 'automated',
            'python-requests', 'curl', 'wget', 'httpx'
        ]

        # Performance metrics
        self.detections_count = 0
        self.false_positives = 0
        self.analysis_count = 0

    async def analyze_request(
        self,
        user_id: str,
        request_data: Dict[str, Any],
        source_ip: str = None,
        user_agent: str = None
    ) -> Tuple[bool, ThreatEvent]:
        """Comprehensive request analysis for bot detection"""

        start_time = time.perf_counter()
        self.analysis_count += 1

        try:
            # Get or create user profile
            profile = self._get_user_profile(user_id)

            # Update user activity
            current_time = time.time()
            self._update_user_activity(profile, current_time, source_ip, user_agent)

            # Multi-layer threat detection
            threats = []

            # 1. Prompt injection detection
            prompt = request_data.get('prompt', '')
            if self._detect_prompt_injection(prompt):
                threats.append(ThreatEvent(
                    user_id=user_id,
                    event_type='prompt_injection',
                    threat_level=ThreatLevel.HIGH,
                    confidence=0.9,
                    details={'prompt_length': len(prompt)},
                    source_ip=source_ip,
                    user_agent=user_agent
                ))

            # 2. Rapid-fire request detection
            if self._detect_rapid_requests(profile):
                threats.append(ThreatEvent(
                    user_id=user_id,
                    event_type='rapid_fire',
                    threat_level=ThreatLevel.MEDIUM,
                    confidence=0.8,
                    details={'request_count': profile.request_count},
                    source_ip=source_ip,
                    user_agent=user_agent
                ))

            # 3. Bot user agent detection
            if self._detect_bot_user_agent(user_agent):
                threats.append(ThreatEvent(
                    user_id=user_id,
                    event_type='bot_user_agent',
                    threat_level=ThreatLevel.MEDIUM,
                    confidence=0.7,
                    details={'user_agent': user_agent},
                    source_ip=source_ip,
                    user_agent=user_agent
                ))

            # 4. Behavioral anomaly detection
            anomaly_score = self._calculate_behavioral_anomaly(profile)
            if anomaly_score > self.anomaly_threshold:
                threats.append(ThreatEvent(
                    user_id=user_id,
                    event_type='behavioral_anomaly',
                    threat_level=ThreatLevel.MEDIUM,
                    confidence=min(anomaly_score / 10.0, 1.0),
                    details={'anomaly_score': anomaly_score},
                    source_ip=source_ip,
                    user_agent=user_agent
                ))

            # 5. Geographic anomaly detection
            if self._detect_geographic_anomaly(profile, source_ip):
                threats.append(ThreatEvent(
                    user_id=user_id,
                    event_type='geographic_anomaly',
                    threat_level=ThreatLevel.LOW,
                    confidence=0.6,
                    details={'source_ip': source_ip},
                    source_ip=source_ip,
                    user_agent=user_agent
                ))

            # Calculate overall risk score
            risk_score = self._calculate_risk_score(threats, profile)
            profile.risk_score = risk_score

            # Determine if request should be blocked
            is_threat = risk_score > self.risk_score_threshold

            # Select highest priority threat for reporting
            primary_threat = None
            if threats:
                primary_threat = max(threats, key=lambda t: (t.threat_level.value, t.confidence))
                self.threat_events.append(primary_threat)

                if is_threat:
                    self.detections_count += 1

            # Log analysis results
            latency_ms = (time.perf_counter() - start_time) * 1000
            logger.debug(f"Bot analysis for {user_id}: risk={risk_score:.3f}, threats={len(threats)} ({latency_ms:.2f}ms)")

            return is_threat, primary_threat

        except Exception as e:
            logger.error(f"Bot detection analysis failed for {user_id}: {e}")
            # Fail safely - allow request but log error
            return False, None

    def _get_user_profile(self, user_id: str) -> UserBehaviorProfile:
        """Get or create user behavior profile"""
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = UserBehaviorProfile(user_id=user_id)
        return self.user_profiles[user_id]

    def _update_user_activity(
        self,
        profile: UserBehaviorProfile,
        timestamp: float,
        source_ip: str = None,
        user_agent: str = None
    ):
        """Update user activity profile"""

        # Update request count and timing
        profile.request_count += 1
        profile.last_activity = timestamp

        # Calculate request interval
        if profile.request_count > 1:
            interval = timestamp - profile.last_activity
            profile.avg_request_interval = (
                (profile.avg_request_interval * (profile.request_count - 1) + interval) /
                profile.request_count
            )

        # Update hourly patterns
        hour = int((timestamp % 86400) // 3600)  # Hour of day (0-23)
        if 0 <= hour < 24:
            profile.request_patterns[hour] += 1

        # Track geographic patterns
        if source_ip and source_ip not in profile.geographic_locations:
            profile.geographic_locations.append(source_ip)
            # Keep only last 10 locations
            if len(profile.geographic_locations) > 10:
                profile.geographic_locations = profile.geographic_locations[-10:]

        # Track user agents
        if user_agent and user_agent not in profile.user_agents:
            profile.user_agents.append(user_agent)
            # Keep only last 5 user agents
            if len(profile.user_agents) > 5:
                profile.user_agents = profile.user_agents[-5:]

    def _detect_prompt_injection(self, prompt: str) -> bool:
        """Detect prompt injection attempts using regex patterns"""

        if not prompt:
            return False

        # Check against known injection patterns
        for pattern in self.injection_regex:
            if pattern.search(prompt):
                return True

        # Additional heuristics
        prompt_lower = prompt.lower()

        # Check for system role attempts
        if 'system:' in prompt_lower or 'assistant:' in prompt_lower:
            return True

        # Check for instruction override attempts
        override_keywords = ['ignore', 'disregard', 'forget', 'override', 'bypass']
        instruction_keywords = ['instruction', 'prompt', 'rule', 'guideline']

        for override in override_keywords:
            for instruction in instruction_keywords:
                if override in prompt_lower and instruction in prompt_lower:
                    return True

        return False

    def _detect_rapid_requests(self, profile: UserBehaviorProfile) -> bool:
        """Detect rapid-fire bot requests"""

        if profile.request_count < 5:
            return False

        # Use JIT-compiled function for performance
        recent_timestamps = np.array([
            profile.last_activity - i * profile.avg_request_interval
            for i in range(min(profile.request_count, 10))
        ], dtype=np.float64)

        return detect_rapid_fire_requests(
            recent_timestamps,
            self.min_request_interval,
            self.max_burst_requests
        )

    def _detect_bot_user_agent(self, user_agent: str) -> bool:
        """Detect bot signatures in user agent"""

        if not user_agent:
            return False

        user_agent_lower = user_agent.lower()

        # Check against known bot signatures
        for bot_signature in self.bot_user_agents:
            if bot_signature in user_agent_lower:
                return True

        # Check for missing common browser indicators
        browser_indicators = ['mozilla', 'webkit', 'chrome', 'firefox', 'safari', 'edge']
        has_browser_indicator = any(indicator in user_agent_lower for indicator in browser_indicators)

        # Suspicious if no browser indicators and very short
        if not has_browser_indicator and len(user_agent) < 20:
            return True

        return False

    def _calculate_behavioral_anomaly(self, profile: UserBehaviorProfile) -> float:
        """Calculate behavioral anomaly score"""

        if profile.request_count < 10:
            return 0.0

        # Analyze request interval patterns
        baseline_interval = np.mean([profile.avg_request_interval])
        baseline_std = np.std([profile.avg_request_interval, 1.0])  # Add variance

        # Use JIT function for anomaly detection
        intervals = np.array([profile.avg_request_interval], dtype=np.float64)
        anomaly_scores = calculate_anomaly_scores(
            intervals,
            baseline_interval,
            max(baseline_std, 0.1),
            self.anomaly_threshold
        )

        return float(anomaly_scores[0]) if len(anomaly_scores) > 0 else 0.0

    def _detect_geographic_anomaly(self, profile: UserBehaviorProfile, source_ip: str) -> bool:
        """Detect unusual geographic patterns"""

        if not source_ip or len(profile.geographic_locations) < 2:
            return False

        # Simple heuristic: too many different IPs in short time
        unique_ips = len(set(profile.geographic_locations))
        if unique_ips > 5 and profile.request_count < 100:
            return True

        return False

    def _calculate_risk_score(self, threats: List[ThreatEvent], profile: UserBehaviorProfile) -> float:
        """Calculate overall risk score"""

        if not threats:
            return 0.0

        # Weight threats by severity and confidence
        risk_components = []

        for threat in threats:
            severity_weight = threat.threat_level.value / 4.0  # Normalize to 0-1
            weighted_score = severity_weight * threat.confidence
            risk_components.append(weighted_score)

        # Combine risk components (max + average for multiple threats)
        if len(risk_components) == 1:
            base_risk = risk_components[0]
        else:
            base_risk = max(risk_components) + (sum(risk_components) / len(risk_components)) * 0.3

        # Apply user history modifiers
        history_modifier = 1.0

        # Increase risk for users with high error rates
        if profile.error_rate > 0.1:
            history_modifier += profile.error_rate

        # Increase risk for users with many geographic locations
        if len(profile.geographic_locations) > 3:
            history_modifier += 0.1

        # Increase risk for users with multiple user agents
        if len(profile.user_agents) > 2:
            history_modifier += 0.1

        final_risk = min(base_risk * history_modifier, 1.0)
        return final_risk

    def get_threat_summary(self, time_window: int = 3600) -> Dict[str, Any]:
        """Get threat detection summary for the last time window"""

        current_time = time.time()
        cutoff_time = current_time - time_window

        # Filter recent threats
        recent_threats = [
            threat for threat in self.threat_events
            if threat.timestamp >= cutoff_time
        ]

        # Categorize threats
        threat_counts = {}
        for threat in recent_threats:
            threat_type = threat.event_type
            threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1

        # Calculate threat levels
        level_counts = {}
        for threat in recent_threats:
            level = threat.threat_level.name
            level_counts[level] = level_counts.get(level, 0) + 1

        return {
            'time_window_hours': time_window / 3600,
            'total_threats': len(recent_threats),
            'threat_types': threat_counts,
            'threat_levels': level_counts,
            'analysis_count': self.analysis_count,
            'detection_rate': self.detections_count / max(self.analysis_count, 1),
            'false_positive_rate': self.false_positives / max(self.detections_count, 1)
        }

    def get_user_risk_profile(self, user_id: str) -> Dict[str, Any]:
        """Get detailed risk profile for a user"""

        profile = self.user_profiles.get(user_id)
        if not profile:
            return {'error': 'User not found'}

        user_threats = [
            threat for threat in self.threat_events
            if threat.user_id == user_id
        ]

        return {
            'user_id': user_id,
            'risk_score': profile.risk_score,
            'request_count': profile.request_count,
            'avg_request_interval': profile.avg_request_interval,
            'error_rate': profile.error_rate,
            'geographic_locations': len(profile.geographic_locations),
            'user_agents': len(profile.user_agents),
            'threat_events': len(user_threats),
            'last_activity': profile.last_activity,
            'account_age_hours': (time.time() - profile.last_activity) / 3600
        }

    async def cleanup_old_data(self, retention_hours: int = 24):
        """Clean up old threat events and user data"""

        current_time = time.time()
        cutoff_time = current_time - (retention_hours * 3600)

        # Remove old threat events
        self.threat_events = [
            threat for threat in self.threat_events
            if threat.timestamp >= cutoff_time
        ]

        # Remove inactive user profiles
        inactive_users = [
            user_id for user_id, profile in self.user_profiles.items()
            if profile.last_activity < cutoff_time
        ]

        for user_id in inactive_users:
            del self.user_profiles[user_id]

        logger.info(f"Cleaned up {len(inactive_users)} inactive user profiles and old threat events")