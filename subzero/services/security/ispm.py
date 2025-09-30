"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

Identity Security Posture Management (ISPM)
Continuous security monitoring and risk assessment for AI agents

Features:
- Agent risk scoring
- Behavioral anomaly detection
- Automated remediation
- Compliance monitoring
- Security posture dashboards
- Real-time threat alerts
"""

import asyncio
import time
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import deque
from datetime import datetime, timedelta

import numpy as np
from numba import jit

from subzero.config.defaults import settings


class RiskLevel(str, Enum):
    """Risk severity levels"""

    CRITICAL = "critical"  # Immediate action required
    HIGH = "high"  # Remediation needed
    MEDIUM = "medium"  # Monitor closely
    LOW = "low"  # Normal operations
    INFO = "info"  # Informational only


class RemediationAction(str, Enum):
    """Automated remediation actions"""

    NONE = "none"
    MONITOR = "monitor"
    RESTRICT = "restrict"  # Limit permissions
    SUSPEND = "suspend"  # Suspend agent
    REVOKE = "revoke"  # Revoke all access
    ALERT = "alert"  # Alert security team


@dataclass
class SecurityFinding:
    """Individual security finding"""

    finding_id: str
    agent_id: str
    risk_level: RiskLevel
    category: str
    description: str
    evidence: Dict
    detected_at: float = field(default_factory=time.time)
    remediation_action: RemediationAction = RemediationAction.NONE
    remediated: bool = False


@dataclass
class AgentSecurityPosture:
    """Security posture for an agent"""

    agent_id: str
    risk_score: float  # 0.0-1.0
    risk_level: RiskLevel
    findings: List[SecurityFinding] = field(default_factory=list)
    last_assessment: float = field(default_factory=time.time)
    compliance_score: float = 1.0
    behavioral_anomalies: int = 0
    metadata: Dict = field(default_factory=dict)


@dataclass
class ComplianceRule:
    """Compliance rule definition"""

    rule_id: str
    name: str
    description: str
    severity: RiskLevel
    check_function: str  # Name of check function
    auto_remediate: bool = False


class ISPMEngine:
    """
    Identity Security Posture Management Engine
    Monitors and manages security posture of AI agents
    """

    def __init__(self):
        # Agent postures
        self.agent_postures: Dict[str, AgentSecurityPosture] = {}

        # Security findings
        self.findings: Dict[str, SecurityFinding] = {}

        # Behavioral baselines: agent_id -> behavior metrics
        self.behavioral_baselines: Dict[str, Dict] = {}

        # Activity history: agent_id -> recent activities
        self.activity_history: Dict[str, deque] = {}

        # Compliance rules
        self.compliance_rules: Dict[str, ComplianceRule] = {}

        # Remediation queue
        self.remediation_queue: deque = deque()

        # Metrics
        self.assessment_count = 0
        self.remediation_count = 0
        self.alert_count = 0

        # Initialize default compliance rules
        self._init_compliance_rules()

    def _init_compliance_rules(self):
        """Initialize default compliance rules"""
        rules = [
            ComplianceRule(
                rule_id="token_expiry",
                name="Token Expiration Check",
                description="Tokens must not be expired",
                severity=RiskLevel.HIGH,
                check_function="check_token_expiry",
                auto_remediate=True,
            ),
            ComplianceRule(
                rule_id="excessive_permissions",
                name="Excessive Permissions",
                description="Agent has more permissions than necessary",
                severity=RiskLevel.MEDIUM,
                check_function="check_excessive_permissions",
                auto_remediate=True,
            ),
            ComplianceRule(
                rule_id="dormant_agent",
                name="Dormant Agent Check",
                description="Agent inactive for extended period",
                severity=RiskLevel.LOW,
                check_function="check_dormant_agent",
                auto_remediate=False,
            ),
            ComplianceRule(
                rule_id="anomalous_behavior",
                name="Behavioral Anomaly",
                description="Agent behavior deviates from baseline",
                severity=RiskLevel.HIGH,
                check_function="check_behavioral_anomaly",
                auto_remediate=False,
            ),
            ComplianceRule(
                rule_id="failed_auth_attempts",
                name="Failed Authentication Attempts",
                description="Multiple failed authentication attempts",
                severity=RiskLevel.CRITICAL,
                check_function="check_failed_auth",
                auto_remediate=True,
            ),
        ]

        for rule in rules:
            self.compliance_rules[rule.rule_id] = rule

    async def assess_agent(self, agent_id: str, force_refresh: bool = False) -> AgentSecurityPosture:
        """
        Assess security posture of an agent

        Args:
            agent_id: Agent identifier
            force_refresh: Force new assessment even if recent

        Returns:
            Agent security posture
        """
        self.assessment_count += 1
        start_time = time.perf_counter()

        # Check if recent assessment exists
        if not force_refresh and agent_id in self.agent_postures:
            posture = self.agent_postures[agent_id]
            # Use cached if less than 5 minutes old
            if time.time() - posture.last_assessment < 300:
                return posture

        # Run compliance checks
        findings = await self._run_compliance_checks(agent_id)

        # Calculate risk score
        risk_score = self._calculate_risk_score(findings)
        risk_level = self._determine_risk_level(risk_score)

        # Check behavioral anomalies
        anomaly_count = await self._detect_behavioral_anomalies(agent_id)

        # Calculate compliance score
        compliance_score = self._calculate_compliance_score(findings)

        # Create or update posture
        posture = AgentSecurityPosture(
            agent_id=agent_id,
            risk_score=risk_score,
            risk_level=risk_level,
            findings=findings,
            compliance_score=compliance_score,
            behavioral_anomalies=anomaly_count,
        )

        self.agent_postures[agent_id] = posture

        # Auto-remediate if enabled
        if settings.ISPM_AUTO_REMEDIATION:
            await self._auto_remediate(posture)

        # Alert if high risk
        if risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            await self._send_alert(posture)

        latency_ms = (time.perf_counter() - start_time) * 1000

        print(f"🛡️  Agent assessed: {agent_id} (risk: {risk_level.value}, score: {risk_score:.2f}, {latency_ms:.2f}ms)")

        return posture

    async def _run_compliance_checks(self, agent_id: str) -> List[SecurityFinding]:
        """Run all compliance checks for an agent"""
        findings = []

        for rule in self.compliance_rules.values():
            # Get check function
            check_func = getattr(self, rule.check_function, None)

            if not check_func:
                continue

            try:
                # Run check
                result = await check_func(agent_id)

                if result:  # Finding detected
                    finding = SecurityFinding(
                        finding_id=f"{agent_id}_{rule.rule_id}_{int(time.time())}",
                        agent_id=agent_id,
                        risk_level=rule.severity,
                        category=rule.name,
                        description=result.get("description", rule.description),
                        evidence=result.get("evidence", {}),
                        remediation_action=(
                            RemediationAction.RESTRICT if rule.auto_remediate else RemediationAction.ALERT
                        ),
                    )

                    findings.append(finding)
                    self.findings[finding.finding_id] = finding

            except Exception as e:
                print(f"❌ Compliance check failed ({rule.rule_id}): {e}")

        return findings

    async def check_token_expiry(self, agent_id: str) -> Optional[Dict]:
        """Check if agent has expired tokens"""
        # Placeholder - integrate with token vault
        return None

    async def check_excessive_permissions(self, agent_id: str) -> Optional[Dict]:
        """Check if agent has excessive permissions"""
        # Placeholder - integrate with FGA
        return None

    async def check_dormant_agent(self, agent_id: str) -> Optional[Dict]:
        """Check if agent is dormant"""
        if agent_id not in self.activity_history:
            return None

        activities = self.activity_history[agent_id]

        if not activities:
            return {"description": f"Agent {agent_id} has no recent activity", "evidence": {"last_activity": None}}

        last_activity = activities[-1]["timestamp"]
        inactive_days = (time.time() - last_activity) / 86400

        if inactive_days > 30:
            return {
                "description": f"Agent {agent_id} inactive for {inactive_days:.0f} days",
                "evidence": {"last_activity": last_activity, "inactive_days": inactive_days},
            }

        return None

    async def check_behavioral_anomaly(self, agent_id: str) -> Optional[Dict]:
        """Check for behavioral anomalies"""
        anomaly_count = await self._detect_behavioral_anomalies(agent_id)

        if anomaly_count > 5:
            return {
                "description": f"Agent {agent_id} has {anomaly_count} behavioral anomalies",
                "evidence": {"anomaly_count": anomaly_count},
            }

        return None

    async def check_failed_auth(self, agent_id: str) -> Optional[Dict]:
        """Check for failed authentication attempts"""
        if agent_id not in self.activity_history:
            return None

        activities = list(self.activity_history[agent_id])

        # Count failed auth in last hour
        one_hour_ago = time.time() - 3600
        failed_auths = sum(
            1
            for activity in activities
            if activity.get("type") == "auth_failed" and activity["timestamp"] > one_hour_ago
        )

        if failed_auths >= 5:
            return {
                "description": f"Agent {agent_id} has {failed_auths} failed auth attempts in last hour",
                "evidence": {"failed_count": failed_auths},
            }

        return None

    async def _detect_behavioral_anomalies(self, agent_id: str) -> int:
        """Detect behavioral anomalies using baseline comparison"""
        if agent_id not in self.behavioral_baselines:
            # Build baseline
            await self._build_behavioral_baseline(agent_id)
            return 0

        if agent_id not in self.activity_history:
            return 0

        baseline = self.behavioral_baselines[agent_id]
        activities = list(self.activity_history[agent_id])

        anomaly_count = 0

        # Recent activity pattern (last 24 hours)
        day_ago = time.time() - 86400
        recent_activities = [a for a in activities if a["timestamp"] > day_ago]

        if not recent_activities:
            return 0

        # Check request rate anomaly
        request_rate = len(recent_activities) / 24  # requests per hour

        baseline_rate = baseline.get("avg_request_rate", 10)

        if request_rate > baseline_rate * 3:  # 3x normal rate
            anomaly_count += 1

        # Check access pattern anomaly
        accessed_resources = set(a.get("resource") for a in recent_activities if a.get("resource"))
        baseline_resources = set(baseline.get("common_resources", []))

        unusual_resources = accessed_resources - baseline_resources

        if len(unusual_resources) > 5:
            anomaly_count += 1

        # Check time-of-day anomaly
        access_hours = [datetime.fromtimestamp(a["timestamp"]).hour for a in recent_activities]

        baseline_hours = set(baseline.get("typical_hours", range(9, 18)))

        unusual_hours = sum(1 for hour in access_hours if hour not in baseline_hours)

        if unusual_hours > len(access_hours) * 0.5:  # >50% outside typical hours
            anomaly_count += 1

        return anomaly_count

    async def _build_behavioral_baseline(self, agent_id: str):
        """Build behavioral baseline for an agent"""
        if agent_id not in self.activity_history:
            return

        activities = list(self.activity_history[agent_id])

        if len(activities) < 100:  # Need minimum data
            return

        # Calculate baseline metrics
        timestamps = [a["timestamp"] for a in activities]
        time_diffs = np.diff(timestamps)

        avg_request_rate = len(activities) / ((timestamps[-1] - timestamps[0]) / 3600)

        # Common resources
        resources = [a.get("resource") for a in activities if a.get("resource")]
        resource_counts = {}
        for r in resources:
            resource_counts[r] = resource_counts.get(r, 0) + 1

        common_resources = [
            r for r, count in resource_counts.items() if count >= len(resources) * 0.1  # >10% of accesses
        ]

        # Typical hours
        hours = [datetime.fromtimestamp(t).hour for t in timestamps]
        hour_counts = np.bincount(hours, minlength=24)
        typical_hours = np.where(hour_counts > len(hours) * 0.05)[0].tolist()

        self.behavioral_baselines[agent_id] = {
            "avg_request_rate": avg_request_rate,
            "common_resources": common_resources,
            "typical_hours": typical_hours,
            "baseline_created_at": time.time(),
        }

        print(f"📊 Baseline created for {agent_id}")

    def _calculate_risk_score(self, findings: List[SecurityFinding]) -> float:
        """Calculate composite risk score from findings"""
        if not findings:
            return 0.0

        # Weight by severity
        severity_weights = {
            RiskLevel.CRITICAL: 1.0,
            RiskLevel.HIGH: 0.7,
            RiskLevel.MEDIUM: 0.4,
            RiskLevel.LOW: 0.2,
            RiskLevel.INFO: 0.1,
        }

        total_weight = sum(severity_weights[f.risk_level] for f in findings)

        # Normalize to 0-1 scale
        return min(1.0, total_weight / 3.0)

    def _determine_risk_level(self, risk_score: float) -> RiskLevel:
        """Determine risk level from score"""
        if risk_score >= 0.8:
            return RiskLevel.CRITICAL
        elif risk_score >= 0.6:
            return RiskLevel.HIGH
        elif risk_score >= 0.3:
            return RiskLevel.MEDIUM
        elif risk_score > 0.0:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO

    def _calculate_compliance_score(self, findings: List[SecurityFinding]) -> float:
        """Calculate compliance score (inverse of risk)"""
        total_rules = len(self.compliance_rules)

        if total_rules == 0:
            return 1.0

        # Count failed rules
        failed_rules = len(set(f.category for f in findings))

        return 1.0 - (failed_rules / total_rules)

    async def _auto_remediate(self, posture: AgentSecurityPosture):
        """Automatically remediate findings"""
        for finding in posture.findings:
            if finding.remediated:
                continue

            if finding.remediation_action == RemediationAction.NONE:
                continue

            # Execute remediation
            success = await self._execute_remediation(finding)

            if success:
                finding.remediated = True
                self.remediation_count += 1
                print(f"✅ Remediated {finding.category} for {finding.agent_id}")

    async def _execute_remediation(self, finding: SecurityFinding) -> bool:
        """Execute remediation action"""
        action = finding.remediation_action

        if action == RemediationAction.RESTRICT:
            # Restrict agent permissions
            return await self._restrict_permissions(finding.agent_id)

        elif action == RemediationAction.SUSPEND:
            # Suspend agent
            return await self._suspend_agent(finding.agent_id)

        elif action == RemediationAction.REVOKE:
            # Revoke all access
            return await self._revoke_access(finding.agent_id)

        elif action == RemediationAction.ALERT:
            # Send alert
            return await self._send_alert_for_finding(finding)

        return False

    async def _restrict_permissions(self, agent_id: str) -> bool:
        """Restrict agent permissions (placeholder)"""
        print(f"🔒 Restricting permissions for {agent_id}")
        return True

    async def _suspend_agent(self, agent_id: str) -> bool:
        """Suspend agent (placeholder)"""
        print(f"⏸️  Suspending agent {agent_id}")
        return True

    async def _revoke_access(self, agent_id: str) -> bool:
        """Revoke agent access (placeholder)"""
        print(f"🚫 Revoking access for {agent_id}")
        return True

    async def _send_alert(self, posture: AgentSecurityPosture):
        """Send security alert"""
        self.alert_count += 1

        alert_data = {
            "agent_id": posture.agent_id,
            "risk_level": posture.risk_level.value,
            "risk_score": posture.risk_score,
            "findings_count": len(posture.findings),
            "timestamp": time.time(),
        }

        if settings.ISPM_ALERT_WEBHOOK:
            # Send to webhook (placeholder)
            print(f"🚨 ALERT sent for {posture.agent_id}: {posture.risk_level.value}")

    async def _send_alert_for_finding(self, finding: SecurityFinding) -> bool:
        """Send alert for specific finding"""
        print(f"🚨 ALERT: {finding.category} for {finding.agent_id}")
        return True

    def record_activity(self, agent_id: str, activity_type: str, metadata: Optional[Dict] = None):
        """Record agent activity for behavioral analysis"""
        if agent_id not in self.activity_history:
            self.activity_history[agent_id] = deque(maxlen=10000)

        activity = {"timestamp": time.time(), "type": activity_type, **(metadata or {})}

        self.activity_history[agent_id].append(activity)

    def get_metrics(self) -> Dict:
        """Get ISPM metrics"""
        return {
            "assessment_count": self.assessment_count,
            "remediation_count": self.remediation_count,
            "alert_count": self.alert_count,
            "monitored_agents": len(self.agent_postures),
            "total_findings": len(self.findings),
            "compliance_rules": len(self.compliance_rules),
            "agents_by_risk": {
                risk.value: sum(1 for p in self.agent_postures.values() if p.risk_level == risk) for risk in RiskLevel
            },
        }
