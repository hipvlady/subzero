"""
Attribute-Based Access Control (ABAC) Engine
Dynamic authorization based on attributes of user, resource, action, and context

Features:
- Multi-dimensional attribute evaluation
- Dynamic context-aware decisions (time, location, risk score)
- Policy evaluation with attribute conditions
- Integration with ReBAC for hybrid authorization
- Real-time risk assessment
"""

import time
import math
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, time as dt_time
import ipaddress

import numpy as np
from numba import jit


class AttributeType(str, Enum):
    """Types of attributes"""
    USER = "user"
    RESOURCE = "resource"
    ACTION = "action"
    ENVIRONMENT = "environment"


class Operator(str, Enum):
    """Comparison operators for attribute conditions"""
    EQUALS = "eq"
    NOT_EQUALS = "ne"
    GREATER_THAN = "gt"
    LESS_THAN = "lt"
    GREATER_EQUAL = "ge"
    LESS_EQUAL = "le"
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    MATCHES = "matches"


class Effect(str, Enum):
    """Policy effect"""
    ALLOW = "allow"
    DENY = "deny"


@dataclass
class Attribute:
    """Attribute with type and value"""
    name: str
    value: Any
    attribute_type: AttributeType


@dataclass
class Condition:
    """Attribute condition for policy evaluation"""
    attribute_name: str
    operator: Operator
    value: Any
    attribute_type: AttributeType = AttributeType.USER


@dataclass
class Policy:
    """ABAC policy with conditions"""
    policy_id: str
    description: str
    effect: Effect
    conditions: List[Condition] = field(default_factory=list)
    priority: int = 0  # Higher priority policies evaluated first


@dataclass
class AuthorizationContext:
    """
    Complete context for authorization decision
    Includes user, resource, action, and environment attributes
    """
    # User attributes
    user_id: str
    user_role: str
    user_department: Optional[str] = None
    user_clearance_level: int = 0

    # Resource attributes
    resource_type: str = ""
    resource_id: str = ""
    resource_owner: Optional[str] = None
    resource_sensitivity: str = "public"  # public, internal, confidential, secret

    # Action attributes
    action: str = ""

    # Environment/context attributes
    timestamp: float = field(default_factory=time.time)
    source_ip: Optional[str] = None
    location: Optional[str] = None
    device_type: Optional[str] = None
    risk_score: float = 0.0  # 0.0 = low risk, 1.0 = high risk

    # Additional custom attributes
    custom_attributes: Dict[str, Any] = field(default_factory=dict)


class RiskCalculator:
    """
    Calculate risk scores based on contextual factors
    Used for dynamic authorization decisions
    """

    def __init__(self):
        # Trusted IP ranges (example: corporate network)
        self.trusted_ip_ranges = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("192.168.0.0/16"),
        ]

        # Business hours (9 AM - 6 PM)
        self.business_hours_start = dt_time(9, 0)
        self.business_hours_end = dt_time(18, 0)

        # Risk factor weights
        self.risk_weights = {
            'ip_trust': 0.3,
            'time_of_day': 0.2,
            'location': 0.2,
            'device': 0.15,
            'user_behavior': 0.15
        }

    def calculate_risk_score(self, context: AuthorizationContext) -> float:
        """
        Calculate composite risk score (0.0 - 1.0)
        Higher score = higher risk

        Returns:
            Risk score between 0.0 (low) and 1.0 (high)
        """
        risk_factors = {}

        # IP trust factor
        risk_factors['ip_trust'] = self._calculate_ip_risk(context.source_ip)

        # Time of day factor
        risk_factors['time_of_day'] = self._calculate_time_risk(context.timestamp)

        # Location factor
        risk_factors['location'] = self._calculate_location_risk(context.location)

        # Device factor
        risk_factors['device'] = self._calculate_device_risk(context.device_type)

        # User behavior factor (placeholder - implement behavioral analysis)
        risk_factors['user_behavior'] = 0.0

        # Calculate weighted risk score
        total_risk = sum(
            risk_factors[factor] * self.risk_weights[factor]
            for factor in risk_factors
        )

        return min(1.0, max(0.0, total_risk))

    def _calculate_ip_risk(self, ip_address: Optional[str]) -> float:
        """Calculate risk based on IP address trust"""
        if not ip_address:
            return 0.5  # Unknown = medium risk

        try:
            ip = ipaddress.ip_address(ip_address)

            # Check if IP is in trusted range
            for trusted_range in self.trusted_ip_ranges:
                if ip in trusted_range:
                    return 0.0  # Trusted network = low risk

            # External IP = higher risk
            return 0.7

        except ValueError:
            return 0.5

    def _calculate_time_risk(self, timestamp: float) -> float:
        """Calculate risk based on time of access"""
        access_time = datetime.fromtimestamp(timestamp).time()

        # Check if during business hours
        if self.business_hours_start <= access_time <= self.business_hours_end:
            return 0.0  # Business hours = low risk

        # After hours = higher risk
        return 0.6

    def _calculate_location_risk(self, location: Optional[str]) -> float:
        """Calculate risk based on location"""
        if not location:
            return 0.3  # Unknown location = medium-low risk

        # Example: check against known safe locations
        safe_locations = {'US', 'CA', 'GB', 'DE', 'FR'}

        if location.upper() in safe_locations:
            return 0.1  # Safe location = low risk

        return 0.7  # Unknown location = higher risk

    def _calculate_device_risk(self, device_type: Optional[str]) -> float:
        """Calculate risk based on device type"""
        if not device_type:
            return 0.3

        trusted_devices = {'corporate_laptop', 'managed_mobile'}

        if device_type in trusted_devices:
            return 0.0  # Trusted device = low risk

        return 0.5  # Unknown device = medium risk


class ABACEngine:
    """
    Attribute-Based Access Control Engine
    Evaluates policies based on attributes and context
    """

    def __init__(self):
        # Policy registry
        self.policies: Dict[str, Policy] = {}

        # Risk calculator
        self.risk_calculator = RiskCalculator()

        # Attribute providers (functions to fetch attributes)
        self.attribute_providers: Dict[AttributeType, Dict[str, Callable]] = {
            AttributeType.USER: {},
            AttributeType.RESOURCE: {},
            AttributeType.ACTION: {},
            AttributeType.ENVIRONMENT: {}
        }

        # Decision cache
        self.decision_cache: Dict[str, Tuple[Effect, float]] = {}
        self.cache_ttl = 60  # 1 minute

        # Metrics
        self.decisions_count = 0
        self.allow_count = 0
        self.deny_count = 0

        # Initialize default policies
        self._init_default_policies()

    def _init_default_policies(self):
        """Initialize common ABAC policies"""

        # Policy 1: High-risk access requires MFA
        self.add_policy(Policy(
            policy_id="high_risk_requires_mfa",
            description="Deny high-risk access without MFA",
            effect=Effect.DENY,
            conditions=[
                Condition("risk_score", Operator.GREATER_THAN, 0.7, AttributeType.ENVIRONMENT),
                Condition("mfa_verified", Operator.EQUALS, False, AttributeType.USER)
            ],
            priority=100
        ))

        # Policy 2: Confidential data requires clearance
        self.add_policy(Policy(
            policy_id="confidential_requires_clearance",
            description="Deny access to confidential data without clearance",
            effect=Effect.DENY,
            conditions=[
                Condition("resource_sensitivity", Operator.IN, ["confidential", "secret"], AttributeType.RESOURCE),
                Condition("user_clearance_level", Operator.LESS_THAN, 3, AttributeType.USER)
            ],
            priority=90
        ))

        # Policy 3: After-hours access to sensitive data
        self.add_policy(Policy(
            policy_id="after_hours_sensitive",
            description="Deny after-hours access to sensitive data",
            effect=Effect.DENY,
            conditions=[
                Condition("resource_sensitivity", Operator.IN, ["confidential", "secret"], AttributeType.RESOURCE),
                Condition("is_business_hours", Operator.EQUALS, False, AttributeType.ENVIRONMENT)
            ],
            priority=80
        ))

        # Policy 4: Resource owner always has access
        self.add_policy(Policy(
            policy_id="owner_full_access",
            description="Allow resource owner full access",
            effect=Effect.ALLOW,
            conditions=[
                Condition("user_id", Operator.EQUALS, "{{resource_owner}}", AttributeType.USER)
            ],
            priority=70
        ))

    def add_policy(self, policy: Policy):
        """Add or update an ABAC policy"""
        self.policies[policy.policy_id] = policy

    def remove_policy(self, policy_id: str) -> bool:
        """Remove an ABAC policy"""
        if policy_id in self.policies:
            del self.policies[policy_id]
            return True
        return False

    async def evaluate(self, context: AuthorizationContext) -> Tuple[Effect, Dict]:
        """
        Evaluate authorization decision based on context

        Args:
            context: Authorization context with all attributes

        Returns:
            Tuple of (effect, metadata)
            metadata includes matched policies, risk score, etc.
        """
        self.decisions_count += 1
        start_time = time.perf_counter()

        # Calculate risk score
        risk_score = self.risk_calculator.calculate_risk_score(context)
        context.risk_score = risk_score

        # Enrich context with derived attributes
        context.custom_attributes['is_business_hours'] = self._is_business_hours(context.timestamp)
        context.custom_attributes['mfa_verified'] = context.custom_attributes.get('mfa_verified', False)

        # Check cache
        cache_key = self._generate_cache_key(context)
        if cache_key in self.decision_cache:
            cached_effect, cached_at = self.decision_cache[cache_key]
            if time.time() - cached_at < self.cache_ttl:
                return cached_effect, {'cached': True, 'risk_score': risk_score}

        # Evaluate policies in priority order
        sorted_policies = sorted(
            self.policies.values(),
            key=lambda p: p.priority,
            reverse=True
        )

        matched_policies = []
        decision = Effect.DENY  # Default deny

        for policy in sorted_policies:
            if self._evaluate_policy(policy, context):
                matched_policies.append({
                    'policy_id': policy.policy_id,
                    'description': policy.description,
                    'effect': policy.effect.value
                })

                # First matching DENY wins
                if policy.effect == Effect.DENY:
                    decision = Effect.DENY
                    break

                # ALLOW only if no DENY
                if policy.effect == Effect.ALLOW:
                    decision = Effect.ALLOW

        # Update metrics
        if decision == Effect.ALLOW:
            self.allow_count += 1
        else:
            self.deny_count += 1

        # Cache decision
        self.decision_cache[cache_key] = (decision, time.time())

        latency_ms = (time.perf_counter() - start_time) * 1000

        metadata = {
            'risk_score': risk_score,
            'matched_policies': matched_policies,
            'policy_count': len(matched_policies),
            'latency_ms': latency_ms,
            'cached': False
        }

        return decision, metadata

    def _evaluate_policy(self, policy: Policy, context: AuthorizationContext) -> bool:
        """
        Evaluate if policy conditions match context

        Returns:
            True if all conditions match
        """
        for condition in policy.conditions:
            if not self._evaluate_condition(condition, context):
                return False
        return True

    def _evaluate_condition(self, condition: Condition, context: AuthorizationContext) -> bool:
        """
        Evaluate a single condition against context

        Returns:
            True if condition matches
        """
        # Get attribute value from context
        actual_value = self._get_attribute_value(condition.attribute_name, condition.attribute_type, context)

        # Handle template variables (e.g., {{resource_owner}})
        expected_value = condition.value
        if isinstance(expected_value, str) and expected_value.startswith('{{'):
            template_var = expected_value.strip('{}')
            expected_value = self._get_attribute_value(template_var, AttributeType.RESOURCE, context)

        # Evaluate based on operator
        return self._apply_operator(condition.operator, actual_value, expected_value)

    def _get_attribute_value(self, attr_name: str, attr_type: AttributeType, context: AuthorizationContext) -> Any:
        """Get attribute value from context"""
        # Map attribute names to context fields
        if attr_type == AttributeType.USER:
            if attr_name == "user_id":
                return context.user_id
            elif attr_name == "user_role":
                return context.user_role
            elif attr_name == "user_clearance_level":
                return context.user_clearance_level

        elif attr_type == AttributeType.RESOURCE:
            if attr_name == "resource_type":
                return context.resource_type
            elif attr_name == "resource_id":
                return context.resource_id
            elif attr_name == "resource_owner":
                return context.resource_owner
            elif attr_name == "resource_sensitivity":
                return context.resource_sensitivity

        elif attr_type == AttributeType.ACTION:
            if attr_name == "action":
                return context.action

        elif attr_type == AttributeType.ENVIRONMENT:
            if attr_name == "risk_score":
                return context.risk_score
            elif attr_name == "source_ip":
                return context.source_ip
            elif attr_name == "location":
                return context.location

        # Check custom attributes
        return context.custom_attributes.get(attr_name)

    def _apply_operator(self, operator: Operator, actual: Any, expected: Any) -> bool:
        """Apply comparison operator"""
        try:
            if operator == Operator.EQUALS:
                return actual == expected
            elif operator == Operator.NOT_EQUALS:
                return actual != expected
            elif operator == Operator.GREATER_THAN:
                return actual > expected
            elif operator == Operator.LESS_THAN:
                return actual < expected
            elif operator == Operator.GREATER_EQUAL:
                return actual >= expected
            elif operator == Operator.LESS_EQUAL:
                return actual <= expected
            elif operator == Operator.IN:
                return actual in expected
            elif operator == Operator.NOT_IN:
                return actual not in expected
            elif operator == Operator.CONTAINS:
                return expected in actual
            elif operator == Operator.MATCHES:
                import re
                return bool(re.match(expected, str(actual)))
        except (TypeError, AttributeError):
            return False

        return False

    def _is_business_hours(self, timestamp: float) -> bool:
        """Check if timestamp is during business hours"""
        access_time = datetime.fromtimestamp(timestamp).time()
        return self.risk_calculator.business_hours_start <= access_time <= self.risk_calculator.business_hours_end

    def _generate_cache_key(self, context: AuthorizationContext) -> str:
        """Generate cache key from context"""
        import hashlib
        key_parts = [
            context.user_id,
            context.user_role,
            context.resource_type,
            context.resource_id,
            context.action,
            str(int(context.timestamp / 60))  # Round to minute
        ]
        key_string = "|".join(key_parts)
        return hashlib.sha256(key_string.encode()).hexdigest()

    def get_metrics(self) -> Dict:
        """Get ABAC engine metrics"""
        allow_rate = (self.allow_count / max(self.decisions_count, 1)) * 100
        deny_rate = (self.deny_count / max(self.decisions_count, 1)) * 100

        return {
            'total_decisions': self.decisions_count,
            'allow_count': self.allow_count,
            'deny_count': self.deny_count,
            'allow_rate_percent': allow_rate,
            'deny_rate_percent': deny_rate,
            'policy_count': len(self.policies),
            'cache_size': len(self.decision_cache)
        }