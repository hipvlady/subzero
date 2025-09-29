"""
Open Policy Agent (OPA) Integration
Policy-as-code framework for declarative authorization

Features:
- Rego policy language support
- Policy compilation and caching
- Integration with ABAC/ReBAC engines
- Real-time policy updates
- Policy testing and validation
"""

import asyncio
import time
import json
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum

import aiohttp


class PolicyLanguage(str, Enum):
    """Supported policy languages"""
    REGO = "rego"  # OPA's native language
    CEDAR = "cedar"  # AWS Cedar
    JSON = "json"  # JSON-based policies


@dataclass
class PolicyDocument:
    """OPA policy document"""
    policy_id: str
    name: str
    content: str
    language: PolicyLanguage = PolicyLanguage.REGO
    version: str = "1.0"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyDecision:
    """Result of policy evaluation"""
    allowed: bool
    policy_id: str
    decision_id: str
    reasons: List[str] = field(default_factory=list)
    matched_rules: List[str] = field(default_factory=list)
    evaluation_time_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class OPAClient:
    """
    Client for Open Policy Agent server
    Handles policy evaluation via OPA REST API
    """

    def __init__(
        self,
        opa_url: str = "http://localhost:8181",
        policy_path: str = "authz/allow"
    ):
        """
        Initialize OPA client

        Args:
            opa_url: Base URL of OPA server
            policy_path: Path to policy decision endpoint
        """
        self.opa_url = opa_url.rstrip('/')
        self.policy_path = policy_path

        # HTTP session
        connector = aiohttp.TCPConnector(limit=100)
        timeout = aiohttp.ClientTimeout(total=5)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)

        # Metrics
        self.query_count = 0
        self.query_errors = 0

    async def query(
        self,
        input_data: Dict,
        policy_path: Optional[str] = None
    ) -> PolicyDecision:
        """
        Query OPA for authorization decision

        Args:
            input_data: Input data for policy evaluation
            policy_path: Override default policy path

        Returns:
            Policy decision result
        """
        self.query_count += 1
        start_time = time.perf_counter()

        path = policy_path or self.policy_path
        url = f"{self.opa_url}/v1/data/{path.replace('.', '/')}"

        try:
            payload = {"input": input_data}

            async with self.session.post(url, json=payload) as response:
                if response.status != 200:
                    self.query_errors += 1
                    error_text = await response.text()
                    raise Exception(f"OPA query failed: {error_text}")

                result = await response.json()

                evaluation_time = (time.perf_counter() - start_time) * 1000

                # Parse OPA response
                decision_result = result.get('result', {})

                if isinstance(decision_result, bool):
                    allowed = decision_result
                    reasons = []
                    matched_rules = []
                elif isinstance(decision_result, dict):
                    allowed = decision_result.get('allow', False)
                    reasons = decision_result.get('reasons', [])
                    matched_rules = decision_result.get('matched_rules', [])
                else:
                    allowed = False
                    reasons = ["Unknown OPA response format"]
                    matched_rules = []

                return PolicyDecision(
                    allowed=allowed,
                    policy_id=path,
                    decision_id=f"opa_{int(time.time() * 1000)}",
                    reasons=reasons,
                    matched_rules=matched_rules,
                    evaluation_time_ms=evaluation_time,
                    metadata={'opa_result': decision_result}
                )

        except Exception as e:
            self.query_errors += 1
            evaluation_time = (time.perf_counter() - start_time) * 1000

            return PolicyDecision(
                allowed=False,
                policy_id=path,
                decision_id=f"opa_error_{int(time.time() * 1000)}",
                reasons=[f"OPA evaluation error: {str(e)}"],
                evaluation_time_ms=evaluation_time
            )

    async def upload_policy(
        self,
        policy_id: str,
        policy_content: str
    ) -> bool:
        """
        Upload policy to OPA server

        Args:
            policy_id: Policy identifier
            policy_content: Rego policy content

        Returns:
            True if successful
        """
        url = f"{self.opa_url}/v1/policies/{policy_id}"

        try:
            async with self.session.put(
                url,
                data=policy_content,
                headers={'Content-Type': 'text/plain'}
            ) as response:
                return response.status == 200

        except Exception as e:
            print(f"Failed to upload policy: {e}")
            return False

    async def delete_policy(self, policy_id: str) -> bool:
        """
        Delete policy from OPA server

        Args:
            policy_id: Policy identifier

        Returns:
            True if successful
        """
        url = f"{self.opa_url}/v1/policies/{policy_id}"

        try:
            async with self.session.delete(url) as response:
                return response.status == 200

        except Exception as e:
            print(f"Failed to delete policy: {e}")
            return False

    async def get_policy(self, policy_id: str) -> Optional[str]:
        """
        Get policy from OPA server

        Args:
            policy_id: Policy identifier

        Returns:
            Policy content or None
        """
        url = f"{self.opa_url}/v1/policies/{policy_id}"

        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    result = await response.json()
                    return result.get('result', {}).get('raw')
                return None

        except Exception:
            return None

    async def health_check(self) -> bool:
        """
        Check if OPA server is healthy

        Returns:
            True if healthy
        """
        url = f"{self.opa_url}/health"

        try:
            async with self.session.get(url) as response:
                return response.status == 200

        except Exception:
            return False

    async def close(self):
        """Close HTTP session"""
        await self.session.close()


class PolicyEngine:
    """
    Policy-as-Code engine with OPA integration
    Manages policy lifecycle and evaluation
    """

    def __init__(
        self,
        opa_url: str = "http://localhost:8181",
        enable_caching: bool = True
    ):
        """
        Initialize policy engine

        Args:
            opa_url: OPA server URL
            enable_caching: Enable decision caching
        """
        self.opa_client = OPAClient(opa_url)
        self.enable_caching = enable_caching

        # Policy registry
        self.policies: Dict[str, PolicyDocument] = {}

        # Decision cache
        self.decision_cache: Dict[str, Tuple[PolicyDecision, float]] = {}
        self.cache_ttl = 60  # 1 minute

        # Built-in policy templates
        self.policy_templates: Dict[str, str] = {}
        self._init_policy_templates()

        # Metrics
        self.total_evaluations = 0
        self.cache_hits = 0

    def _init_policy_templates(self):
        """Initialize common policy templates"""

        # Template 1: Role-based access control
        self.policy_templates['rbac'] = """
package authz

default allow = false

# Allow if user has required role
allow {
    input.user.role == input.required_role
}

# Admins can do everything
allow {
    input.user.role == "admin"
}
"""

        # Template 2: Time-based access control
        self.policy_templates['time_based'] = """
package authz

import future.keywords.if
import future.keywords.in

default allow = false

# Allow during business hours
allow if {
    hour := time.clock(time.now_ns())[0]
    hour >= 9
    hour <= 18
}

# Allow admins anytime
allow if {
    input.user.role == "admin"
}
"""

        # Template 3: Attribute-based access control
        self.policy_templates['abac'] = """
package authz

import future.keywords.if

default allow = false

# Allow if user department matches resource department
allow if {
    input.user.department == input.resource.department
}

# Allow if user clearance >= resource sensitivity
allow if {
    input.user.clearance_level >= input.resource.sensitivity_level
}

# Resource owner always allowed
allow if {
    input.user.id == input.resource.owner_id
}
"""

        # Template 4: Risk-based access control
        self.policy_templates['risk_based'] = """
package authz

import future.keywords.if

default allow = false

# Deny high-risk requests
deny if {
    input.risk_score > 0.8
}

# Allow low-risk requests
allow if {
    not deny
    input.risk_score < 0.3
}

# Medium risk requires additional verification
allow if {
    not deny
    input.risk_score >= 0.3
    input.risk_score <= 0.8
    input.mfa_verified == true
}

reasons[msg] {
    deny
    msg := "Access denied due to high risk score"
}

reasons[msg] {
    allow
    input.mfa_verified == false
    msg := "MFA verification recommended"
}
"""

    async def register_policy(
        self,
        policy: PolicyDocument,
        upload_to_opa: bool = True
    ) -> bool:
        """
        Register a policy document

        Args:
            policy: Policy document to register
            upload_to_opa: Whether to upload to OPA server

        Returns:
            True if successful
        """
        # Validate policy
        if not self._validate_policy(policy):
            return False

        # Store policy
        self.policies[policy.policy_id] = policy

        # Upload to OPA if enabled
        if upload_to_opa:
            success = await self.opa_client.upload_policy(
                policy.policy_id,
                policy.content
            )
            if not success:
                print(f"Warning: Failed to upload policy {policy.policy_id} to OPA")

        return True

    def _validate_policy(self, policy: PolicyDocument) -> bool:
        """
        Validate policy syntax
        Basic validation - enhance with OPA compile check
        """
        if policy.language != PolicyLanguage.REGO:
            return False

        if not policy.content or not policy.content.strip():
            return False

        # Check for package declaration
        if 'package ' not in policy.content:
            return False

        return True

    async def evaluate(
        self,
        policy_id: str,
        input_data: Dict
    ) -> PolicyDecision:
        """
        Evaluate policy against input data

        Args:
            policy_id: Policy to evaluate
            input_data: Input context for evaluation

        Returns:
            Policy decision
        """
        self.total_evaluations += 1

        # Check cache
        if self.enable_caching:
            cache_key = self._generate_cache_key(policy_id, input_data)
            if cache_key in self.decision_cache:
                decision, cached_at = self.decision_cache[cache_key]
                if time.time() - cached_at < self.cache_ttl:
                    self.cache_hits += 1
                    decision.metadata['cached'] = True
                    return decision

        # Query OPA
        decision = await self.opa_client.query(
            input_data,
            policy_path=f"policies.{policy_id}"
        )

        # Cache decision
        if self.enable_caching:
            cache_key = self._generate_cache_key(policy_id, input_data)
            self.decision_cache[cache_key] = (decision, time.time())

        return decision

    async def evaluate_batch(
        self,
        evaluations: List[Tuple[str, Dict]]
    ) -> List[PolicyDecision]:
        """
        Evaluate multiple policies in batch

        Args:
            evaluations: List of (policy_id, input_data) tuples

        Returns:
            List of policy decisions
        """
        tasks = [
            self.evaluate(policy_id, input_data)
            for policy_id, input_data in evaluations
        ]

        return await asyncio.gather(*tasks)

    def create_from_template(
        self,
        template_name: str,
        policy_id: str,
        customizations: Optional[Dict] = None
    ) -> Optional[PolicyDocument]:
        """
        Create policy from template

        Args:
            template_name: Name of template to use
            policy_id: ID for new policy
            customizations: Custom parameters for template

        Returns:
            Policy document or None if template not found
        """
        if template_name not in self.policy_templates:
            return None

        template_content = self.policy_templates[template_name]

        # Apply customizations (simple string replacement)
        if customizations:
            for key, value in customizations.items():
                template_content = template_content.replace(f"{{{{{key}}}}}", str(value))

        return PolicyDocument(
            policy_id=policy_id,
            name=f"Policy from {template_name} template",
            content=template_content,
            language=PolicyLanguage.REGO,
            metadata={'template': template_name}
        )

    def _generate_cache_key(self, policy_id: str, input_data: Dict) -> str:
        """Generate cache key for decision"""
        import hashlib
        data_str = json.dumps(input_data, sort_keys=True)
        combined = f"{policy_id}:{data_str}"
        return hashlib.sha256(combined.encode()).hexdigest()

    async def test_policy(
        self,
        policy_id: str,
        test_cases: List[Dict]
    ) -> Dict:
        """
        Test policy with multiple test cases

        Args:
            policy_id: Policy to test
            test_cases: List of test inputs with expected results

        Returns:
            Test results summary
        """
        results = {
            'total': len(test_cases),
            'passed': 0,
            'failed': 0,
            'details': []
        }

        for i, test_case in enumerate(test_cases):
            input_data = test_case.get('input', {})
            expected = test_case.get('expected', False)

            decision = await self.evaluate(policy_id, input_data)

            passed = decision.allowed == expected

            if passed:
                results['passed'] += 1
            else:
                results['failed'] += 1

            results['details'].append({
                'test_number': i + 1,
                'passed': passed,
                'expected': expected,
                'actual': decision.allowed,
                'reasons': decision.reasons
            })

        return results

    def get_metrics(self) -> Dict:
        """Get policy engine metrics"""
        cache_hit_rate = (
            self.cache_hits / max(self.total_evaluations, 1)
        ) * 100

        return {
            'total_policies': len(self.policies),
            'total_evaluations': self.total_evaluations,
            'cache_hits': self.cache_hits,
            'cache_hit_rate_percent': cache_hit_rate,
            'opa_queries': self.opa_client.query_count,
            'opa_errors': self.opa_client.query_errors
        }

    async def close(self):
        """Clean up resources"""
        await self.opa_client.close()