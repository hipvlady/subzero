"""Base agent proxy classes adapted from Enterprise Gateway ProcessProxy pattern."""

import abc
import asyncio
import time
from enum import Enum
from typing import Dict, List, Optional, Any, AsyncGenerator
import numpy as np

class AgentCapability(Enum):
    """Enumeration of AI agent capabilities"""
    TEXT_GENERATION = "text_generation"
    CODE_GENERATION = "code_generation"
    IMAGE_ANALYSIS = "image_analysis"
    SUMMARIZATION = "summarization"
    TRANSLATION = "translation"
    MATH_REASONING = "math_reasoning"
    FUNCTION_CALLING = "function_calling"
    MULTIMODAL = "multimodal"

class BaseAgentProxyABC(abc.ABC):
    """Agent Proxy Abstract Base Class - adapted from Enterprise Gateway ProcessProxy pattern"""

    def __init__(self, agent_manager, proxy_config: Dict[str, Any]):
        """Initialize the agent proxy instance.

        Parameters
        ----------
        agent_manager : RemoteAgentManager
            The agent manager instance tied to this agent proxy
        proxy_config : dict
            The dictionary of per-agent config settings
        """
        self.agent_manager = agent_manager
        self.log = agent_manager.log if agent_manager else None
        self.agent_id = proxy_config.get('agent_id', f"agent-{int(time.time())}")

        # Performance optimization settings
        self.request_timeout = float(proxy_config.get('request_timeout', 30.0))
        self.max_retries = int(proxy_config.get('max_retries', 3))

        # Security settings (adapted from Enterprise Gateway authorization pattern)
        self.unauthorized_users = set(proxy_config.get('unauthorized_users', []))
        self.authorized_users = set(proxy_config.get('authorized_users', []))
        self.required_capabilities = set(proxy_config.get('required_capabilities', []))

        # Performance tracking
        self.request_count = 0
        self.total_latency = 0.0
        self.error_count = 0
        self.last_request_time = 0.0

        # Configuration
        self.config = proxy_config

    @abc.abstractmethod
    async def invoke_agent(self, prompt: str, **kwargs) -> Dict:
        """Invoke the AI agent with given prompt."""
        pass

    @abc.abstractmethod
    async def stream_response(self, prompt: str, **kwargs) -> AsyncGenerator:
        """Stream response from AI agent."""
        pass

    @abc.abstractmethod
    async def health_check(self) -> bool:
        """Check agent availability and health."""
        pass

    @abc.abstractmethod
    async def validate_capabilities(self, required_caps: List[str]) -> bool:
        """Validate agent capabilities against requirements."""
        pass

    def is_authorized(self, user_id: str, capabilities: List[str] = None) -> bool:
        """Check if user is authorized for this agent (Enterprise Gateway pattern)"""
        # Check unauthorized list first (fail fast)
        if user_id in self.unauthorized_users:
            return False

        # Check authorized list if specified
        if self.authorized_users and user_id not in self.authorized_users:
            return False

        # Check capability requirements
        if capabilities and self.required_capabilities:
            required_set = set(capabilities)
            if not required_set.issubset(self.required_capabilities):
                return False

        return True

    def update_metrics(self, latency_ms: float, success: bool = True):
        """Update performance metrics"""
        self.request_count += 1
        self.total_latency += latency_ms
        self.last_request_time = time.time()

        if not success:
            self.error_count += 1

    def get_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        return {
            'agent_id': self.agent_id,
            'request_count': self.request_count,
            'error_count': self.error_count,
            'error_rate': self.error_count / max(self.request_count, 1),
            'avg_latency_ms': self.total_latency / max(self.request_count, 1),
            'last_request_time': self.last_request_time,
            'uptime_seconds': time.time() - self.last_request_time if self.last_request_time > 0 else 0
        }

class MockAgentProxy(BaseAgentProxyABC):
    """Mock agent proxy for testing and development"""

    def __init__(self, agent_manager, proxy_config: Dict[str, Any]):
        super().__init__(agent_manager, proxy_config)

        # Mock configuration
        self.model = proxy_config.get('model', 'mock-model')
        self.latency_ms = float(proxy_config.get('mock_latency_ms', 50.0))

        # Define capabilities
        self.capabilities = {
            AgentCapability.TEXT_GENERATION,
            AgentCapability.SUMMARIZATION
        }

    async def invoke_agent(self, prompt: str, **kwargs) -> Dict:
        """Mock agent invocation"""
        start_time = time.perf_counter()

        try:
            # Security check
            user_id = kwargs.get('user_id')
            if not self.is_authorized(user_id, kwargs.get('capabilities')):
                return {
                    'success': False,
                    'error': 'User not authorized for this agent',
                    'latency_ms': 0
                }

            # Simulate processing time
            await asyncio.sleep(self.latency_ms / 1000)

            # Generate mock response
            response_text = f"Mock AI response to: {prompt[:50]}..."

            # Calculate performance metrics
            end_time = time.perf_counter()
            latency_ms = (end_time - start_time) * 1000

            # Update metrics
            self.update_metrics(latency_ms, True)

            return {
                'success': True,
                'response': response_text,
                'model': self.model,
                'usage': {
                    'prompt_tokens': len(prompt.split()),
                    'completion_tokens': len(response_text.split()),
                    'total_tokens': len(prompt.split()) + len(response_text.split())
                },
                'latency_ms': latency_ms,
                'agent_id': self.agent_id
            }

        except Exception as e:
            end_time = time.perf_counter()
            latency_ms = (end_time - start_time) * 1000
            self.update_metrics(latency_ms, False)

            return {
                'success': False,
                'error': str(e),
                'latency_ms': latency_ms,
                'agent_id': self.agent_id
            }

    async def stream_response(self, prompt: str, **kwargs) -> AsyncGenerator:
        """Mock streaming response"""
        try:
            response_text = f"Mock streaming response to: {prompt}"
            words = response_text.split()

            for i, word in enumerate(words):
                await asyncio.sleep(0.1)  # Simulate streaming delay
                yield {
                    'content': word + " ",
                    'agent_id': self.agent_id,
                    'finish_reason': 'stop' if i == len(words) - 1 else None
                }

        except Exception as e:
            yield {
                'error': str(e),
                'agent_id': self.agent_id
            }

    async def health_check(self) -> bool:
        """Mock health check"""
        return True

    async def validate_capabilities(self, required_caps: List[str]) -> bool:
        """Validate mock capabilities"""
        try:
            required_cap_set = {AgentCapability(cap) for cap in required_caps}
            return required_cap_set.issubset(self.capabilities)
        except ValueError:
            return False