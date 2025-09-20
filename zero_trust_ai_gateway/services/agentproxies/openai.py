"""OpenAI agent proxy implementation with high-performance optimizations."""

import asyncio
import time
import json
from typing import Dict, List, AsyncGenerator, Any, Optional
import httpx
import logging

from .agentproxy import BaseAgentProxyABC, AgentCapability

logger = logging.getLogger(__name__)

class OpenAIAgentProxy(BaseAgentProxyABC):
    """OpenAI API proxy implementation with connection pooling and caching"""

    def __init__(self, agent_manager, proxy_config: Dict[str, Any]):
        super().__init__(agent_manager, proxy_config)

        # OpenAI-specific configuration
        self.api_key = proxy_config.get('api_key')
        self.base_url = proxy_config.get('base_url', 'https://api.openai.com/v1')
        self.model = proxy_config.get('model', 'gpt-3.5-turbo')
        self.max_tokens = proxy_config.get('max_tokens', 4000)
        self.temperature = proxy_config.get('temperature', 0.7)

        # Performance settings
        self.connection_pool_size = proxy_config.get('connection_pool_size', 10)
        self.connection_timeout = proxy_config.get('connection_timeout', 10.0)

        # Security settings
        self.content_filter = proxy_config.get('content_filtering', True)
        self.max_prompt_length = proxy_config.get('max_prompt_length', 50000)

        # Initialize HTTP client with connection pooling
        self.client = None
        self._setup_client()

        # Define capabilities based on model
        self.capabilities = self._get_model_capabilities()

    def _setup_client(self):
        """Setup HTTP client with optimized connection pooling"""
        limits = httpx.Limits(
            max_connections=self.connection_pool_size,
            max_keepalive_connections=self.connection_pool_size // 2,
            keepalive_expiry=30
        )

        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            limits=limits,
            timeout=httpx.Timeout(self.connection_timeout),
            headers={
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
        )

    def _get_model_capabilities(self) -> set:
        """Get capabilities based on model type"""
        base_caps = {
            AgentCapability.TEXT_GENERATION,
            AgentCapability.SUMMARIZATION
        }

        # Add capabilities based on model
        if 'gpt-4' in self.model.lower():
            base_caps.update({
                AgentCapability.CODE_GENERATION,
                AgentCapability.MATH_REASONING,
                AgentCapability.FUNCTION_CALLING
            })

        if 'vision' in self.model.lower():
            base_caps.add(AgentCapability.IMAGE_ANALYSIS)
            base_caps.add(AgentCapability.MULTIMODAL)

        return base_caps

    async def invoke_agent(self, prompt: str, **kwargs) -> Dict:
        """Invoke OpenAI agent with performance tracking"""
        start_time = time.perf_counter()

        try:
            # Security checks
            user_id = kwargs.get('user_id')
            if not self.is_authorized(user_id, kwargs.get('capabilities')):
                return {
                    'success': False,
                    'error': 'User not authorized for this agent',
                    'latency_ms': 0
                }

            # Validate prompt length
            if len(prompt) > self.max_prompt_length:
                return {
                    'success': False,
                    'error': f'Prompt exceeds maximum length of {self.max_prompt_length} characters',
                    'latency_ms': 0
                }

            # Content filtering
            if self.content_filter and not self._validate_content(prompt):
                return {
                    'success': False,
                    'error': 'Content violates safety policies',
                    'latency_ms': 0
                }

            # Prepare request payload
            payload = self._build_request_payload(prompt, **kwargs)

            # Make API call
            response = await self._make_api_call('/chat/completions', payload)

            if response.status_code != 200:
                error_msg = f"OpenAI API error: {response.status_code}"
                try:
                    error_data = response.json()
                    error_msg = error_data.get('error', {}).get('message', error_msg)
                except:
                    pass

                return {
                    'success': False,
                    'error': error_msg,
                    'latency_ms': (time.perf_counter() - start_time) * 1000,
                    'agent_id': self.agent_id
                }

            # Parse response
            response_data = response.json()
            choice = response_data['choices'][0]

            # Calculate performance metrics
            end_time = time.perf_counter()
            latency_ms = (end_time - start_time) * 1000

            # Update metrics
            self.update_metrics(latency_ms, True)

            return {
                'success': True,
                'response': choice['message']['content'],
                'model': self.model,
                'usage': response_data.get('usage', {}),
                'latency_ms': round(latency_ms, 2),
                'agent_id': self.agent_id,
                'finish_reason': choice.get('finish_reason')
            }

        except Exception as e:
            end_time = time.perf_counter()
            latency_ms = (end_time - start_time) * 1000
            self.update_metrics(latency_ms, False)

            logger.error(f"OpenAI agent invocation failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'latency_ms': round(latency_ms, 2),
                'agent_id': self.agent_id
            }

    async def stream_response(self, prompt: str, **kwargs) -> AsyncGenerator:
        """Stream response for real-time AI interactions"""
        try:
            # Security and validation checks (same as invoke_agent)
            user_id = kwargs.get('user_id')
            if not self.is_authorized(user_id, kwargs.get('capabilities')):
                yield {
                    'error': 'User not authorized for this agent',
                    'agent_id': self.agent_id
                }
                return

            if len(prompt) > self.max_prompt_length:
                yield {
                    'error': f'Prompt exceeds maximum length of {self.max_prompt_length} characters',
                    'agent_id': self.agent_id
                }
                return

            # Prepare streaming request
            payload = self._build_request_payload(prompt, stream=True, **kwargs)

            # Make streaming API call
            async with self.client.stream(
                'POST',
                '/chat/completions',
                json=payload
            ) as response:

                if response.status_code != 200:
                    yield {
                        'error': f'OpenAI API error: {response.status_code}',
                        'agent_id': self.agent_id
                    }
                    return

                async for line in response.aiter_lines():
                    if line.startswith('data: '):
                        data_str = line[6:]  # Remove 'data: ' prefix

                        if data_str.strip() == '[DONE]':
                            break

                        try:
                            data = json.loads(data_str)
                            choice = data['choices'][0]
                            delta = choice.get('delta', {})

                            if 'content' in delta:
                                yield {
                                    'content': delta['content'],
                                    'agent_id': self.agent_id,
                                    'finish_reason': choice.get('finish_reason')
                                }

                        except json.JSONDecodeError:
                            continue

        except Exception as e:
            logger.error(f"OpenAI streaming failed: {e}")
            yield {
                'error': str(e),
                'agent_id': self.agent_id
            }

    async def health_check(self) -> bool:
        """Check OpenAI API availability"""
        try:
            if not self.api_key:
                return False

            # Simple health check - get models list
            response = await self._make_api_call('/models', method='GET')
            return response.status_code == 200

        except Exception as e:
            logger.error(f"OpenAI health check failed: {e}")
            return False

    async def validate_capabilities(self, required_caps: List[str]) -> bool:
        """Validate OpenAI model capabilities"""
        try:
            required_cap_set = {AgentCapability(cap) for cap in required_caps}
            return required_cap_set.issubset(self.capabilities)
        except ValueError:
            return False

    def _build_request_payload(self, prompt: str, stream: bool = False, **kwargs) -> Dict:
        """Build OpenAI API request payload"""
        messages = [{"role": "user", "content": prompt}]

        # Add system message if specified
        system_message = kwargs.get('system_message')
        if system_message:
            messages.insert(0, {"role": "system", "content": system_message})

        # Add conversation history if provided
        history = kwargs.get('conversation_history', [])
        if history:
            messages = history + messages

        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": kwargs.get('max_tokens', self.max_tokens),
            "temperature": kwargs.get('temperature', self.temperature),
            "stream": stream
        }

        # Add optional parameters
        if kwargs.get('top_p'):
            payload['top_p'] = kwargs['top_p']

        if kwargs.get('frequency_penalty'):
            payload['frequency_penalty'] = kwargs['frequency_penalty']

        if kwargs.get('presence_penalty'):
            payload['presence_penalty'] = kwargs['presence_penalty']

        return payload

    async def _make_api_call(self, endpoint: str, payload: Dict = None, method: str = 'POST') -> httpx.Response:
        """Make API call with retry logic"""
        for attempt in range(self.max_retries):
            try:
                if method == 'GET':
                    response = await self.client.get(endpoint)
                else:
                    response = await self.client.post(endpoint, json=payload)

                return response

            except Exception as e:
                if attempt == self.max_retries - 1:
                    raise e

                # Exponential backoff
                await asyncio.sleep(2 ** attempt)

        raise Exception("Max retries exceeded")

    def _validate_content(self, content: str) -> bool:
        """Basic content validation"""
        # Implement content safety checks
        # This is a placeholder - in production, integrate with OpenAI moderation API

        harmful_patterns = [
            'how to make explosives',
            'illegal activities',
            'harmful instructions'
        ]

        content_lower = content.lower()
        return not any(pattern in content_lower for pattern in harmful_patterns)

    async def close(self):
        """Close HTTP client"""
        if self.client:
            await self.client.aclose()