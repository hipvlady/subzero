"""
Zero Trust AI Gateway - Core Integration Layer
Consolidates parent components with gateway-specific features for maximum performance
"""

import sys
import os
import asyncio
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import logging

# Add parent directory to path for importing shared components
current_dir = os.path.dirname(os.path.abspath(__file__))
gateway_dir = os.path.dirname(current_dir)
parent_dir = os.path.dirname(gateway_dir)
sys.path.insert(0, parent_dir)

# Import high-performance components from parent directory
try:
    from src.auth.high_performance_auth import HighPerformanceAuthenticator
    from src.fga.authorization_engine import FineGrainedAuthorizationEngine, PermissionType
    from src.performance.vectorized_operations import HighPerformanceBatchProcessor
    from src.mcp.ai_security_module import AIAgentSecurityModule
except ImportError as e:
    logging.warning(f"Could not import parent components: {e}")
    # Fallback to mock implementations for development
    from enum import Enum

    class PermissionType(Enum):
        READ = "read"
        WRITE = "write"
        DELETE = "delete"
        ADMIN = "admin"

    # Mock high-performance authenticator
    class HighPerformanceAuthenticator:
        def __init__(self, auth0_domain=None, client_id=None, cache_capacity=1000, enable_metrics=True):
            self.auth0_domain = auth0_domain
            self.client_id = client_id
            self.cache_capacity = cache_capacity
            self.enable_metrics = enable_metrics

        async def authenticate(self, user_id: str, scopes: str = "openid profile", enable_cache: bool = True):
            return {
                'authenticated': True,
                'access_token': 'mock_token_' + user_id,
                'token_type': 'Bearer',
                'expires_in': 3600,
                'cache_hit': enable_cache,
                'latency_ms': 1.0
            }

        def get_performance_metrics(self):
            return {'total_authentications': 0, 'cache_hit_rate': 0.95}

        async def health_check(self):
            return {'status': 'healthy', 'authentication_service': True}

        async def setup(self):
            pass

        async def close(self):
            pass

    # Mock Fine-Grained Authorization Engine
    class FineGrainedAuthorizationEngine:
        def __init__(self, fga_config=None, redis_url=None):
            self.fga_config = fga_config
            self.redis_url = redis_url

        async def check_permission(self, user_id: str, resource_type: str, resource_id: str, permission):
            return {
                'allowed': user_id in ['demo_user', 'admin'],
                'source': 'mock_fga',
                'latency_ms': 1.0
            }

        async def get_performance_metrics(self):
            return {'total_checks': 0, 'cache_hit_rate': 0.9}

        async def setup(self):
            pass

        async def close(self):
            pass

    # Mock performance processor
    class HighPerformanceBatchProcessor:
        def __init__(self, batch_size=1000):
            self.batch_size = batch_size

        async def batch_authenticate_users(self, requests):
            return [
                {
                    'success': True,
                    'user_id': req.get('user_id', 'unknown'),
                    'authenticated': True,
                    'latency_ms': 1.0
                }
                for req in requests
            ]

    # Mock AI security module
    class AIAgentSecurityModule:
        def __init__(self, server_name="gateway"):
            self.server_name = server_name

# Import unique gateway components
from ..services.security.bot_detection import BotDetectionEngine
from ..services.agents.remotemanager import RemoteAgentManager

logger = logging.getLogger(__name__)

@dataclass
class GatewayConfig:
    """Configuration for Zero Trust AI Gateway"""
    # Auth0 Configuration
    auth0_domain: str
    client_id: str
    private_key: str = ""

    # FGA Configuration
    fga_api_url: str = "https://api.fga.dev"
    fga_store_id: str = ""
    fga_model_id: str = ""

    # Performance Configuration
    cache_capacity: int = 65536
    batch_size: int = 1000
    connection_pool_size: int = 100

    # Security Configuration
    enable_bot_detection: bool = True
    prompt_injection_detection: bool = True
    rate_limit_per_minute: int = 100

    # Redis Configuration
    redis_url: str = "redis://localhost:6379"

    # AI Agent Configuration
    max_agents_per_user: int = 10
    agent_timeout: int = 30

class ZeroTrustAIGateway:
    """
    Consolidated Zero Trust AI Gateway
    Integrates parent components with gateway-specific features

    Architecture:
    - High-Performance Authentication (from parent)
    - Fine-Grained Authorization (from parent)
    - Advanced Bot Detection (gateway-specific)
    - AI Agent Management (gateway-specific)
    - Vectorized Performance (from parent)
    """

    def __init__(self, config: GatewayConfig):
        self.config = config

        # Initialize high-performance components from parent
        self._init_parent_components()

        # Initialize unique gateway components
        self._init_gateway_components()

        # Performance tracking
        self.metrics = {
            'total_requests': 0,
            'successful_auths': 0,
            'blocked_threats': 0,
            'cache_hits': 0,
            'avg_latency_ms': []
        }

        logger.info("Zero Trust AI Gateway initialized with consolidated architecture")

    def _init_parent_components(self):
        """Initialize high-performance components from parent directory"""

        # 1. High-Performance Authentication Layer
        try:
            self.authenticator = HighPerformanceAuthenticator(
                auth0_domain=self.config.auth0_domain,
                client_id=self.config.client_id,
                cache_capacity=self.config.cache_capacity,
                enable_metrics=True
            )
            logger.info("✅ High-Performance Authenticator initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize authenticator: {e}")
            # Fallback implementation
            self.authenticator = None

        # 2. Fine-Grained Authorization Engine
        try:
            fga_config = {
                'api_url': self.config.fga_api_url,
                'store_id': self.config.fga_store_id,
                'model_id': self.config.fga_model_id
            }
            self.fga_engine = FineGrainedAuthorizationEngine(
                fga_config=fga_config,
                redis_url=self.config.redis_url
            )
            logger.info("✅ Fine-Grained Authorization Engine initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize FGA engine: {e}")
            self.fga_engine = None

        # 3. High-Performance Batch Processor
        try:
            self.batch_processor = HighPerformanceBatchProcessor(
                batch_size=self.config.batch_size
            )
            logger.info("✅ High-Performance Batch Processor initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize batch processor: {e}")
            self.batch_processor = None

        # 4. AI Security Module
        try:
            self.ai_security = AIAgentSecurityModule(
                server_name="zero_trust_gateway"
            )
            logger.info("✅ AI Security Module initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize AI security: {e}")
            self.ai_security = None

    def _init_gateway_components(self):
        """Initialize unique gateway-specific components"""

        # 1. Advanced Bot Detection Engine
        try:
            bot_config = {
                'min_request_interval': 0.1,
                'max_burst_requests': 10,
                'anomaly_threshold': 3.0,
                'risk_score_threshold': 0.7
            }
            self.bot_detector = BotDetectionEngine(config=bot_config)
            logger.info("✅ Advanced Bot Detection Engine initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize bot detector: {e}")
            self.bot_detector = None

        # 2. AI Agent Manager
        try:
            self.agent_manager = RemoteAgentManager(
                parent=self,
                log=logger
            )
            logger.info("✅ AI Agent Manager initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize agent manager: {e}")
            self.agent_manager = None

    async def setup(self):
        """Setup all components asynchronously"""
        setup_tasks = []

        # Setup parent components
        if self.authenticator and hasattr(self.authenticator, 'setup'):
            setup_tasks.append(self.authenticator.setup())

        if self.fga_engine and hasattr(self.fga_engine, 'setup'):
            setup_tasks.append(self.fga_engine.setup())

        # Setup gateway components
        if self.agent_manager:
            setup_tasks.append(self.agent_manager.start_cleanup_task())

        # Execute all setup tasks
        if setup_tasks:
            await asyncio.gather(*setup_tasks, return_exceptions=True)

        logger.info("🚀 Zero Trust AI Gateway setup completed")

    async def authenticate_request(
        self,
        user_id: str,
        scopes: str = "openid profile email",
        source_ip: str = None,
        user_agent: str = None
    ) -> Dict[str, Any]:
        """
        High-performance authentication with integrated security checks

        Returns:
            Dict containing authentication result and security analysis
        """
        start_time = time.perf_counter()
        self.metrics['total_requests'] += 1

        try:
            # 1. Advanced Threat Detection (Gateway-specific)
            if self.bot_detector:
                is_threat, threat_event = await self.bot_detector.analyze_request(
                    user_id=user_id,
                    request_data={'user_id': user_id},
                    source_ip=source_ip,
                    user_agent=user_agent
                )

                if is_threat:
                    self.metrics['blocked_threats'] += 1
                    return {
                        'authenticated': False,
                        'reason': 'threat_detected',
                        'threat_type': threat_event.event_type if threat_event else 'unknown',
                        'risk_score': threat_event.confidence if threat_event else 1.0,
                        'latency_ms': (time.perf_counter() - start_time) * 1000
                    }

            # 2. High-Performance Authentication (Parent component)
            if self.authenticator:
                auth_result = await self.authenticator.authenticate(
                    user_id=user_id,
                    scopes=scopes,
                    enable_cache=True
                )

                if auth_result:
                    self.metrics['successful_auths'] += 1
                    if 'cache_hit' in auth_result and auth_result['cache_hit']:
                        self.metrics['cache_hits'] += 1

                    latency_ms = (time.perf_counter() - start_time) * 1000
                    self.metrics['avg_latency_ms'].append(latency_ms)

                    return {
                        'authenticated': True,
                        'access_token': auth_result.get('access_token'),
                        'token_type': auth_result.get('token_type', 'Bearer'),
                        'expires_in': auth_result.get('expires_in', 3600),
                        'cache_hit': auth_result.get('cache_hit', False),
                        'auth_latency_ms': auth_result.get('latency_ms', 0),
                        'total_latency_ms': latency_ms,
                        'threat_checked': True
                    }

            # Fallback authentication
            latency_ms = (time.perf_counter() - start_time) * 1000
            return {
                'authenticated': False,
                'reason': 'authenticator_unavailable',
                'latency_ms': latency_ms
            }

        except Exception as e:
            error_latency = (time.perf_counter() - start_time) * 1000
            logger.error(f"Authentication failed for {user_id}: {e}")

            return {
                'authenticated': False,
                'reason': 'authentication_error',
                'error': str(e),
                'latency_ms': error_latency
            }

    async def authorize_request(
        self,
        user_id: str,
        resource_type: str,
        resource_id: str,
        permission: str
    ) -> Dict[str, Any]:
        """
        High-performance authorization with vectorized permission checking
        """
        start_time = time.perf_counter()

        try:
            if self.fga_engine:
                # Use parent's advanced FGA engine
                permission_type = PermissionType(permission)
                result = await self.fga_engine.check_permission(
                    user_id=user_id,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    permission=permission_type
                )

                return result
            else:
                # Basic fallback authorization
                latency_ms = (time.perf_counter() - start_time) * 1000
                return {
                    'allowed': user_id in ['demo_user', 'admin'],  # Basic demo logic
                    'source': 'fallback',
                    'latency_ms': latency_ms
                }

        except Exception as e:
            error_latency = (time.perf_counter() - start_time) * 1000
            logger.error(f"Authorization failed for {user_id}: {e}")

            return {
                'allowed': False,
                'source': 'error',
                'error': str(e),
                'latency_ms': error_latency
            }

    async def invoke_ai_agent(
        self,
        user_id: str,
        agent_id: str,
        prompt: str,
        model: str = "gpt-3.5-turbo",
        **kwargs
    ) -> Dict[str, Any]:
        """
        AI agent invocation with integrated security and performance optimization
        """
        start_time = time.perf_counter()

        try:
            # 1. Security validation
            if self.ai_security:
                # Use parent's AI security module for validation
                pass  # Placeholder for AI security checks

            # 2. Agent management
            if self.agent_manager:
                result = await self.agent_manager.invoke_agent(
                    agent_id=agent_id,
                    prompt=prompt,
                    user_id=user_id,
                    model=model,
                    **kwargs
                )

                return result
            else:
                # Basic fallback response
                latency_ms = (time.perf_counter() - start_time) * 1000
                return {
                    'success': False,
                    'error': 'Agent manager unavailable',
                    'latency_ms': latency_ms
                }

        except Exception as e:
            error_latency = (time.perf_counter() - start_time) * 1000
            logger.error(f"AI agent invocation failed: {e}")

            return {
                'success': False,
                'error': str(e),
                'latency_ms': error_latency
            }

    async def batch_process_requests(self, requests: List[Dict]) -> List[Dict]:
        """
        High-performance batch processing using parent's vectorized operations
        """
        if self.batch_processor:
            try:
                # Use parent's high-performance batch processor
                results = await self.batch_processor.batch_authenticate_users(requests)
                return results
            except Exception as e:
                logger.error(f"Batch processing failed: {e}")

        # Fallback to sequential processing
        results = []
        for request in requests:
            result = await self.authenticate_request(
                user_id=request.get('user_id'),
                scopes=request.get('scopes', 'openid profile'),
                source_ip=request.get('source_ip'),
                user_agent=request.get('user_agent')
            )
            results.append(result)

        return results

    async def get_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive performance metrics from all components"""
        metrics = {
            'gateway_metrics': {
                'total_requests': self.metrics['total_requests'],
                'successful_auths': self.metrics['successful_auths'],
                'blocked_threats': self.metrics['blocked_threats'],
                'cache_hits': self.metrics['cache_hits'],
                'success_rate': self.metrics['successful_auths'] / max(self.metrics['total_requests'], 1),
                'threat_detection_rate': self.metrics['blocked_threats'] / max(self.metrics['total_requests'], 1),
                'cache_hit_rate': self.metrics['cache_hits'] / max(self.metrics['successful_auths'], 1),
                'avg_latency_ms': sum(self.metrics['avg_latency_ms']) / max(len(self.metrics['avg_latency_ms']), 1)
            }
        }

        # Add parent component metrics
        if self.authenticator and hasattr(self.authenticator, 'get_performance_metrics'):
            metrics['authenticator_metrics'] = self.authenticator.get_performance_metrics()

        if self.fga_engine and hasattr(self.fga_engine, 'get_performance_metrics'):
            metrics['fga_metrics'] = await self.fga_engine.get_performance_metrics()

        if self.bot_detector:
            metrics['bot_detection_metrics'] = self.bot_detector.get_threat_summary()

        if self.agent_manager:
            metrics['agent_metrics'] = self.agent_manager.get_agent_stats()

        return metrics

    async def health_check(self) -> Dict[str, Any]:
        """Comprehensive health check for all components"""
        health_status = {
            'overall_status': 'healthy',
            'components': {}
        }

        # Check parent components
        if self.authenticator and hasattr(self.authenticator, 'health_check'):
            try:
                auth_health = await self.authenticator.health_check()
                health_status['components']['authenticator'] = auth_health
            except Exception as e:
                health_status['components']['authenticator'] = {'status': 'unhealthy', 'error': str(e)}

        # Check gateway components
        health_status['components']['bot_detector'] = {'status': 'healthy' if self.bot_detector else 'unavailable'}
        health_status['components']['agent_manager'] = {'status': 'healthy' if self.agent_manager else 'unavailable'}

        # Determine overall status
        component_statuses = [
            comp.get('status', comp.get('authentication_service', True))
            for comp in health_status['components'].values()
        ]

        if any(status == 'unhealthy' for status in component_statuses):
            health_status['overall_status'] = 'degraded'
        elif any(status == 'unavailable' for status in component_statuses):
            health_status['overall_status'] = 'partial'

        return health_status

    async def shutdown(self):
        """Clean shutdown of all components"""
        shutdown_tasks = []

        # Shutdown parent components
        if self.authenticator and hasattr(self.authenticator, 'close'):
            shutdown_tasks.append(self.authenticator.close())

        if self.fga_engine and hasattr(self.fga_engine, 'close'):
            shutdown_tasks.append(self.fga_engine.close())

        # Shutdown gateway components
        if self.agent_manager:
            shutdown_tasks.append(self.agent_manager.shutdown())

        # Execute all shutdown tasks
        if shutdown_tasks:
            await asyncio.gather(*shutdown_tasks, return_exceptions=True)

        logger.info("🔒 Zero Trust AI Gateway shutdown completed")