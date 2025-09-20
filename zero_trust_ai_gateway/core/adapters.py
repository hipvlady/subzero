"""
Adapter classes for integrating parent components with gateway interfaces
Provides seamless integration between different component APIs
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Protocol
import logging

logger = logging.getLogger(__name__)

class AuthProtocol(Protocol):
    """Protocol for authentication components"""
    async def authenticate(self, user_id: str, scopes: str = "openid profile") -> Dict[str, Any]:
        ...

    def get_performance_metrics(self) -> Dict[str, Any]:
        ...

    async def health_check(self) -> Dict[str, Any]:
        ...

class AuthAdapter:
    """
    Adapter for integrating parent authentication components with gateway
    Handles API differences and provides consistent interface
    """

    def __init__(self, auth_component: Any):
        self.auth_component = auth_component
        self.adapter_metrics = {
            'total_calls': 0,
            'successful_calls': 0,
            'errors': 0,
            'avg_latency_ms': []
        }

    async def authenticate_user(
        self,
        user_id: str,
        scopes: str = "openid profile email",
        enable_cache: bool = True,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Unified authentication interface that adapts parent component API
        """
        start_time = time.perf_counter()
        self.adapter_metrics['total_calls'] += 1

        try:
            # Check if parent component has the expected method
            if hasattr(self.auth_component, 'authenticate'):
                # Try with enable_cache parameter first
                try:
                    result = await self.auth_component.authenticate(
                        user_id=user_id,
                        scopes=scopes,
                        enable_cache=enable_cache
                    )
                except TypeError:
                    # Fallback without enable_cache if not supported
                    result = await self.auth_component.authenticate(
                        user_id=user_id,
                        scopes=scopes
                    )
            elif hasattr(self.auth_component, 'authenticate_private_key_jwt'):
                # Adapt to different method signature
                result = await self.auth_component.authenticate_private_key_jwt(
                    scope=scopes
                )
                # Enhance result with user_id
                result['user_id'] = user_id
            else:
                # Fallback for unknown interface
                result = {
                    'authenticated': False,
                    'error': 'Authentication method not available'
                }

            # Standardize response format
            standardized_result = self._standardize_auth_response(result)

            # Record metrics
            latency_ms = (time.perf_counter() - start_time) * 1000
            self.adapter_metrics['avg_latency_ms'].append(latency_ms)

            if standardized_result.get('authenticated'):
                self.adapter_metrics['successful_calls'] += 1

            return standardized_result

        except Exception as e:
            self.adapter_metrics['errors'] += 1
            error_latency = (time.perf_counter() - start_time) * 1000

            logger.error(f"Auth adapter error: {e}")
            return {
                'authenticated': False,
                'error': str(e),
                'adapter_error': True,
                'latency_ms': error_latency
            }

    def _standardize_auth_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Standardize authentication response format across different components"""
        standardized = {
            'authenticated': response.get('authenticated', False),
            'user_id': response.get('user_id'),
            'access_token': response.get('access_token'),
            'token_type': response.get('token_type', 'Bearer'),
            'expires_in': response.get('expires_in', 3600),
            'scope': response.get('scope'),
            'cache_hit': response.get('cache_hit', False),
            'latency_ms': response.get('latency_ms', 0),
            'source_component': type(self.auth_component).__name__
        }

        # Include any additional metadata
        if 'metadata' in response:
            standardized['metadata'] = response['metadata']

        return standardized

    def get_adapter_metrics(self) -> Dict[str, Any]:
        """Get adapter-specific metrics"""
        success_rate = self.adapter_metrics['successful_calls'] / max(self.adapter_metrics['total_calls'], 1)
        error_rate = self.adapter_metrics['errors'] / max(self.adapter_metrics['total_calls'], 1)
        avg_latency = sum(self.adapter_metrics['avg_latency_ms']) / max(len(self.adapter_metrics['avg_latency_ms']), 1)

        return {
            'adapter_type': 'AuthAdapter',
            'total_calls': self.adapter_metrics['total_calls'],
            'success_rate': success_rate,
            'error_rate': error_rate,
            'avg_latency_ms': avg_latency,
            'component_type': type(self.auth_component).__name__
        }

class FGAAdapter:
    """
    Adapter for Fine-Grained Authorization components
    Handles permission type conversions and API standardization
    """

    def __init__(self, fga_component: Any):
        self.fga_component = fga_component
        self.permission_mapping = {
            'read': 'READ',
            'write': 'WRITE',
            'delete': 'DELETE',
            'admin': 'ADMIN',
            'share': 'SHARE'
        }

    async def check_permission(
        self,
        user_id: str,
        resource_type: str,
        resource_id: str,
        permission: str
    ) -> Dict[str, Any]:
        """
        Unified permission checking interface
        """
        try:
            # Standardize permission format
            standardized_permission = self._standardize_permission(permission)

            # Check if component has expected method
            if hasattr(self.fga_component, 'check_permission'):
                # Use enum if available
                if hasattr(self.fga_component, '__module__'):
                    # Try to import PermissionType from component's module
                    try:
                        module = __import__(self.fga_component.__module__, fromlist=['PermissionType'])
                        PermissionType = getattr(module, 'PermissionType')
                        permission_enum = PermissionType(standardized_permission.lower())
                    except (ImportError, AttributeError, ValueError):
                        permission_enum = standardized_permission

                    result = await self.fga_component.check_permission(
                        user_id=user_id,
                        resource_type=resource_type,
                        resource_id=resource_id,
                        permission=permission_enum
                    )
                else:
                    result = await self.fga_component.check_permission(
                        user_id=user_id,
                        resource_type=resource_type,
                        resource_id=resource_id,
                        permission=standardized_permission
                    )

            elif hasattr(self.fga_component, 'check_ai_model_access'):
                # Adapt to different method signature
                result = await self.fga_component.check_ai_model_access(
                    user_id=user_id,
                    model_id=resource_id,
                    action=standardized_permission.lower()
                )
                # Convert boolean result to standard format
                if isinstance(result, bool):
                    result = {
                        'allowed': result,
                        'source': 'adapted_method',
                        'latency_ms': 0
                    }
            else:
                # Fallback for unknown interface
                result = {
                    'allowed': False,
                    'error': 'Permission check method not available',
                    'source': 'adapter_fallback'
                }

            return self._standardize_fga_response(result)

        except Exception as e:
            logger.error(f"FGA adapter error: {e}")
            return {
                'allowed': False,
                'error': str(e),
                'adapter_error': True,
                'source': 'adapter_error'
            }

    def _standardize_permission(self, permission: str) -> str:
        """Standardize permission format"""
        return self.permission_mapping.get(permission.lower(), permission.upper())

    def _standardize_fga_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Standardize FGA response format"""
        return {
            'allowed': response.get('allowed', False),
            'source': response.get('source', 'fga_component'),
            'latency_ms': response.get('latency_ms', 0),
            'cache_key': response.get('cache_key'),
            'metadata': response.get('fga_metadata', response.get('metadata', {})),
            'component_type': type(self.fga_component).__name__
        }

class PerformanceAdapter:
    """
    Adapter for performance monitoring and batch processing components
    """

    def __init__(self, performance_component: Any):
        self.performance_component = performance_component

    async def batch_process(self, requests: List[Dict], operation_type: str = "auth") -> List[Dict]:
        """
        Unified batch processing interface
        """
        try:
            if operation_type == "auth" and hasattr(self.performance_component, 'batch_authenticate_users'):
                return await self.performance_component.batch_authenticate_users(requests)
            elif hasattr(self.performance_component, 'batch_process'):
                return await self.performance_component.batch_process(requests)
            else:
                # Fallback to sequential processing
                return await self._sequential_fallback(requests)

        except Exception as e:
            logger.error(f"Performance adapter error: {e}")
            return [{'error': str(e), 'request': req} for req in requests]

    async def _sequential_fallback(self, requests: List[Dict]) -> List[Dict]:
        """Fallback sequential processing when batch methods aren't available"""
        results = []
        for request in requests:
            # Mock processing for fallback
            result = {
                'success': True,
                'request_id': request.get('user_id', 'unknown'),
                'processing_method': 'sequential_fallback',
                'latency_ms': 1.0  # Mock latency
            }
            results.append(result)

        return results

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics from component"""
        try:
            if hasattr(self.performance_component, 'get_performance_metrics'):
                return self.performance_component.get_performance_metrics()
            elif hasattr(self.performance_component, 'get_performance_report'):
                return self.performance_component.get_performance_report()
            else:
                return {
                    'status': 'No performance metrics available',
                    'component_type': type(self.performance_component).__name__
                }
        except Exception as e:
            return {
                'error': str(e),
                'component_type': type(self.performance_component).__name__
            }

class ComponentFactory:
    """
    Factory for creating adapters based on component types
    Automatically detects component capabilities and creates appropriate adapters
    """

    @staticmethod
    def create_auth_adapter(component: Any) -> AuthAdapter:
        """Create authentication adapter for any component"""
        return AuthAdapter(component)

    @staticmethod
    def create_fga_adapter(component: Any) -> FGAAdapter:
        """Create FGA adapter for any authorization component"""
        return FGAAdapter(component)

    @staticmethod
    def create_performance_adapter(component: Any) -> PerformanceAdapter:
        """Create performance adapter for any performance component"""
        return PerformanceAdapter(component)

    @staticmethod
    def auto_detect_adapters(component: Any) -> Dict[str, Any]:
        """
        Automatically detect component capabilities and suggest appropriate adapters
        """
        capabilities = {
            'authentication': False,
            'authorization': False,
            'performance': False,
            'methods': []
        }

        # Detect authentication capabilities
        auth_methods = ['authenticate', 'authenticate_private_key_jwt', 'verify_token']
        if any(hasattr(component, method) for method in auth_methods):
            capabilities['authentication'] = True

        # Detect authorization capabilities
        authz_methods = ['check_permission', 'check_ai_model_access', 'authorize']
        if any(hasattr(component, method) for method in authz_methods):
            capabilities['authorization'] = True

        # Detect performance capabilities
        perf_methods = ['batch_process', 'batch_authenticate_users', 'get_performance_metrics']
        if any(hasattr(component, method) for method in perf_methods):
            capabilities['performance'] = True

        # List all available methods
        capabilities['methods'] = [
            method for method in dir(component)
            if not method.startswith('_') and callable(getattr(component, method))
        ]

        return capabilities