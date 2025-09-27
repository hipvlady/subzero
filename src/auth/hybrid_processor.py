"""
Hybrid Request Processor for Intelligent Work Routing
Intelligently routes work based on operation type to maximize performance
- CPU-bound operations: Uses multiprocessing (bypasses GIL)
- I/O-bound operations: Uses asyncio/threading (efficient with GIL)
"""

import asyncio
import aiohttp
import time
import psutil
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass
from enum import Enum
import numpy as np

try:
    import orjson
except ImportError:
    import json as orjson

from auth.multiprocess_jwt import MultiProcessJWTProcessor
from auth.parallel_hash import ParallelHashComputer
from auth.distributed_cache import DistributedCacheManager
from config.settings import settings


class OperationType(Enum):
    """Operation type classification for routing decisions"""
    CPU_BOUND = "cpu_bound"
    IO_BOUND = "io_bound"
    MIXED = "mixed"
    UNKNOWN = "unknown"


@dataclass
class RequestContext:
    """Request context for processing decisions"""
    request_id: str
    user_id: str
    operation_type: OperationType
    batch_size: int = 1
    priority: int = 0
    timeout: float = 30.0
    created_at: float = 0.0

    def __post_init__(self):
        if self.created_at == 0.0:
            self.created_at = time.time()


@dataclass
class ProcessingResult:
    """Result of hybrid processing"""
    request_id: str
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    processing_time: float = 0.0
    operation_type: OperationType = OperationType.UNKNOWN
    routing_decision: str = ""


class WorkloadAnalyzer:
    """
    Analyzes workload characteristics to make intelligent routing decisions
    """

    def __init__(self):
        # Operation timing history for classification
        self.operation_history = {
            'jwt_signing': [],
            'hash_computation': [],
            'cache_operations': [],
            'auth0_api_calls': [],
            'db_queries': []
        }

        # CPU and I/O metrics
        self.cpu_threshold = 70.0  # CPU utilization percentage
        self.io_threshold = 100    # I/O operations per second

    def classify_operation(self, operation: str, batch_size: int = 1) -> OperationType:
        """
        Classify operation type based on characteristics

        Args:
            operation: Operation name
            batch_size: Number of items in batch

        Returns:
            Classified operation type
        """

        # CPU-bound operations
        cpu_bound_ops = {
            'jwt_signing', 'jwt_verification', 'hash_computation',
            'encryption', 'decryption', 'signature_verification'
        }

        # I/O-bound operations
        io_bound_ops = {
            'auth0_api_call', 'database_query', 'cache_lookup',
            'redis_operation', 'file_read', 'network_request'
        }

        # Mixed operations
        mixed_ops = {
            'user_authentication', 'batch_processing', 'data_transformation'
        }

        if operation in cpu_bound_ops:
            # Large batches benefit more from multiprocessing
            if batch_size >= settings.BATCH_SIZE_THRESHOLD:
                return OperationType.CPU_BOUND
            else:
                return OperationType.CPU_BOUND

        elif operation in io_bound_ops:
            return OperationType.IO_BOUND

        elif operation in mixed_ops:
            return OperationType.MIXED

        else:
            # Use historical data and system metrics for unknown operations
            return self._analyze_unknown_operation(operation)

    def _analyze_unknown_operation(self, operation: str) -> OperationType:
        """Analyze unknown operation based on system metrics"""

        # Get current system metrics
        cpu_percent = psutil.cpu_percent(interval=0.1)
        io_counters = psutil.disk_io_counters()

        # Simple heuristic based on current system state
        if cpu_percent > self.cpu_threshold:
            return OperationType.CPU_BOUND
        elif io_counters and io_counters.read_count > self.io_threshold:
            return OperationType.IO_BOUND
        else:
            return OperationType.MIXED

    def should_use_multiprocessing(self, operation_type: OperationType,
                                 batch_size: int, current_load: Dict[str, float]) -> bool:
        """
        Decide whether to use multiprocessing based on operation characteristics

        Args:
            operation_type: Type of operation
            batch_size: Size of batch
            current_load: Current system load metrics

        Returns:
            True if multiprocessing should be used
        """

        # Always use multiprocessing for CPU-bound operations above threshold
        if operation_type == OperationType.CPU_BOUND:
            return batch_size >= settings.BATCH_SIZE_THRESHOLD

        # Never use multiprocessing for pure I/O operations
        if operation_type == OperationType.IO_BOUND:
            return False

        # For mixed operations, consider current load
        if operation_type == OperationType.MIXED:
            cpu_usage = current_load.get('cpu_percent', 0)
            # Use multiprocessing if CPU is underutilized and batch is large enough
            return (cpu_usage < 50 and batch_size >= settings.BATCH_SIZE_THRESHOLD)

        return False

    def update_operation_stats(self, operation: str, processing_time: float,
                             operation_type: OperationType):
        """Update operation timing statistics"""

        if operation in self.operation_history:
            history = self.operation_history[operation]
            history.append(processing_time)

            # Keep only recent history (last 100 operations)
            if len(history) > 100:
                history.pop(0)


class HybridRequestProcessor:
    """
    Hybrid request processor that intelligently routes work based on operation type
    Maximizes performance by using the right concurrency model for each task type

    Architecture:
    - CPU-bound operations → Multiprocessing (bypass GIL)
    - I/O-bound operations → Asyncio/Threading (efficient with GIL)
    - Mixed operations → Intelligent routing based on system state
    """

    def __init__(self):
        # Multiprocessing components for CPU-bound work
        self.jwt_processor = MultiProcessJWTProcessor(
            num_workers=settings.JWT_PROCESSOR_WORKERS
        )
        self.hash_computer = ParallelHashComputer(
            num_workers=settings.HASH_PROCESSOR_WORKERS
        )

        # Threading components for I/O-bound work
        self.io_thread_pool = ThreadPoolExecutor(
            max_workers=settings.MAX_CONNECTIONS // 10  # Conservative sizing
        )

        # Distributed cache for shared state
        self.cache_manager = DistributedCacheManager()

        # Workload analyzer for routing decisions
        self.analyzer = WorkloadAnalyzer()

        # HTTP session for I/O operations
        self.http_session = None
        self._setup_http_session()

        # Performance metrics
        self.metrics = {
            'total_requests': 0,
            'cpu_bound_requests': 0,
            'io_bound_requests': 0,
            'mixed_requests': 0,
            'multiprocess_time': 0.0,
            'async_time': 0.0,
            'cache_hits': 0,
            'cache_misses': 0,
            'routing_decisions': {}
        }

    def _setup_http_session(self):
        """Setup optimized HTTP session for I/O operations"""
        connector = aiohttp.TCPConnector(
            limit=settings.MAX_CONNECTIONS,
            limit_per_host=settings.CONNECTION_POOL_SIZE,
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
            keepalive_timeout=30,
            tcp_nodelay=True
        )

        timeout = aiohttp.ClientTimeout(
            total=30,
            connect=5,
            sock_read=10
        )

        self.http_session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            json_serialize=orjson.dumps if hasattr(orjson, 'dumps') else None
        )

    async def process_authentication_request(self, context: RequestContext) -> ProcessingResult:
        """
        Process authentication request using hybrid approach

        Args:
            context: Request context with routing information

        Returns:
            Processing result with performance metrics
        """
        start_time = time.perf_counter()
        self.metrics['total_requests'] += 1

        try:
            # Step 1: Fast cache lookup (I/O-bound - use async)
            cached_result = await self._check_cache_async(context.user_id)

            if cached_result:
                self.metrics['cache_hits'] += 1
                processing_time = (time.perf_counter() - start_time) * 1000

                return ProcessingResult(
                    request_id=context.request_id,
                    success=True,
                    data=cached_result,
                    processing_time=processing_time,
                    operation_type=OperationType.IO_BOUND,
                    routing_decision="cache_hit_async"
                )

            self.metrics['cache_misses'] += 1

            # Step 2: Determine processing strategy
            routing_decision = await self._make_routing_decision(context)

            # Step 3: Execute based on routing decision
            result = await self._execute_with_routing(context, routing_decision)

            # Step 4: Cache the result (I/O-bound - use async)
            if result.success and result.data:
                await self._cache_result_async(context.user_id, result.data)

            result.processing_time = (time.perf_counter() - start_time) * 1000
            result.routing_decision = routing_decision

            # Update metrics
            self.analyzer.update_operation_stats(
                'user_authentication',
                result.processing_time,
                result.operation_type
            )

            return result

        except Exception as e:
            processing_time = (time.perf_counter() - start_time) * 1000

            return ProcessingResult(
                request_id=context.request_id,
                success=False,
                error=str(e),
                processing_time=processing_time,
                routing_decision="error"
            )

    async def _make_routing_decision(self, context: RequestContext) -> str:
        """
        Make intelligent routing decision based on context and system state

        Returns:
            Routing strategy string
        """

        # Get current system metrics
        system_load = {
            'cpu_percent': psutil.cpu_percent(interval=0.1),
            'memory_percent': psutil.virtual_memory().percent,
            'active_processes': len(psutil.pids())
        }

        # Classify the operation
        operation_type = self.analyzer.classify_operation(
            'user_authentication',
            context.batch_size
        )

        # Decide on multiprocessing vs async
        use_multiprocessing = self.analyzer.should_use_multiprocessing(
            operation_type,
            context.batch_size,
            system_load
        )

        if use_multiprocessing:
            if context.batch_size >= settings.BATCH_SIZE_THRESHOLD:
                return "multiprocess_batch"
            else:
                return "multiprocess_single"
        else:
            if operation_type == OperationType.IO_BOUND:
                return "async_io"
            else:
                return "async_mixed"

    async def _execute_with_routing(self, context: RequestContext,
                                  routing_decision: str) -> ProcessingResult:
        """Execute request using the determined routing strategy"""

        if routing_decision == "multiprocess_batch":
            return await self._execute_multiprocess_batch(context)

        elif routing_decision == "multiprocess_single":
            return await self._execute_multiprocess_single(context)

        elif routing_decision == "async_io":
            return await self._execute_async_io(context)

        elif routing_decision == "async_mixed":
            return await self._execute_async_mixed(context)

        else:
            raise ValueError(f"Unknown routing decision: {routing_decision}")

    async def _execute_multiprocess_batch(self, context: RequestContext) -> ProcessingResult:
        """Execute using multiprocessing for batch CPU operations"""
        self.metrics['cpu_bound_requests'] += 1

        try:
            # Step 1: Compute user hash (CPU-bound - multiprocess)
            user_hashes = await self.hash_computer.compute_user_hashes([context.user_id])
            user_hash = user_hashes[0] if user_hashes else 0

            # Step 2: Generate JWT (CPU-bound - multiprocess)
            jwt_payload = {
                'sub': context.user_id,
                'iss': 'ztag',
                'aud': f'https://{settings.AUTH0_DOMAIN}/api/v2/',
                'exp': int(time.time()) + 3600,
                'iat': int(time.time())
            }

            jwt_token = await self.jwt_processor.sign_jwt_async(jwt_payload)

            return ProcessingResult(
                request_id=context.request_id,
                success=True,
                data={
                    'access_token': jwt_token,
                    'user_hash': user_hash,
                    'expires_in': 3600,
                    'token_type': 'Bearer'
                },
                operation_type=OperationType.CPU_BOUND
            )

        except Exception as e:
            return ProcessingResult(
                request_id=context.request_id,
                success=False,
                error=str(e),
                operation_type=OperationType.CPU_BOUND
            )

    async def _execute_multiprocess_single(self, context: RequestContext) -> ProcessingResult:
        """Execute single request using multiprocessing"""
        return await self._execute_multiprocess_batch(context)  # Same logic

    async def _execute_async_io(self, context: RequestContext) -> ProcessingResult:
        """Execute using async I/O for network operations"""
        self.metrics['io_bound_requests'] += 1

        try:
            # Simulate Auth0 API call (I/O-bound - use async)
            auth0_response = await self._fetch_user_profile_async(context.user_id)

            # Fast token generation using single-threaded approach
            token_data = {
                'access_token': f'fake_token_{context.user_id}_{int(time.time())}',
                'user_data': auth0_response,
                'expires_in': 3600,
                'token_type': 'Bearer'
            }

            return ProcessingResult(
                request_id=context.request_id,
                success=True,
                data=token_data,
                operation_type=OperationType.IO_BOUND
            )

        except Exception as e:
            return ProcessingResult(
                request_id=context.request_id,
                success=False,
                error=str(e),
                operation_type=OperationType.IO_BOUND
            )

    async def _execute_async_mixed(self, context: RequestContext) -> ProcessingResult:
        """Execute mixed workload using hybrid approach"""
        self.metrics['mixed_requests'] += 1

        try:
            # I/O operation first (Auth0 API)
            user_profile = await self._fetch_user_profile_async(context.user_id)

            # CPU operation second (hash computation)
            user_hash = await self.hash_computer.compute_single_hash(
                context.user_id.encode('utf-8')
            )

            # Combine results
            result_data = {
                'user_profile': user_profile,
                'user_hash': user_hash,
                'access_token': f'mixed_token_{context.user_id}_{user_hash}',
                'expires_in': 3600
            }

            return ProcessingResult(
                request_id=context.request_id,
                success=True,
                data=result_data,
                operation_type=OperationType.MIXED
            )

        except Exception as e:
            return ProcessingResult(
                request_id=context.request_id,
                success=False,
                error=str(e),
                operation_type=OperationType.MIXED
            )

    async def _check_cache_async(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Check cache asynchronously (I/O-bound)"""
        return await self.cache_manager.get(f"auth_{user_id}")

    async def _cache_result_async(self, user_id: str, data: Dict[str, Any]) -> bool:
        """Cache result asynchronously (I/O-bound)"""
        return await self.cache_manager.set(f"auth_{user_id}", data, ttl=3600)

    async def _fetch_user_profile_async(self, user_id: str) -> Dict[str, Any]:
        """
        Fetch user profile from Auth0 (I/O-bound - perfect for async)
        GIL is released during network wait
        """
        # Simulate Auth0 API call
        await asyncio.sleep(0.05)  # Simulate 50ms network latency

        return {
            'user_id': user_id,
            'email': f'{user_id}@example.com',
            'name': f'User {user_id}',
            'last_login': time.time(),
            'metadata': {
                'source': 'auth0_api',
                'fetched_at': time.time()
            }
        }

    async def batch_process_requests(self, contexts: List[RequestContext]) -> List[ProcessingResult]:
        """
        Process multiple requests efficiently using hybrid routing

        Args:
            contexts: List of request contexts

        Returns:
            List of processing results
        """

        if not contexts:
            return []

        # Group requests by optimal processing strategy
        grouped_requests = self._group_requests_by_strategy(contexts)

        # Process each group with optimal strategy
        all_results = []

        for strategy, request_group in grouped_requests.items():
            if strategy == "multiprocess_batch":
                results = await self._batch_multiprocess(request_group)
            elif strategy == "async_concurrent":
                results = await self._batch_async_concurrent(request_group)
            else:
                # Process individually
                results = []
                for context in request_group:
                    result = await self.process_authentication_request(context)
                    results.append(result)

            all_results.extend(results)

        # Sort results to maintain original order
        all_results.sort(key=lambda r: r.request_id)

        return all_results

    def _group_requests_by_strategy(self, contexts: List[RequestContext]) -> Dict[str, List[RequestContext]]:
        """Group requests by optimal processing strategy"""

        groups = {
            "multiprocess_batch": [],
            "async_concurrent": [],
            "individual": []
        }

        for context in contexts:
            operation_type = self.analyzer.classify_operation(
                'user_authentication',
                context.batch_size
            )

            if operation_type == OperationType.CPU_BOUND and len(contexts) >= settings.BATCH_SIZE_THRESHOLD:
                groups["multiprocess_batch"].append(context)
            elif operation_type == OperationType.IO_BOUND:
                groups["async_concurrent"].append(context)
            else:
                groups["individual"].append(context)

        return groups

    async def _batch_multiprocess(self, contexts: List[RequestContext]) -> List[ProcessingResult]:
        """Process batch using multiprocessing"""

        # Extract user IDs for batch processing
        user_ids = [ctx.user_id for ctx in contexts]

        try:
            # Batch hash computation
            user_hashes = await self.hash_computer.compute_user_hashes(user_ids)

            # Batch JWT generation
            jwt_payloads = [
                {
                    'sub': user_id,
                    'iss': 'ztag',
                    'exp': int(time.time()) + 3600,
                    'iat': int(time.time())
                }
                for user_id in user_ids
            ]

            jwt_tokens = await self.jwt_processor.batch_sign_jwts(jwt_payloads)

            # Create results
            results = []
            for i, context in enumerate(contexts):
                result_data = {
                    'access_token': jwt_tokens[i],
                    'user_hash': user_hashes[i],
                    'expires_in': 3600,
                    'token_type': 'Bearer'
                }

                results.append(ProcessingResult(
                    request_id=context.request_id,
                    success=True,
                    data=result_data,
                    operation_type=OperationType.CPU_BOUND
                ))

            return results

        except Exception as e:
            # Return error results for all requests
            return [
                ProcessingResult(
                    request_id=ctx.request_id,
                    success=False,
                    error=str(e),
                    operation_type=OperationType.CPU_BOUND
                )
                for ctx in contexts
            ]

    async def _batch_async_concurrent(self, contexts: List[RequestContext]) -> List[ProcessingResult]:
        """Process batch using async concurrency"""

        # Process all requests concurrently
        tasks = [
            self.process_authentication_request(context)
            for context in contexts
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle exceptions
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append(ProcessingResult(
                    request_id=contexts[i].request_id,
                    success=False,
                    error=str(result),
                    operation_type=OperationType.IO_BOUND
                ))
            else:
                processed_results.append(result)

        return processed_results

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive performance metrics"""

        total_requests = self.metrics['total_requests']
        if total_requests == 0:
            return self.metrics

        return {
            **self.metrics,
            'cpu_bound_ratio': self.metrics['cpu_bound_requests'] / total_requests,
            'io_bound_ratio': self.metrics['io_bound_requests'] / total_requests,
            'mixed_ratio': self.metrics['mixed_requests'] / total_requests,
            'cache_hit_ratio': self.metrics['cache_hits'] / max(
                self.metrics['cache_hits'] + self.metrics['cache_misses'], 1
            ),
            'avg_multiprocess_time': (
                self.metrics['multiprocess_time'] / max(self.metrics['cpu_bound_requests'], 1)
            ),
            'avg_async_time': (
                self.metrics['async_time'] / max(self.metrics['io_bound_requests'], 1)
            )
        }

    async def health_check(self) -> Dict[str, bool]:
        """Comprehensive health check for hybrid processor"""
        checks = {}

        try:
            # Check JWT processor
            jwt_health = await self.jwt_processor.health_check()
            checks['jwt_processor'] = all(jwt_health.values())

            # Check hash computer
            hash_health = await self.hash_computer.health_check()
            checks['hash_computer'] = all(hash_health.values())

            # Check cache manager
            cache_health = await self.cache_manager.health_check()
            checks['cache_manager'] = all(cache_health.values())

            # Check HTTP session
            checks['http_session'] = not self.http_session.closed

            # Check thread pool
            checks['thread_pool'] = not self.io_thread_pool._shutdown

            # Overall health
            checks['hybrid_processor'] = all(checks.values())

        except Exception as e:
            checks['hybrid_processor'] = False
            checks['error'] = str(e)

        return checks

    async def close(self):
        """Clean up all resources"""
        try:
            # Close multiprocessing components
            await self.jwt_processor.close()
            self.hash_computer.close()

            # Close cache manager
            await self.cache_manager.close()

            # Close HTTP session
            if self.http_session and not self.http_session.closed:
                await self.http_session.close()

            # Shutdown thread pool
            self.io_thread_pool.shutdown(wait=True)

        except Exception as e:
            print(f"Error during hybrid processor cleanup: {e}")