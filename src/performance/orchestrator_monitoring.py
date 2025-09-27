"""
Orchestrator Monitoring and Observability Module

Provides comprehensive monitoring, alerting, and analytics for the
Functional Event Loop Orchestrator, including:

1. Real-time performance dashboards
2. Alert triggers for performance degradation
3. Prometheus metrics export
4. Performance trend analysis
5. Automated recommendations

Performance Monitoring Targets:
- Latency reduction: ≥60% improvement
- Throughput improvement: ≥2.5x baseline
- Coalescing efficiency: ≥40% of requests
- Circuit breaker effectiveness: ≥90% cascade failure reduction
"""

import asyncio
import time
import logging
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import statistics
from collections import deque, defaultdict
import threading

try:
    from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

logger = logging.getLogger(__name__)

class AlertLevel(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

@dataclass
class PerformanceAlert:
    """Performance alert definition"""
    alert_id: str
    level: AlertLevel
    message: str
    metric_name: str
    current_value: float
    threshold_value: float
    timestamp: float = field(default_factory=time.time)
    resolved: bool = False

@dataclass
class PerformanceTrend:
    """Performance trend analysis"""
    metric_name: str
    current_value: float
    trend_direction: str  # "improving", "degrading", "stable"
    change_percentage: float
    time_window_seconds: int
    confidence: float  # 0.0 to 1.0

class PrometheusMetrics:
    """Prometheus metrics for orchestrator monitoring"""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled and PROMETHEUS_AVAILABLE

        if self.enabled:
            # Request metrics
            self.requests_total = Counter(
                'orchestrator_requests_total',
                'Total number of requests processed',
                ['operation_type', 'priority', 'status']
            )

            self.request_duration = Histogram(
                'orchestrator_request_duration_seconds',
                'Request processing duration',
                ['operation_type', 'coalesced']
            )

            # Coalescing metrics
            self.coalesced_requests = Counter(
                'orchestrator_coalesced_requests_total',
                'Total number of coalesced requests',
                ['operation_type']
            )

            self.cache_hits = Counter(
                'orchestrator_cache_hits_total',
                'Total number of cache hits',
                ['operation_type']
            )

            # Circuit breaker metrics
            self.circuit_breaker_trips = Counter(
                'orchestrator_circuit_breaker_trips_total',
                'Total number of circuit breaker trips',
                ['operation_type']
            )

            # Worker metrics
            self.active_workers = Gauge(
                'orchestrator_active_workers',
                'Number of active worker processes'
            )

            self.queue_depth = Gauge(
                'orchestrator_queue_depth',
                'Current queue depth'
            )

            # Performance metrics
            self.throughput_rps = Gauge(
                'orchestrator_throughput_rps',
                'Current throughput in requests per second'
            )

            self.latency_ms = Gauge(
                'orchestrator_avg_latency_ms',
                'Average request latency in milliseconds'
            )

            self.efficiency_score = Gauge(
                'orchestrator_efficiency_score',
                'Overall orchestrator efficiency score (0-1)'
            )

    def record_request(self, operation_type: str, priority: str, status: str, duration: float, coalesced: bool = False):
        """Record request metrics"""
        if not self.enabled:
            return

        self.requests_total.labels(
            operation_type=operation_type,
            priority=priority,
            status=status
        ).inc()

        self.request_duration.labels(
            operation_type=operation_type,
            coalesced=str(coalesced)
        ).observe(duration)

    def record_coalescing(self, operation_type: str, cache_hit: bool = False):
        """Record coalescing metrics"""
        if not self.enabled:
            return

        self.coalesced_requests.labels(operation_type=operation_type).inc()

        if cache_hit:
            self.cache_hits.labels(operation_type=operation_type).inc()

    def record_circuit_breaker_trip(self, operation_type: str):
        """Record circuit breaker trip"""
        if not self.enabled:
            return

        self.circuit_breaker_trips.labels(operation_type=operation_type).inc()

    def update_gauges(self, metrics: Dict[str, Any]):
        """Update gauge metrics"""
        if not self.enabled:
            return

        orchestrator_metrics = metrics.get('orchestrator_metrics', {})

        self.active_workers.set(orchestrator_metrics.get('active_workers', 0))
        self.queue_depth.set(orchestrator_metrics.get('queue_depth', 0))
        self.throughput_rps.set(orchestrator_metrics.get('throughput_rps', 0))
        self.latency_ms.set(orchestrator_metrics.get('avg_latency_ms', 0))
        self.efficiency_score.set(orchestrator_metrics.get('efficiency_score', 0))

    def get_metrics(self) -> str:
        """Get Prometheus metrics in text format"""
        if not self.enabled:
            return ""

        return generate_latest().decode('utf-8')

class OrchestratorMonitor:
    """
    Comprehensive Orchestrator Monitoring System

    Provides real-time monitoring, alerting, and analytics for the
    Functional Event Loop Orchestrator with performance targets:

    - 60% latency reduction through coalescing
    - 2.5x throughput improvement via priority scheduling
    - 90% reduction in cascade failures
    - 25% better resource utilization
    """

    def __init__(self,
                 orchestrator=None,
                 alert_thresholds: Optional[Dict[str, float]] = None,
                 enable_prometheus: bool = True,
                 trend_window_seconds: int = 300):  # 5 minutes

        self.orchestrator = orchestrator
        self.enable_prometheus = enable_prometheus
        self.trend_window_seconds = trend_window_seconds

        # Default alert thresholds
        self.alert_thresholds = alert_thresholds or {
            'avg_latency_ms': 50.0,           # Alert if latency > 50ms
            'error_rate': 0.05,               # Alert if error rate > 5%
            'queue_depth': 1000,              # Alert if queue > 1000
            'efficiency_score': 0.70,         # Alert if efficiency < 70%
            'worker_utilization': 0.90,       # Alert if utilization > 90%
            'throughput_rps': 1000            # Alert if throughput < 1000 RPS
        }

        # Monitoring state
        self.active_alerts: Dict[str, PerformanceAlert] = {}
        self.alert_history: List[PerformanceAlert] = []
        self.performance_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.last_metrics_update = time.time()

        # Prometheus metrics
        self.prometheus = PrometheusMetrics(enabled=enable_prometheus)

        # Alert callbacks
        self.alert_callbacks: List[Callable] = []

        # Background monitoring
        self.monitoring_task: Optional[asyncio.Task] = None
        self.shutdown_event = asyncio.Event()

        logger.info("OrchestratorMonitor initialized with performance alerting")

    def add_alert_callback(self, callback: Callable[[PerformanceAlert], None]):
        """Add callback for alert notifications"""
        self.alert_callbacks.append(callback)

    async def start_monitoring(self, interval_seconds: float = 10.0):
        """Start background monitoring loop"""
        if self.monitoring_task:
            return

        self.monitoring_task = asyncio.create_task(
            self._monitoring_loop(interval_seconds)
        )

        logger.info(f"Started orchestrator monitoring with {interval_seconds}s interval")

    async def stop_monitoring(self):
        """Stop background monitoring"""
        self.shutdown_event.set()

        if self.monitoring_task:
            try:
                await asyncio.wait_for(self.monitoring_task, timeout=5.0)
            except asyncio.TimeoutError:
                self.monitoring_task.cancel()

        logger.info("Stopped orchestrator monitoring")

    async def _monitoring_loop(self, interval_seconds: float):
        """Background monitoring loop"""
        while not self.shutdown_event.is_set():
            try:
                await self._collect_and_analyze_metrics()
                await asyncio.sleep(interval_seconds)

            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                await asyncio.sleep(interval_seconds)

    async def _collect_and_analyze_metrics(self):
        """Collect metrics and perform analysis"""
        if not self.orchestrator:
            return

        # Get current metrics
        try:
            metrics = self.orchestrator.get_performance_metrics()
            orchestrator_metrics = metrics.get('orchestrator_metrics', {})

            # Update Prometheus metrics
            self.prometheus.update_gauges(metrics)

            # Store historical data
            current_time = time.time()
            for metric_name, value in orchestrator_metrics.items():
                if isinstance(value, (int, float)):
                    self.performance_history[metric_name].append({
                        'timestamp': current_time,
                        'value': value
                    })

            # Check alert conditions
            await self._check_alert_conditions(orchestrator_metrics)

            # Analyze performance trends
            await self._analyze_performance_trends()

            self.last_metrics_update = current_time

        except Exception as e:
            logger.error(f"Metrics collection failed: {e}")

    async def _check_alert_conditions(self, metrics: Dict[str, Any]):
        """Check for alert conditions"""
        current_time = time.time()

        # Check each threshold
        for metric_name, threshold in self.alert_thresholds.items():
            current_value = metrics.get(metric_name, 0)
            alert_id = f"orchestrator_{metric_name}"

            # Determine if alert should trigger
            should_alert = False
            alert_level = AlertLevel.WARNING

            if metric_name == 'avg_latency_ms' and current_value > threshold:
                should_alert = True
                alert_level = AlertLevel.CRITICAL if current_value > threshold * 2 else AlertLevel.WARNING

            elif metric_name == 'error_rate' and current_value > threshold:
                should_alert = True
                alert_level = AlertLevel.CRITICAL if current_value > threshold * 2 else AlertLevel.WARNING

            elif metric_name == 'queue_depth' and current_value > threshold:
                should_alert = True
                alert_level = AlertLevel.WARNING

            elif metric_name == 'efficiency_score' and current_value < threshold:
                should_alert = True
                alert_level = AlertLevel.WARNING

            elif metric_name == 'worker_utilization' and current_value > threshold:
                should_alert = True
                alert_level = AlertLevel.WARNING

            elif metric_name == 'throughput_rps' and current_value < threshold:
                should_alert = True
                alert_level = AlertLevel.WARNING

            # Handle alert state
            if should_alert and alert_id not in self.active_alerts:
                # New alert
                alert = PerformanceAlert(
                    alert_id=alert_id,
                    level=alert_level,
                    message=f"Orchestrator {metric_name} exceeded threshold: {current_value:.2f} vs {threshold:.2f}",
                    metric_name=metric_name,
                    current_value=current_value,
                    threshold_value=threshold,
                    timestamp=current_time
                )

                self.active_alerts[alert_id] = alert
                self.alert_history.append(alert)

                # Notify callbacks
                for callback in self.alert_callbacks:
                    try:
                        callback(alert)
                    except Exception as e:
                        logger.error(f"Alert callback failed: {e}")

                logger.warning(f"ALERT: {alert.message}")

            elif not should_alert and alert_id in self.active_alerts:
                # Resolve alert
                alert = self.active_alerts[alert_id]
                alert.resolved = True
                del self.active_alerts[alert_id]

                logger.info(f"RESOLVED: Alert {alert_id} - {metric_name} back to normal: {current_value:.2f}")

    async def _analyze_performance_trends(self):
        """Analyze performance trends over time"""
        current_time = time.time()
        trends = {}

        for metric_name, history in self.performance_history.items():
            if len(history) < 10:  # Need at least 10 data points
                continue

            # Get recent data within trend window
            recent_data = [
                point for point in history
                if current_time - point['timestamp'] <= self.trend_window_seconds
            ]

            if len(recent_data) < 5:
                continue

            # Calculate trend
            values = [point['value'] for point in recent_data]
            timestamps = [point['timestamp'] for point in recent_data]

            # Simple linear trend analysis
            if len(values) >= 2:
                recent_avg = statistics.mean(values[-5:])  # Last 5 values
                older_avg = statistics.mean(values[:5])    # First 5 values

                if older_avg != 0:
                    change_percentage = ((recent_avg - older_avg) / older_avg) * 100
                else:
                    change_percentage = 0

                # Determine trend direction
                if abs(change_percentage) < 2.0:  # Less than 2% change
                    trend_direction = "stable"
                elif change_percentage > 0:
                    trend_direction = "improving" if metric_name in ['throughput_rps', 'efficiency_score'] else "degrading"
                else:
                    trend_direction = "degrading" if metric_name in ['throughput_rps', 'efficiency_score'] else "improving"

                # Calculate confidence based on consistency
                variance = statistics.variance(values) if len(values) > 1 else 0
                confidence = max(0.0, min(1.0, 1.0 - (variance / max(recent_avg, 1.0))))

                trends[metric_name] = PerformanceTrend(
                    metric_name=metric_name,
                    current_value=recent_avg,
                    trend_direction=trend_direction,
                    change_percentage=change_percentage,
                    time_window_seconds=self.trend_window_seconds,
                    confidence=confidence
                )

        return trends

    async def get_monitoring_report(self) -> Dict[str, Any]:
        """Get comprehensive monitoring report"""
        if not self.orchestrator:
            return {'error': 'No orchestrator attached'}

        # Get current metrics
        try:
            metrics = self.orchestrator.get_performance_metrics()
        except Exception as e:
            return {'error': f'Failed to get metrics: {e}'}

        # Analyze trends
        trends = await self._analyze_performance_trends()

        # Calculate performance scores
        orchestrator_metrics = metrics.get('orchestrator_metrics', {})
        performance_scores = self._calculate_performance_scores(orchestrator_metrics)

        return {
            'monitoring_status': {
                'last_update': self.last_metrics_update,
                'active_alerts': len(self.active_alerts),
                'total_alerts_today': len([
                    a for a in self.alert_history
                    if time.time() - a.timestamp < 86400  # Last 24 hours
                ]),
                'monitoring_uptime': time.time() - getattr(self, 'start_time', time.time())
            },
            'current_metrics': metrics,
            'performance_scores': performance_scores,
            'active_alerts': [
                {
                    'alert_id': alert.alert_id,
                    'level': alert.level.value,
                    'message': alert.message,
                    'current_value': alert.current_value,
                    'threshold': alert.threshold_value,
                    'duration_seconds': time.time() - alert.timestamp
                }
                for alert in self.active_alerts.values()
            ],
            'performance_trends': {
                name: {
                    'direction': trend.trend_direction,
                    'change_percentage': trend.change_percentage,
                    'confidence': trend.confidence
                }
                for name, trend in trends.items()
            },
            'recommendations': self._generate_recommendations(orchestrator_metrics, trends)
        }

    def _calculate_performance_scores(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate performance scores against targets"""
        # Target values for scoring
        targets = {
            'latency_reduction': 0.60,      # 60% reduction target
            'throughput_multiplier': 2.5,   # 2.5x improvement target
            'coalescing_rate': 0.40,        # 40% coalescing target
            'efficiency_score': 0.85        # 85% efficiency target
        }

        # Calculate actual scores
        current_latency = metrics.get('avg_latency_ms', 10.0)
        latency_score = max(0, min(1.0, (10.0 - current_latency) / 10.0))  # Baseline 10ms

        throughput_score = min(1.0, metrics.get('throughput_rps', 0) / 25000)  # Target 25k RPS

        coalescing_score = metrics.get('coalescing_rate', 0)

        efficiency_score = metrics.get('efficiency_score', 0)

        overall_score = (latency_score + throughput_score + coalescing_score + efficiency_score) / 4

        return {
            'latency_score': latency_score,
            'throughput_score': throughput_score,
            'coalescing_score': coalescing_score,
            'efficiency_score': efficiency_score,
            'overall_score': overall_score,
            'targets_met': {
                'latency_reduction': latency_score >= targets['latency_reduction'],
                'throughput_improvement': throughput_score >= targets['throughput_multiplier'] / 2.5,
                'coalescing_efficiency': coalescing_score >= targets['coalescing_rate'],
                'overall_efficiency': efficiency_score >= targets['efficiency_score']
            }
        }

    def _generate_recommendations(self,
                                metrics: Dict[str, Any],
                                trends: Dict[str, PerformanceTrend]) -> List[str]:
        """Generate performance optimization recommendations"""
        recommendations = []

        # Latency recommendations
        avg_latency = metrics.get('avg_latency_ms', 0)
        if avg_latency > 20:
            recommendations.append("High latency detected. Consider increasing coalescing window or worker count.")

        # Throughput recommendations
        throughput = metrics.get('throughput_rps', 0)
        if throughput < 5000:
            recommendations.append("Low throughput. Consider optimizing priority scheduling or increasing parallelism.")

        # Queue depth recommendations
        queue_depth = metrics.get('queue_depth', 0)
        if queue_depth > 500:
            recommendations.append("High queue depth. Consider scaling worker count or optimizing request processing.")

        # Coalescing recommendations
        coalescing_rate = metrics.get('coalescing_rate', 0)
        if coalescing_rate < 0.20:
            recommendations.append("Low coalescing rate. Consider increasing coalescing window or reviewing request patterns.")

        # Worker utilization recommendations
        active_workers = metrics.get('active_workers', 0)
        max_workers = metrics.get('max_workers', 1)
        utilization = active_workers / max(max_workers, 1)

        if utilization > 0.90:
            recommendations.append("High worker utilization. Consider increasing worker pool size.")
        elif utilization < 0.30:
            recommendations.append("Low worker utilization. Consider reducing worker pool size for efficiency.")

        # Trend-based recommendations
        for metric_name, trend in trends.items():
            if trend.trend_direction == "degrading" and trend.confidence > 0.7:
                if metric_name == 'throughput_rps':
                    recommendations.append(f"Throughput trending down ({trend.change_percentage:.1f}%). Monitor system resources.")
                elif metric_name == 'avg_latency_ms':
                    recommendations.append(f"Latency trending up ({trend.change_percentage:.1f}%). Consider optimization.")

        # Default recommendation if none specific
        if not recommendations:
            recommendations.append("Orchestrator performing within normal parameters. Continue monitoring.")

        return recommendations

    def get_prometheus_metrics(self) -> str:
        """Get Prometheus metrics for external monitoring"""
        return self.prometheus.get_metrics()

# Convenience function for global monitor instance
_global_monitor: Optional[OrchestratorMonitor] = None

def get_monitor(orchestrator=None) -> OrchestratorMonitor:
    """Get or create global monitor instance"""
    global _global_monitor

    if _global_monitor is None:
        _global_monitor = OrchestratorMonitor(orchestrator=orchestrator)

    return _global_monitor

async def setup_monitoring(orchestrator, interval_seconds: float = 10.0) -> OrchestratorMonitor:
    """Setup orchestrator monitoring with default configuration"""
    monitor = get_monitor(orchestrator)
    monitor.orchestrator = orchestrator  # Update reference

    await monitor.start_monitoring(interval_seconds)

    logger.info("Orchestrator monitoring setup completed")
    return monitor