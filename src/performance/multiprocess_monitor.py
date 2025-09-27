"""
Multiprocessing Performance Monitor and Observability System
Provides comprehensive monitoring for process pools and multiprocessing components
"""

import asyncio
import time
import psutil
import threading
import multiprocessing as mp
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import json
from concurrent.futures import ThreadPoolExecutor
import numpy as np

from config.settings import settings


@dataclass
class ProcessMetrics:
    """Metrics for individual processes"""
    pid: int
    name: str
    cpu_percent: float
    memory_mb: float
    memory_percent: float
    create_time: float
    status: str
    num_threads: int
    num_fds: int = 0  # File descriptors (Unix only)


@dataclass
class PoolMetrics:
    """Metrics for process/thread pools"""
    pool_name: str
    pool_type: str  # 'process' or 'thread'
    active_workers: int
    max_workers: int
    pending_tasks: int
    completed_tasks: int
    failed_tasks: int
    avg_task_time: float
    utilization: float
    created_at: float


@dataclass
class SystemMetrics:
    """Overall system metrics"""
    timestamp: float
    cpu_percent: float
    memory_percent: float
    disk_io_read_mb: float
    disk_io_write_mb: float
    network_sent_mb: float
    network_recv_mb: float
    load_average: Tuple[float, float, float]
    active_processes: int


class ProcessPoolMonitor:
    """
    Monitor for individual process pools
    Tracks performance, utilization, and health metrics
    """

    def __init__(self, pool_name: str, pool_type: str = 'process'):
        self.pool_name = pool_name
        self.pool_type = pool_type

        # Metrics tracking
        self.completed_tasks = 0
        self.failed_tasks = 0
        self.task_times = []
        self.start_time = time.time()

        # Worker tracking
        self.worker_pids = set()
        self.max_workers = 0

        # Health status
        self.is_healthy = True
        self.last_health_check = time.time()

    def register_worker(self, pid: int):
        """Register a worker process"""
        self.worker_pids.add(pid)

    def unregister_worker(self, pid: int):
        """Unregister a worker process"""
        self.worker_pids.discard(pid)

    def record_task_completion(self, task_time: float, success: bool = True):
        """Record task completion metrics"""
        if success:
            self.completed_tasks += 1
        else:
            self.failed_tasks += 1

        self.task_times.append(task_time)

        # Keep only recent task times (last 1000)
        if len(self.task_times) > 1000:
            self.task_times = self.task_times[-1000:]

    def get_metrics(self) -> PoolMetrics:
        """Get current pool metrics"""
        active_workers = len([
            pid for pid in self.worker_pids
            if self._is_process_alive(pid)
        ])

        avg_task_time = (
            sum(self.task_times) / len(self.task_times)
            if self.task_times else 0.0
        )

        utilization = (
            active_workers / max(self.max_workers, 1)
            if self.max_workers > 0 else 0.0
        )

        return PoolMetrics(
            pool_name=self.pool_name,
            pool_type=self.pool_type,
            active_workers=active_workers,
            max_workers=self.max_workers,
            pending_tasks=0,  # Would need integration with actual pools
            completed_tasks=self.completed_tasks,
            failed_tasks=self.failed_tasks,
            avg_task_time=avg_task_time,
            utilization=utilization,
            created_at=self.start_time
        )

    def _is_process_alive(self, pid: int) -> bool:
        """Check if process is still alive"""
        try:
            process = psutil.Process(pid)
            return process.is_running()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    def health_check(self) -> Dict[str, Any]:
        """Perform health check on the pool"""
        current_time = time.time()

        # Check worker health
        alive_workers = 0
        dead_workers = 0

        for pid in self.worker_pids.copy():
            if self._is_process_alive(pid):
                alive_workers += 1
            else:
                dead_workers += 1
                self.worker_pids.discard(pid)

        # Calculate health metrics
        worker_health_ratio = (
            alive_workers / max(len(self.worker_pids), 1)
            if self.worker_pids else 1.0
        )

        task_success_ratio = (
            self.completed_tasks /
            max(self.completed_tasks + self.failed_tasks, 1)
        )

        # Determine overall health
        self.is_healthy = (
            worker_health_ratio > 0.8 and
            task_success_ratio > 0.95 and
            current_time - self.last_health_check < 300  # 5 minutes
        )

        self.last_health_check = current_time

        return {
            'pool_name': self.pool_name,
            'is_healthy': self.is_healthy,
            'alive_workers': alive_workers,
            'dead_workers': dead_workers,
            'worker_health_ratio': worker_health_ratio,
            'task_success_ratio': task_success_ratio,
            'uptime_seconds': current_time - self.start_time
        }


class MultiProcessingObserver:
    """
    Comprehensive multiprocessing observability system
    Monitors all process pools, system resources, and performance metrics
    """

    def __init__(self, monitoring_interval: float = 1.0):
        self.monitoring_interval = monitoring_interval

        # Pool monitors
        self.pool_monitors: Dict[str, ProcessPoolMonitor] = {}

        # System metrics history
        self.system_metrics_history: List[SystemMetrics] = []
        self.max_history_size = 3600  # 1 hour at 1-second intervals

        # Monitoring control
        self.is_monitoring = False
        self.monitor_task = None

        # Baseline system metrics
        self.baseline_metrics = self._capture_baseline_metrics()

        # Alert thresholds
        self.alert_thresholds = {
            'cpu_percent': 90.0,
            'memory_percent': 85.0,
            'disk_io_mb_per_sec': 100.0,
            'failed_task_ratio': 0.1,
            'worker_death_ratio': 0.2
        }

        # Performance analytics
        self.performance_analytics = PerformanceAnalytics()

    def register_pool(self, pool_name: str, pool_type: str = 'process'):
        """Register a new pool for monitoring"""
        if pool_name not in self.pool_monitors:
            self.pool_monitors[pool_name] = ProcessPoolMonitor(pool_name, pool_type)

    def _capture_baseline_metrics(self) -> SystemMetrics:
        """Capture baseline system metrics for comparison"""
        return self._get_system_metrics()

    def _get_system_metrics(self) -> SystemMetrics:
        """Capture current system metrics"""
        # CPU and memory
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()

        # Disk I/O
        disk_io = psutil.disk_io_counters()
        disk_read_mb = disk_io.read_bytes / (1024 * 1024) if disk_io else 0
        disk_write_mb = disk_io.write_bytes / (1024 * 1024) if disk_io else 0

        # Network I/O
        net_io = psutil.net_io_counters()
        net_sent_mb = net_io.bytes_sent / (1024 * 1024) if net_io else 0
        net_recv_mb = net_io.bytes_recv / (1024 * 1024) if net_io else 0

        # Load average (Unix only)
        try:
            load_avg = psutil.getloadavg()
        except AttributeError:
            load_avg = (0.0, 0.0, 0.0)  # Windows doesn't have load average

        return SystemMetrics(
            timestamp=time.time(),
            cpu_percent=cpu_percent,
            memory_percent=memory.percent,
            disk_io_read_mb=disk_read_mb,
            disk_io_write_mb=disk_write_mb,
            network_sent_mb=net_sent_mb,
            network_recv_mb=net_recv_mb,
            load_average=load_avg,
            active_processes=len(psutil.pids())
        )

    def get_process_metrics(self, pids: List[int]) -> List[ProcessMetrics]:
        """Get detailed metrics for specific processes"""
        metrics = []

        for pid in pids:
            try:
                process = psutil.Process(pid)

                # Get file descriptor count (Unix only)
                try:
                    num_fds = process.num_fds()
                except (AttributeError, psutil.AccessDenied):
                    num_fds = 0

                metrics.append(ProcessMetrics(
                    pid=pid,
                    name=process.name(),
                    cpu_percent=process.cpu_percent(),
                    memory_mb=process.memory_info().rss / (1024 * 1024),
                    memory_percent=process.memory_percent(),
                    create_time=process.create_time(),
                    status=process.status(),
                    num_threads=process.num_threads(),
                    num_fds=num_fds
                ))

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return metrics

    async def start_monitoring(self):
        """Start the monitoring loop"""
        if self.is_monitoring:
            return

        self.is_monitoring = True
        self.monitor_task = asyncio.create_task(self._monitoring_loop())

    async def stop_monitoring(self):
        """Stop the monitoring loop"""
        self.is_monitoring = False

        if self.monitor_task:
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                pass

    async def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                # Capture system metrics
                system_metrics = self._get_system_metrics()
                self.system_metrics_history.append(system_metrics)

                # Trim history to max size
                if len(self.system_metrics_history) > self.max_history_size:
                    self.system_metrics_history = self.system_metrics_history[-self.max_history_size:]

                # Check for alerts
                await self._check_alerts(system_metrics)

                # Update performance analytics
                self.performance_analytics.update(system_metrics)

                await asyncio.sleep(self.monitoring_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Monitoring loop error: {e}")
                await asyncio.sleep(self.monitoring_interval)

    async def _check_alerts(self, metrics: SystemMetrics):
        """Check for alert conditions"""
        alerts = []

        # CPU alert
        if metrics.cpu_percent > self.alert_thresholds['cpu_percent']:
            alerts.append({
                'type': 'high_cpu',
                'severity': 'critical',
                'message': f'CPU usage {metrics.cpu_percent:.1f}% exceeds threshold {self.alert_thresholds["cpu_percent"]:.1f}%',
                'timestamp': metrics.timestamp
            })

        # Memory alert
        if metrics.memory_percent > self.alert_thresholds['memory_percent']:
            alerts.append({
                'type': 'high_memory',
                'severity': 'critical',
                'message': f'Memory usage {metrics.memory_percent:.1f}% exceeds threshold {self.alert_thresholds["memory_percent"]:.1f}%',
                'timestamp': metrics.timestamp
            })

        # Process alerts for each pool
        for pool_name, monitor in self.pool_monitors.items():
            health = monitor.health_check()

            if not health['is_healthy']:
                alerts.append({
                    'type': 'unhealthy_pool',
                    'severity': 'warning',
                    'message': f'Pool {pool_name} is unhealthy: {health}',
                    'timestamp': metrics.timestamp
                })

        # Log alerts
        for alert in alerts:
            print(f"🚨 ALERT [{alert['severity'].upper()}]: {alert['message']}")

    def get_comprehensive_metrics(self) -> Dict[str, Any]:
        """Get all monitoring metrics"""
        current_system_metrics = self._get_system_metrics()

        # Pool metrics
        pool_metrics = {}
        for pool_name, monitor in self.pool_monitors.items():
            pool_metrics[pool_name] = asdict(monitor.get_metrics())

        # System metrics summary
        if len(self.system_metrics_history) > 0:
            recent_metrics = self.system_metrics_history[-10:]  # Last 10 readings

            avg_cpu = sum(m.cpu_percent for m in recent_metrics) / len(recent_metrics)
            avg_memory = sum(m.memory_percent for m in recent_metrics) / len(recent_metrics)
        else:
            avg_cpu = current_system_metrics.cpu_percent
            avg_memory = current_system_metrics.memory_percent

        # Performance analytics
        analytics = self.performance_analytics.get_analytics()

        return {
            'current_system_metrics': asdict(current_system_metrics),
            'pool_metrics': pool_metrics,
            'system_summary': {
                'avg_cpu_percent': avg_cpu,
                'avg_memory_percent': avg_memory,
                'total_pools': len(self.pool_monitors),
                'monitoring_uptime': time.time() - (self.baseline_metrics.timestamp if self.baseline_metrics else time.time()),
                'metrics_collected': len(self.system_metrics_history)
            },
            'performance_analytics': analytics,
            'alert_thresholds': self.alert_thresholds
        }

    def export_prometheus_metrics(self) -> str:
        """Export metrics in Prometheus format"""
        metrics = self.get_comprehensive_metrics()
        current_metrics = metrics['current_system_metrics']

        prometheus_output = []

        # System metrics
        prometheus_output.extend([
            f"# HELP system_cpu_percent CPU usage percentage",
            f"# TYPE system_cpu_percent gauge",
            f"system_cpu_percent {current_metrics['cpu_percent']:.2f}",
            "",
            f"# HELP system_memory_percent Memory usage percentage",
            f"# TYPE system_memory_percent gauge",
            f"system_memory_percent {current_metrics['memory_percent']:.2f}",
            "",
            f"# HELP system_active_processes Number of active processes",
            f"# TYPE system_active_processes gauge",
            f"system_active_processes {current_metrics['active_processes']}",
            ""
        ])

        # Pool metrics
        for pool_name, pool_data in metrics['pool_metrics'].items():
            prometheus_output.extend([
                f"# HELP pool_active_workers Active workers in pool {pool_name}",
                f"# TYPE pool_active_workers gauge",
                f"pool_active_workers{{pool=\"{pool_name}\"}} {pool_data['active_workers']}",
                "",
                f"# HELP pool_utilization Pool utilization ratio",
                f"# TYPE pool_utilization gauge",
                f"pool_utilization{{pool=\"{pool_name}\"}} {pool_data['utilization']:.2f}",
                "",
                f"# HELP pool_completed_tasks_total Completed tasks",
                f"# TYPE pool_completed_tasks_total counter",
                f"pool_completed_tasks_total{{pool=\"{pool_name}\"}} {pool_data['completed_tasks']}",
                "",
                f"# HELP pool_failed_tasks_total Failed tasks",
                f"# TYPE pool_failed_tasks_total counter",
                f"pool_failed_tasks_total{{pool=\"{pool_name}\"}} {pool_data['failed_tasks']}",
                ""
            ])

        return "\n".join(prometheus_output)

    def get_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report"""
        metrics = self.get_comprehensive_metrics()

        # Calculate performance improvements
        baseline = asdict(self.baseline_metrics)
        current = metrics['current_system_metrics']

        cpu_change = current['cpu_percent'] - baseline['cpu_percent']
        memory_change = current['memory_percent'] - baseline['memory_percent']

        # Pool performance summary
        total_tasks = sum(
            pool['completed_tasks'] + pool['failed_tasks']
            for pool in metrics['pool_metrics'].values()
        )

        total_success_rate = (
            sum(pool['completed_tasks'] for pool in metrics['pool_metrics'].values()) /
            max(total_tasks, 1)
        )

        return {
            'report_timestamp': time.time(),
            'monitoring_duration_hours': (
                time.time() - baseline['timestamp']
            ) / 3600,
            'system_performance': {
                'cpu_change_percent': cpu_change,
                'memory_change_percent': memory_change,
                'current_load_average': current['load_average']
            },
            'multiprocessing_performance': {
                'total_pools': len(self.pool_monitors),
                'total_tasks_processed': total_tasks,
                'overall_success_rate': total_success_rate,
                'average_pool_utilization': (
                    sum(pool['utilization'] for pool in metrics['pool_metrics'].values()) /
                    max(len(metrics['pool_metrics']), 1)
                )
            },
            'recommendations': self._generate_recommendations(metrics),
            'full_metrics': metrics
        }

    def _generate_recommendations(self, metrics: Dict[str, Any]) -> List[str]:
        """Generate performance recommendations"""
        recommendations = []
        current = metrics['current_system_metrics']

        # CPU recommendations
        if current['cpu_percent'] > 80:
            recommendations.append(
                "High CPU usage detected. Consider increasing process pool sizes or optimizing CPU-bound operations."
            )
        elif current['cpu_percent'] < 30:
            recommendations.append(
                "Low CPU usage. Consider reducing process pool sizes to save resources."
            )

        # Memory recommendations
        if current['memory_percent'] > 80:
            recommendations.append(
                "High memory usage. Monitor for memory leaks and consider optimizing data structures."
            )

        # Pool-specific recommendations
        for pool_name, pool_data in metrics['pool_metrics'].items():
            if pool_data['utilization'] > 0.9:
                recommendations.append(
                    f"Pool '{pool_name}' is highly utilized. Consider increasing worker count."
                )
            elif pool_data['utilization'] < 0.3:
                recommendations.append(
                    f"Pool '{pool_name}' is underutilized. Consider reducing worker count."
                )

            failure_rate = pool_data['failed_tasks'] / max(
                pool_data['completed_tasks'] + pool_data['failed_tasks'], 1
            )
            if failure_rate > 0.05:
                recommendations.append(
                    f"Pool '{pool_name}' has high failure rate ({failure_rate:.1%}). Investigate error causes."
                )

        return recommendations


class PerformanceAnalytics:
    """
    Advanced performance analytics for multiprocessing systems
    """

    def __init__(self):
        self.metrics_buffer = []
        self.analysis_window = 300  # 5 minutes

    def update(self, metrics: SystemMetrics):
        """Update analytics with new metrics"""
        self.metrics_buffer.append(metrics)

        # Keep only recent metrics
        cutoff_time = time.time() - self.analysis_window
        self.metrics_buffer = [
            m for m in self.metrics_buffer
            if m.timestamp > cutoff_time
        ]

    def get_analytics(self) -> Dict[str, Any]:
        """Get performance analytics"""
        if not self.metrics_buffer:
            return {}

        # Convert to numpy arrays for analysis
        cpu_data = np.array([m.cpu_percent for m in self.metrics_buffer])
        memory_data = np.array([m.memory_percent for m in self.metrics_buffer])

        return {
            'cpu_statistics': {
                'mean': float(np.mean(cpu_data)),
                'std': float(np.std(cpu_data)),
                'min': float(np.min(cpu_data)),
                'max': float(np.max(cpu_data)),
                'percentile_95': float(np.percentile(cpu_data, 95))
            },
            'memory_statistics': {
                'mean': float(np.mean(memory_data)),
                'std': float(np.std(memory_data)),
                'min': float(np.min(memory_data)),
                'max': float(np.max(memory_data)),
                'percentile_95': float(np.percentile(memory_data, 95))
            },
            'trend_analysis': self._analyze_trends(cpu_data, memory_data),
            'stability_score': self._calculate_stability_score(cpu_data, memory_data)
        }

    def _analyze_trends(self, cpu_data: np.ndarray, memory_data: np.ndarray) -> Dict[str, str]:
        """Analyze performance trends"""
        if len(cpu_data) < 10:
            return {'cpu': 'insufficient_data', 'memory': 'insufficient_data'}

        # Simple linear trend analysis
        x = np.arange(len(cpu_data))

        cpu_slope = np.polyfit(x, cpu_data, 1)[0]
        memory_slope = np.polyfit(x, memory_data, 1)[0]

        def classify_trend(slope):
            if slope > 0.1:
                return 'increasing'
            elif slope < -0.1:
                return 'decreasing'
            else:
                return 'stable'

        return {
            'cpu': classify_trend(cpu_slope),
            'memory': classify_trend(memory_slope)
        }

    def _calculate_stability_score(self, cpu_data: np.ndarray, memory_data: np.ndarray) -> float:
        """Calculate system stability score (0-1, higher is better)"""
        if len(cpu_data) < 5:
            return 0.5

        # Calculate coefficient of variation (std/mean) for both metrics
        cpu_cv = np.std(cpu_data) / max(np.mean(cpu_data), 1)
        memory_cv = np.std(memory_data) / max(np.mean(memory_data), 1)

        # Lower coefficient of variation = higher stability
        # Score from 0 to 1, where 1 is perfectly stable
        cpu_stability = max(0, 1 - cpu_cv / 0.5)  # Normalize to 0-1
        memory_stability = max(0, 1 - memory_cv / 0.5)

        return (cpu_stability + memory_stability) / 2