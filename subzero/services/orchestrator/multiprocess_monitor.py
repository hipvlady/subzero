"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

Multi-Processing Performance Observer
Monitors CPU, memory, and performance metrics across processes
"""

import asyncio
import time
from dataclasses import dataclass
from typing import Any

import psutil


@dataclass
class ProcessMetrics:
    """Metrics for a single process"""

    pid: int
    cpu_percent: float
    memory_mb: float
    num_threads: int
    status: str


@dataclass
class SystemMetrics:
    """System-wide metrics"""

    total_cpu_percent: float
    memory_percent: float
    available_memory_mb: float
    num_processes: int
    num_cores: int


class MultiProcessingObserver:
    """
    Observer for multi-processing performance metrics

    Features:
    - Real-time CPU and memory monitoring
    - Per-process metrics tracking
    - System-wide resource utilization
    - Performance degradation detection
    """

    def __init__(self, monitoring_interval: float = 1.0):
        """
        Initialize observer

        Args:
            monitoring_interval: Interval between metric collections (seconds)
        """
        self.monitoring_interval = monitoring_interval
        self.monitoring_task: asyncio.Task | None = None
        self.is_monitoring = False

        # Metrics storage
        self.metrics_history: list[dict[str, Any]] = []
        self.max_history = 1000  # Keep last 1000 samples

        # Current metrics
        self.current_system_metrics: SystemMetrics | None = None
        self.current_process_metrics: dict[int, ProcessMetrics] = {}

    async def start_monitoring(self):
        """Start background monitoring"""
        if not self.is_monitoring:
            self.is_monitoring = True
            self.monitoring_task = asyncio.create_task(self._monitoring_loop())

    async def stop_monitoring(self):
        """Stop background monitoring"""
        self.is_monitoring = False
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
            self.monitoring_task = None

    async def _monitoring_loop(self):
        """Background monitoring loop"""
        while self.is_monitoring:
            try:
                # Collect metrics
                await self._collect_metrics()

                # Wait for next interval
                await asyncio.sleep(self.monitoring_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Error in monitoring loop: {e}")

    async def _collect_metrics(self):
        """Collect current metrics"""
        # System metrics
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        num_cores = psutil.cpu_count()

        self.current_system_metrics = SystemMetrics(
            total_cpu_percent=cpu_percent,
            memory_percent=memory.percent,
            available_memory_mb=memory.available / (1024 * 1024),
            num_processes=len(psutil.pids()),
            num_cores=num_cores,
        )

        # Process metrics
        current_process = psutil.Process()
        children = current_process.children(recursive=True)

        self.current_process_metrics = {}

        # Main process
        self.current_process_metrics[current_process.pid] = ProcessMetrics(
            pid=current_process.pid,
            cpu_percent=current_process.cpu_percent(interval=0.1),
            memory_mb=current_process.memory_info().rss / (1024 * 1024),
            num_threads=current_process.num_threads(),
            status=current_process.status(),
        )

        # Child processes
        for child in children:
            try:
                self.current_process_metrics[child.pid] = ProcessMetrics(
                    pid=child.pid,
                    cpu_percent=child.cpu_percent(interval=0.1),
                    memory_mb=child.memory_info().rss / (1024 * 1024),
                    num_threads=child.num_threads(),
                    status=child.status(),
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # Store in history
        snapshot = {
            "timestamp": time.time(),
            "system": {
                "cpu_percent": self.current_system_metrics.total_cpu_percent,
                "memory_percent": self.current_system_metrics.memory_percent,
                "available_memory_mb": self.current_system_metrics.available_memory_mb,
            },
            "processes": {
                pid: {
                    "cpu_percent": metrics.cpu_percent,
                    "memory_mb": metrics.memory_mb,
                    "num_threads": metrics.num_threads,
                }
                for pid, metrics in self.current_process_metrics.items()
            },
        }

        self.metrics_history.append(snapshot)

        # Trim history
        if len(self.metrics_history) > self.max_history:
            self.metrics_history = self.metrics_history[-self.max_history :]

    def get_current_metrics(self) -> dict[str, Any]:
        """Get current metrics snapshot"""
        if not self.current_system_metrics:
            return {}

        return {
            "system": {
                "cpu_percent": self.current_system_metrics.total_cpu_percent,
                "memory_percent": self.current_system_metrics.memory_percent,
                "available_memory_mb": self.current_system_metrics.available_memory_mb,
                "num_processes": self.current_system_metrics.num_processes,
                "num_cores": self.current_system_metrics.num_cores,
            },
            "processes": {
                pid: {
                    "cpu_percent": metrics.cpu_percent,
                    "memory_mb": metrics.memory_mb,
                    "num_threads": metrics.num_threads,
                    "status": metrics.status,
                }
                for pid, metrics in self.current_process_metrics.items()
            },
        }

    def get_comprehensive_metrics(self) -> dict[str, Any]:
        """Get comprehensive metrics with aggregations"""
        if not self.metrics_history:
            return {}

        # Calculate aggregations
        cpu_samples = [m["system"]["cpu_percent"] for m in self.metrics_history]
        memory_samples = [m["system"]["memory_percent"] for m in self.metrics_history]

        # Process-level aggregations
        process_cpu_totals = []
        process_memory_totals = []

        for snapshot in self.metrics_history:
            process_cpu = sum(p["cpu_percent"] for p in snapshot["processes"].values())
            process_memory = sum(p["memory_mb"] for p in snapshot["processes"].values())
            process_cpu_totals.append(process_cpu)
            process_memory_totals.append(process_memory)

        return {
            "system": {
                "cpu_avg": sum(cpu_samples) / len(cpu_samples),
                "cpu_max": max(cpu_samples),
                "cpu_min": min(cpu_samples),
                "memory_avg": sum(memory_samples) / len(memory_samples),
                "memory_max": max(memory_samples),
            },
            "processes": {
                "cpu_total_avg": sum(process_cpu_totals) / len(process_cpu_totals),
                "cpu_total_max": max(process_cpu_totals),
                "memory_total_avg_mb": sum(process_memory_totals) / len(process_memory_totals),
                "memory_total_max_mb": max(process_memory_totals),
                "num_processes": len(self.current_process_metrics),
            },
            "samples": len(self.metrics_history),
            "monitoring_interval": self.monitoring_interval,
        }

    def detect_resource_pressure(self) -> dict[str, Any]:
        """Detect if system is under resource pressure"""
        if not self.current_system_metrics:
            return {"pressure": False}

        cpu_pressure = self.current_system_metrics.total_cpu_percent > 80
        memory_pressure = self.current_system_metrics.memory_percent > 85

        return {
            "pressure": cpu_pressure or memory_pressure,
            "cpu_pressure": cpu_pressure,
            "memory_pressure": memory_pressure,
            "cpu_percent": self.current_system_metrics.total_cpu_percent,
            "memory_percent": self.current_system_metrics.memory_percent,
            "recommendation": (
                "Consider scaling down workers" if cpu_pressure or memory_pressure else "Resources healthy"
            ),
        }
