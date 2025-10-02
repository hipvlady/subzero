"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

Adaptive Batching with Machine Learning Optimization
Uses online learning algorithms to optimize batch sizes dynamically

Based on "Python Concurrency with asyncio" (Fowler)
Following ML patterns for systems optimization

Features:
- EWMA (Exponential Weighted Moving Average) for predictions
- UCB (Upper Confidence Bound) for exploration/exploitation
- Adaptive batch sizing based on latency/throughput targets
- Multi-armed bandit algorithm for batch size selection
- Real-time adaptation to workload patterns
"""

import asyncio
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Callable, Generic, Optional, TypeVar

import numpy as np

T = TypeVar("T")


@dataclass
class BatchMetrics:
    """Metrics for a batch execution"""

    batch_size: int
    latency_ms: float
    throughput: float
    success_rate: float
    timestamp: float


class EWMAPredictor:
    """
    Exponential Weighted Moving Average predictor
    Tracks and predicts optimal batch sizes
    """

    def __init__(self, alpha: float = 0.2):
        """
        Initialize EWMA predictor

        Args:
            alpha: Smoothing factor (0 < alpha < 1)
                  Higher alpha = more weight to recent observations
        """
        self.alpha = alpha
        self.ewma_latency = 0.0
        self.ewma_throughput = 0.0
        self.count = 0

    def update(self, latency_ms: float, throughput: float):
        """Update EWMA with new observation"""
        if self.count == 0:
            # Initialize
            self.ewma_latency = latency_ms
            self.ewma_throughput = throughput
        else:
            # Update EWMA
            self.ewma_latency = self.alpha * latency_ms + (1 - self.alpha) * self.ewma_latency
            self.ewma_throughput = self.alpha * throughput + (1 - self.alpha) * self.ewma_throughput

        self.count += 1

    def predict_latency(self) -> float:
        """Predict next latency"""
        return self.ewma_latency

    def predict_throughput(self) -> float:
        """Predict next throughput"""
        return self.ewma_throughput


class UCBBatchSelector:
    """
    Upper Confidence Bound algorithm for batch size selection
    Balances exploration vs exploitation
    """

    def __init__(self, min_batch: int = 1, max_batch: int = 100, num_arms: int = 10):
        """
        Initialize UCB selector

        Args:
            min_batch: Minimum batch size
            max_batch: Maximum batch size
            num_arms: Number of batch size options (arms)
        """
        self.min_batch = min_batch
        self.max_batch = max_batch
        self.num_arms = num_arms

        # Batch size options (arms)
        self.batch_sizes = np.linspace(min_batch, max_batch, num_arms, dtype=int)

        # Arm statistics
        self.arm_counts = np.zeros(num_arms)
        self.arm_rewards = np.zeros(num_arms)
        self.arm_avg_rewards = np.zeros(num_arms)

        self.total_pulls = 0

    def select_batch_size(self, exploration_factor: float = 2.0) -> int:
        """
        Select batch size using UCB algorithm

        Args:
            exploration_factor: Controls exploration vs exploitation

        Returns:
            Selected batch size
        """
        if self.total_pulls < self.num_arms:
            # Initial exploration: try each arm once
            arm_idx = self.total_pulls
        else:
            # UCB selection
            ucb_values = np.zeros(self.num_arms)

            for i in range(self.num_arms):
                if self.arm_counts[i] == 0:
                    ucb_values[i] = float("inf")
                else:
                    # UCB formula: avg_reward + exploration_bonus
                    avg_reward = self.arm_avg_rewards[i]
                    exploration_bonus = exploration_factor * math.sqrt(math.log(self.total_pulls) / self.arm_counts[i])
                    ucb_values[i] = avg_reward + exploration_bonus

            arm_idx = int(np.argmax(ucb_values))

        return int(self.batch_sizes[arm_idx])

    def update_reward(self, batch_size: int, reward: float):
        """
        Update arm statistics with reward

        Args:
            batch_size: Batch size that was used
            reward: Reward received (higher is better)
        """
        # Find closest arm
        arm_idx = int(np.argmin(np.abs(self.batch_sizes - batch_size)))

        # Update statistics
        self.arm_counts[arm_idx] += 1
        self.arm_rewards[arm_idx] += reward
        self.arm_avg_rewards[arm_idx] = self.arm_rewards[arm_idx] / self.arm_counts[arm_idx]

        self.total_pulls += 1


class AdaptiveBatcher(Generic[T]):
    """
    Adaptive batching system with ML-based optimization
    Dynamically adjusts batch sizes based on performance metrics
    """

    def __init__(
        self,
        batch_processor: Callable[[list[T]], Any],
        target_latency_ms: float = 10.0,
        target_throughput: float = 1000.0,
        min_batch_size: int = 1,
        max_batch_size: int = 100,
        max_wait_ms: float = 5.0,
    ):
        """
        Initialize adaptive batcher

        Args:
            batch_processor: Function to process batches
            target_latency_ms: Target batch processing latency
            target_throughput: Target throughput (items/sec)
            min_batch_size: Minimum batch size
            max_batch_size: Maximum batch size
            max_wait_ms: Maximum wait time before processing
        """
        self.batch_processor = batch_processor
        self.target_latency_ms = target_latency_ms
        self.target_throughput = target_throughput
        self.max_wait_ms = max_wait_ms

        # Current batch
        self.current_batch: list[T] = []
        self.batch_start_time: Optional[float] = None

        # ML components
        self.ewma_predictor = EWMAPredictor(alpha=0.2)
        self.ucb_selector = UCBBatchSelector(min_batch=min_batch_size, max_batch=max_batch_size, num_arms=10)

        # Current batch size (adaptive)
        self.current_batch_size = min_batch_size

        # Metrics history
        self.metrics_history: deque[BatchMetrics] = deque(maxlen=100)

        # Background task
        self._flush_task: Optional[asyncio.Task] = None
        self.is_running = False

        # Statistics
        self.stats = {
            "total_items": 0,
            "total_batches": 0,
            "avg_batch_size": 0.0,
            "avg_latency_ms": 0.0,
            "avg_throughput": 0.0,
            "current_batch_size": min_batch_size,
        }

    async def start(self):
        """Start adaptive batcher"""
        if not self.is_running:
            self.is_running = True
            self._flush_task = asyncio.create_task(self._flush_loop())
            print("🎯 Adaptive batcher started")

    async def stop(self):
        """Stop adaptive batcher"""
        if self._flush_task:
            self.is_running = False
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
            self._flush_task = None

            # Flush remaining items
            if self.current_batch:
                await self._process_batch()

    async def add(self, item: T):
        """
        Add item to batch

        Args:
            item: Item to add
        """
        # Start batch timer on first item
        if not self.current_batch:
            self.batch_start_time = time.time()

        self.current_batch.append(item)
        self.stats["total_items"] += 1

        # Check if batch is full
        if len(self.current_batch) >= self.current_batch_size:
            await self._process_batch()

    async def _flush_loop(self):
        """Background flush loop"""
        while self.is_running:
            try:
                # Check if batch timeout reached
                if self.current_batch and self.batch_start_time:
                    elapsed_ms = (time.time() - self.batch_start_time) * 1000

                    if elapsed_ms >= self.max_wait_ms:
                        await self._process_batch()

                # Sleep for 1ms
                await asyncio.sleep(0.001)

            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"❌ Adaptive batcher flush error: {e}")

    async def _process_batch(self):
        """Process current batch and update ML models"""
        if not self.current_batch:
            return

        batch = self.current_batch
        batch_size = len(batch)
        self.current_batch = []

        # Measure batch processing
        start_time = time.time()

        try:
            # Process batch
            if asyncio.iscoroutinefunction(self.batch_processor):
                await self.batch_processor(batch)
            else:
                self.batch_processor(batch)

            success_rate = 1.0

        except Exception as e:
            print(f"⚠️  Batch processing error: {e}")
            success_rate = 0.0

        # Calculate metrics
        latency_ms = (time.time() - start_time) * 1000
        throughput = batch_size / (latency_ms / 1000) if latency_ms > 0 else 0.0

        # Create metrics record
        metrics = BatchMetrics(
            batch_size=batch_size,
            latency_ms=latency_ms,
            throughput=throughput,
            success_rate=success_rate,
            timestamp=time.time(),
        )

        self.metrics_history.append(metrics)

        # Update EWMA predictor
        self.ewma_predictor.update(latency_ms, throughput)

        # Calculate reward for UCB
        # Reward is higher when we're close to targets
        latency_score = 1.0 - min(abs(latency_ms - self.target_latency_ms) / self.target_latency_ms, 1.0)
        throughput_score = min(throughput / self.target_throughput, 1.0)
        reward = (latency_score + throughput_score) / 2.0 * success_rate

        # Update UCB selector
        self.ucb_selector.update_reward(batch_size, reward)

        # Select next batch size using UCB
        self.current_batch_size = self.ucb_selector.select_batch_size()

        # Update stats
        self.stats["total_batches"] += 1
        self.stats["avg_batch_size"] = self.stats["total_items"] / self.stats["total_batches"]
        self.stats["avg_latency_ms"] = self.ewma_predictor.predict_latency()
        self.stats["avg_throughput"] = self.ewma_predictor.predict_throughput()
        self.stats["current_batch_size"] = self.current_batch_size

        # Reset batch timer
        self.batch_start_time = None

    def get_stats(self) -> dict:
        """Get batcher statistics"""
        ucb_stats = {
            "batch_sizes": self.ucb_selector.batch_sizes.tolist(),
            "arm_counts": self.ucb_selector.arm_counts.tolist(),
            "arm_avg_rewards": self.ucb_selector.arm_avg_rewards.tolist(),
        }

        recent_metrics = []
        if self.metrics_history:
            recent_metrics = [
                {
                    "batch_size": m.batch_size,
                    "latency_ms": m.latency_ms,
                    "throughput": m.throughput,
                }
                for m in list(self.metrics_history)[-10:]
            ]

        return {
            "stats": self.stats,
            "ucb": ucb_stats,
            "ewma": {
                "latency_ms": self.ewma_predictor.predict_latency(),
                "throughput": self.ewma_predictor.predict_throughput(),
            },
            "recent_metrics": recent_metrics,
        }


class MultiTargetBatcher:
    """
    Multi-target adaptive batcher
    Maintains separate batchers for different operation types
    """

    def __init__(self):
        self.batchers: dict[str, AdaptiveBatcher] = {}

    def create_batcher(
        self,
        name: str,
        batch_processor: Callable,
        target_latency_ms: float = 10.0,
        min_batch_size: int = 1,
        max_batch_size: int = 100,
    ) -> AdaptiveBatcher:
        """Create named batcher"""
        batcher = AdaptiveBatcher(
            batch_processor=batch_processor,
            target_latency_ms=target_latency_ms,
            min_batch_size=min_batch_size,
            max_batch_size=max_batch_size,
        )

        self.batchers[name] = batcher
        return batcher

    async def start_all(self):
        """Start all batchers"""
        for batcher in self.batchers.values():
            await batcher.start()

    async def stop_all(self):
        """Stop all batchers"""
        for batcher in self.batchers.values():
            await batcher.stop()

    def get_batcher(self, name: str) -> Optional[AdaptiveBatcher]:
        """Get batcher by name"""
        return self.batchers.get(name)

    def get_all_stats(self) -> dict:
        """Get stats for all batchers"""
        return {name: batcher.get_stats() for name, batcher in self.batchers.items()}


# Global instance
_multi_batcher: Optional[MultiTargetBatcher] = None


def get_multi_batcher() -> MultiTargetBatcher:
    """Get global multi-target batcher"""
    global _multi_batcher
    if _multi_batcher is None:
        _multi_batcher = MultiTargetBatcher()
    return _multi_batcher
