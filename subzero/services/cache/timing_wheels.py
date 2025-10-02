"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

Hierarchical Timing Wheels for O(1) Cache Expiry
Implements multi-level timing wheels for efficient expiry management

Based on "Hashed and Hierarchical Timing Wheels" paper by Varghese & Lauck
Following Kleppmann's timer management patterns from DDIA

Features:
- O(1) insertion and deletion
- O(1) expiry processing per tick
- Multi-level hierarchy for different time granularities
- Lazy deletion with generation counters
- Batch expiry processing
"""

import asyncio
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any


class TimeUnit(Enum):
    """Time units for hierarchical wheels"""

    MILLISECONDS = 1
    SECONDS = 1000
    MINUTES = 60000
    HOURS = 3600000


@dataclass
class ExpiryEntry:
    """Entry in timing wheel"""

    key: str
    expiry_time: float
    generation: int  # For lazy deletion
    callback: Callable | None = None
    data: Any | None = None


class TimingWheel:
    """
    Single-level timing wheel
    Implements circular buffer with buckets
    """

    def __init__(self, num_buckets: int, tick_duration_ms: int, level: int = 0):
        """
        Initialize timing wheel

        Args:
            num_buckets: Number of buckets in wheel
            tick_duration_ms: Duration of each tick in milliseconds
            level: Hierarchy level (0 = finest granularity)
        """
        self.num_buckets = num_buckets
        self.tick_duration_ms = tick_duration_ms
        self.level = level

        # Circular buffer of buckets
        self.buckets: list[deque[ExpiryEntry]] = [deque() for _ in range(num_buckets)]

        # Current position in wheel
        self.current_tick = 0

        # Total duration this wheel covers
        self.total_duration_ms = num_buckets * tick_duration_ms

        # Parent wheel (for overflow)
        self.parent_wheel: TimingWheel | None = None

        # Statistics
        self.stats = {
            "insertions": 0,
            "deletions": 0,
            "expirations": 0,
            "overflows": 0,
        }

    def insert(self, entry: ExpiryEntry) -> bool:
        """
        Insert entry into appropriate bucket

        Args:
            entry: Expiry entry to insert

        Returns:
            True if inserted, False if overflowed to parent
        """
        current_time_ms = int(time.time() * 1000)
        delay_ms = int(entry.expiry_time * 1000) - current_time_ms

        if delay_ms < 0:
            # Already expired
            return True

        if delay_ms < self.total_duration_ms:
            # Fits in this wheel
            ticks_from_now = delay_ms // self.tick_duration_ms
            bucket_idx = (self.current_tick + ticks_from_now) % self.num_buckets

            self.buckets[bucket_idx].append(entry)
            self.stats["insertions"] += 1
            return True

        # Overflow to parent wheel
        if self.parent_wheel:
            self.stats["overflows"] += 1
            return self.parent_wheel.insert(entry)

        # No parent, insert at last bucket
        self.buckets[-1].append(entry)
        self.stats["insertions"] += 1
        return True

    def advance(self) -> list[ExpiryEntry]:
        """
        Advance wheel by one tick and return expired entries

        Returns:
            List of expired entries
        """
        expired = []

        # Get entries from current bucket
        current_bucket = self.buckets[self.current_tick]

        while current_bucket:
            entry = current_bucket.popleft()

            current_time_ms = int(time.time() * 1000)
            expiry_time_ms = int(entry.expiry_time * 1000)

            if expiry_time_ms <= current_time_ms:
                # Actually expired
                expired.append(entry)
                self.stats["expirations"] += 1
            else:
                # Re-insert into appropriate bucket (cascade from parent)
                self.insert(entry)

        # Advance tick
        self.current_tick = (self.current_tick + 1) % self.num_buckets

        return expired

    def remove(self, key: str, generation: int) -> bool:
        """
        Remove entry by key (lazy deletion)

        Args:
            key: Entry key
            generation: Generation number for verification

        Returns:
            True if removed
        """
        # Note: Actual removal happens during expiry processing
        # This just marks for deletion via generation counter
        self.stats["deletions"] += 1
        return True


class HierarchicalTimingWheels:
    """
    Multi-level hierarchical timing wheels
    Provides O(1) expiry management across different time scales
    """

    def __init__(self):
        """
        Initialize hierarchical timing wheels

        Architecture:
        - Level 0: 256 buckets × 10ms = 2.56s coverage
        - Level 1: 64 buckets × 2.56s = 163s coverage (~2.7min)
        - Level 2: 64 buckets × 163s = 10,432s coverage (~2.9hr)
        - Level 3: 24 buckets × 10,432s = 250,368s coverage (~69hr)
        """
        # Level 0: Millisecond-level (10ms ticks)
        self.wheel_level0 = TimingWheel(num_buckets=256, tick_duration_ms=10, level=0)

        # Level 1: Second-level (2.56s ticks)
        self.wheel_level1 = TimingWheel(num_buckets=64, tick_duration_ms=2560, level=1)

        # Level 2: Minute-level (163s ticks)
        self.wheel_level2 = TimingWheel(num_buckets=64, tick_duration_ms=163840, level=2)

        # Level 3: Hour-level (2.9hr ticks)
        self.wheel_level3 = TimingWheel(num_buckets=24, tick_duration_ms=10485760, level=3)

        # Wire parent relationships
        self.wheel_level0.parent_wheel = self.wheel_level1
        self.wheel_level1.parent_wheel = self.wheel_level2
        self.wheel_level2.parent_wheel = self.wheel_level3

        # Entry registry for lazy deletion
        self.entries: dict[str, int] = {}  # key -> generation
        self.current_generation = 0

        # Expiry callbacks
        self.callbacks: dict[str, Callable] = {}

        # Background task
        self._tick_task: asyncio.Task | None = None
        self.is_running = False

        # Metrics
        self.metrics = {
            "total_insertions": 0,
            "total_expirations": 0,
            "total_deletions": 0,
            "active_entries": 0,
            "tick_latency_ms": 0.0,
        }

    async def start(self):
        """Start background tick processor"""
        if not self.is_running:
            self.is_running = True
            self._tick_task = asyncio.create_task(self._tick_loop())
            print("⏰ Hierarchical timing wheels started")

    async def stop(self):
        """Stop background processor"""
        if self._tick_task:
            self.is_running = False
            self._tick_task.cancel()
            try:
                await self._tick_task
            except asyncio.CancelledError:
                pass
            self._tick_task = None

    def schedule_expiry(
        self, key: str, expiry_time: float, callback: Callable | None = None, data: Any | None = None
    ) -> bool:
        """
        Schedule entry for expiry

        Args:
            key: Unique entry key
            expiry_time: Unix timestamp when entry expires
            callback: Optional callback when expired
            data: Optional data to pass to callback

        Returns:
            True if scheduled successfully
        """
        # Generate new generation for this key
        self.current_generation += 1
        generation = self.current_generation
        self.entries[key] = generation

        # Store callback if provided
        if callback:
            self.callbacks[key] = callback

        # Create entry
        entry = ExpiryEntry(key=key, expiry_time=expiry_time, generation=generation, callback=callback, data=data)

        # Insert into level 0 wheel
        success = self.wheel_level0.insert(entry)

        if success:
            self.metrics["total_insertions"] += 1
            self.metrics["active_entries"] += 1

        return success

    def cancel_expiry(self, key: str) -> bool:
        """
        Cancel scheduled expiry (lazy deletion)

        Args:
            key: Entry key to cancel

        Returns:
            True if entry existed
        """
        if key in self.entries:
            # Increment generation to invalidate entry
            self.current_generation += 1
            self.entries[key] = self.current_generation

            # Remove callback
            self.callbacks.pop(key, None)

            self.metrics["total_deletions"] += 1
            self.metrics["active_entries"] -= 1
            return True

        return False

    def reschedule(self, key: str, new_expiry_time: float) -> bool:
        """
        Reschedule existing entry

        Args:
            key: Entry key
            new_expiry_time: New expiry time

        Returns:
            True if rescheduled
        """
        # Cancel old entry
        self.cancel_expiry(key)

        # Schedule new entry
        callback = self.callbacks.get(key)
        return self.schedule_expiry(key, new_expiry_time, callback)

    async def _tick_loop(self):
        """Background tick processor"""
        time.time()
        tick_count = 0

        while self.is_running:
            try:
                tick_start = time.time()

                # Advance level 0 wheel every 10ms
                expired_entries = self.wheel_level0.advance()

                # Process expired entries
                for entry in expired_entries:
                    # Check generation (lazy deletion)
                    if self.entries.get(entry.key) == entry.generation:
                        # Valid expiry
                        self.metrics["total_expirations"] += 1
                        self.metrics["active_entries"] -= 1

                        # Remove from registry
                        self.entries.pop(entry.key, None)

                        # Execute callback
                        if entry.callback:
                            try:
                                if asyncio.iscoroutinefunction(entry.callback):
                                    await entry.callback(entry.key, entry.data)
                                else:
                                    entry.callback(entry.key, entry.data)
                            except Exception as e:
                                print(f"⚠️  Expiry callback error for {entry.key}: {e}")

                # Advance higher-level wheels
                tick_count += 1

                # Level 1: Advance every 256 ticks (2.56s)
                if tick_count % 256 == 0:
                    level1_expired = self.wheel_level1.advance()
                    # Re-insert into level 0
                    for entry in level1_expired:
                        self.wheel_level0.insert(entry)

                # Level 2: Advance every 16,384 ticks (163.84s)
                if tick_count % 16384 == 0:
                    level2_expired = self.wheel_level2.advance()
                    # Re-insert into level 1
                    for entry in level2_expired:
                        self.wheel_level1.insert(entry)

                # Level 3: Advance every 1,048,576 ticks (2.9hr)
                if tick_count % 1048576 == 0:
                    level3_expired = self.wheel_level3.advance()
                    # Re-insert into level 2
                    for entry in level3_expired:
                        self.wheel_level2.insert(entry)

                # Measure tick latency
                tick_duration = (time.time() - tick_start) * 1000
                self.metrics["tick_latency_ms"] = tick_duration

                # Sleep for 10ms (level 0 tick duration)
                await asyncio.sleep(0.01)

            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"❌ Timing wheel tick error: {e}")
                await asyncio.sleep(0.01)

    def get_stats(self) -> dict:
        """Get timing wheel statistics"""
        return {
            "metrics": self.metrics,
            "level0": self.wheel_level0.stats,
            "level1": self.wheel_level1.stats,
            "level2": self.wheel_level2.stats,
            "level3": self.wheel_level3.stats,
            "active_entries": self.metrics["active_entries"],
            "total_expirations": self.metrics["total_expirations"],
        }


# Global instance
_timing_wheels: HierarchicalTimingWheels | None = None


def get_timing_wheels() -> HierarchicalTimingWheels:
    """Get global timing wheels instance"""
    global _timing_wheels
    if _timing_wheels is None:
        _timing_wheels = HierarchicalTimingWheels()
    return _timing_wheels
