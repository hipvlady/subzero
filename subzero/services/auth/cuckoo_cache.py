"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

Cuckoo Hashing Cache for Ultra-Fast Lookups
Provides O(1) worst-case lookup time
"""

import hashlib
from typing import Any

import numpy as np


class CuckooCache:
    """
    High-performance cache using Cuckoo hashing

    Features:
    - O(1) worst-case lookup time
    - Better cache utilization than standard hash tables
    - Fast inserts with minimal collisions
    - Memory-efficient with numpy arrays
    """

    def __init__(self, capacity: int = 10000, num_tables: int = 2):
        """
        Initialize Cuckoo cache

        Args:
            capacity: Maximum number of items
            num_tables: Number of hash tables (default: 2)
        """
        self.capacity = capacity
        self.num_tables = num_tables
        self.max_kicks = 500  # Maximum relocations before resize

        # Initialize hash tables
        self.tables = [{}  for _ in range(num_tables)]
        self.keys = [np.zeros(capacity, dtype=np.uint64) for _ in range(num_tables)]
        self.sizes = [0] * num_tables

    def _hash(self, key: np.uint64, table_idx: int) -> int:
        """
        Compute hash for given table

        Args:
            key: Key to hash
            table_idx: Table index

        Returns:
            Hash value
        """
        # Use different hash functions for each table
        seed = table_idx + 1
        hash_bytes = int(key).to_bytes(8, byteorder="big")
        hash_val = int.from_bytes(hashlib.blake2b(hash_bytes, digest_size=8, salt=str(seed).encode()).digest(), "big")

        return hash_val % self.capacity

    def insert(self, key: np.uint64, value: Any) -> bool:
        """
        Insert key-value pair

        Args:
            key: Key (numpy uint64)
            value: Value to store

        Returns:
            True if successful, False otherwise
        """
        # Try to insert in each table
        for table_idx in range(self.num_tables):
            idx = self._hash(key, table_idx)

            # If slot is empty or has same key, insert
            if self.keys[table_idx][idx] == 0 or self.keys[table_idx][idx] == key:
                if self.keys[table_idx][idx] == 0:
                    self.sizes[table_idx] += 1

                self.keys[table_idx][idx] = key
                self.tables[table_idx][idx] = value
                return True

        # Need to relocate (cuckoo hashing)
        return self._relocate(key, value)

    def _relocate(self, key: np.uint64, value: Any) -> bool:
        """
        Relocate existing items to make room (cuckoo hashing)

        Args:
            key: Key to insert
            value: Value to insert

        Returns:
            True if successful
        """
        current_key = key
        current_value = value

        for _ in range(self.max_kicks):
            # Pick a random table
            table_idx = np.random.randint(0, self.num_tables)
            idx = self._hash(current_key, table_idx)

            # Swap with existing item
            old_key = self.keys[table_idx][idx]
            old_value = self.tables[table_idx].get(idx)

            self.keys[table_idx][idx] = current_key
            self.tables[table_idx][idx] = current_value

            if old_key == 0:
                self.sizes[table_idx] += 1
                return True

            # Continue with displaced item
            current_key = old_key
            current_value = old_value

        # Failed to insert after max kicks
        return False

    def get(self, key: np.uint64) -> Any | None:
        """
        Get value for key

        Args:
            key: Key to lookup

        Returns:
            Value if found, None otherwise
        """
        # Check all tables
        for table_idx in range(self.num_tables):
            idx = self._hash(key, table_idx)

            if self.keys[table_idx][idx] == key:
                return self.tables[table_idx].get(idx)

        return None

    def delete(self, key: np.uint64) -> bool:
        """
        Delete key from cache

        Args:
            key: Key to delete

        Returns:
            True if deleted, False if not found
        """
        for table_idx in range(self.num_tables):
            idx = self._hash(key, table_idx)

            if self.keys[table_idx][idx] == key:
                self.keys[table_idx][idx] = 0
                del self.tables[table_idx][idx]
                self.sizes[table_idx] -= 1
                return True

        return False

    def contains(self, key: np.uint64) -> bool:
        """Check if key exists"""
        return self.get(key) is not None

    def clear(self):
        """Clear all entries"""
        self.tables = [{} for _ in range(self.num_tables)]
        self.keys = [np.zeros(self.capacity, dtype=np.uint64) for _ in range(self.num_tables)]
        self.sizes = [0] * self.num_tables

    def __len__(self) -> int:
        """Get total number of items"""
        return sum(self.sizes)

    def get_load_factor(self) -> float:
        """Get cache load factor"""
        return len(self) / (self.capacity * self.num_tables)
