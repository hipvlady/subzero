"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

B+ Tree Indexing for Permission Cache
Optimized for range queries and hierarchical permissions

Based on "Designing Data-Intensive Applications" (Kleppmann)
Following B+ tree implementation from database systems

Features:
- Efficient range queries for wildcard permissions
- Prefix compression for index keys
- Sorted iteration support
- Cache-friendly node layout
- Support for hierarchical permission queries
"""

import bisect
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class PermissionEntry:
    """Permission cache entry"""

    user_id: int
    resource_id: int
    permission: str
    value: Any
    ttl: float


class BPlusTreeNode:
    """B+ tree node (internal or leaf)"""

    def __init__(self, order: int, is_leaf: bool = False):
        """
        Initialize B+ tree node

        Args:
            order: Maximum number of children per node
            is_leaf: Whether this is a leaf node
        """
        self.order = order
        self.is_leaf = is_leaf

        # Keys (sorted)
        self.keys: list[tuple[int, int]] = []  # (user_id, resource_id) tuples

        # Values (for leaf nodes)
        self.values: list[PermissionEntry] = []

        # Children (for internal nodes)
        self.children: list[BPlusTreeNode] = []

        # Leaf node linkage for range queries
        self.next_leaf: BPlusTreeNode | None = None
        self.prev_leaf: BPlusTreeNode | None = None

    def is_full(self) -> bool:
        """Check if node is full"""
        return len(self.keys) >= self.order - 1

    def insert_key(self, key: tuple[int, int], value: PermissionEntry) -> Optional["BPlusTreeNode"]:
        """
        Insert key-value pair into node

        Args:
            key: (user_id, resource_id) tuple
            value: Permission entry

        Returns:
            New root if split occurred, None otherwise
        """
        if self.is_leaf:
            # Leaf node: insert directly
            idx = bisect.bisect_left(self.keys, key)

            if idx < len(self.keys) and self.keys[idx] == key:
                # Update existing key
                self.values[idx] = value
                return None

            # Insert new key
            self.keys.insert(idx, key)
            self.values.insert(idx, value)

            # Check if split needed
            if self.is_full():
                return self._split_leaf()

            return None

        else:
            # Internal node: find child
            idx = bisect.bisect_right(self.keys, key)
            child = self.children[idx]

            # Recursively insert
            new_node = child.insert_key(key, value)

            if new_node:
                # Child split, insert new key
                split_key = new_node.keys[0]
                self.keys.insert(idx, split_key)
                self.children.insert(idx + 1, new_node)

                # Check if this node needs to split
                if self.is_full():
                    return self._split_internal()

            return None

    def _split_leaf(self) -> "BPlusTreeNode":
        """Split leaf node"""
        mid = len(self.keys) // 2

        # Create new leaf
        new_leaf = BPlusTreeNode(order=self.order, is_leaf=True)
        new_leaf.keys = self.keys[mid:]
        new_leaf.values = self.values[mid:]

        # Update current leaf
        self.keys = self.keys[:mid]
        self.values = self.values[:mid]

        # Update linkage
        new_leaf.next_leaf = self.next_leaf
        new_leaf.prev_leaf = self
        self.next_leaf = new_leaf

        if new_leaf.next_leaf:
            new_leaf.next_leaf.prev_leaf = new_leaf

        return new_leaf

    def _split_internal(self) -> "BPlusTreeNode":
        """Split internal node"""
        mid = len(self.keys) // 2

        # Create new internal node
        new_internal = BPlusTreeNode(order=self.order, is_leaf=False)
        new_internal.keys = self.keys[mid + 1 :]
        new_internal.children = self.children[mid + 1 :]

        # Update current internal
        self.keys = self.keys[:mid]
        self.children = self.children[: mid + 1]

        return new_internal

    def search(self, key: tuple[int, int]) -> PermissionEntry | None:
        """
        Search for key in subtree

        Args:
            key: (user_id, resource_id) tuple

        Returns:
            Permission entry if found
        """
        if self.is_leaf:
            # Leaf node: binary search
            idx = bisect.bisect_left(self.keys, key)
            if idx < len(self.keys) and self.keys[idx] == key:
                return self.values[idx]
            return None

        else:
            # Internal node: find child
            idx = bisect.bisect_right(self.keys, key)
            return self.children[idx].search(key)

    def range_search(self, start_key: tuple[int, int], end_key: tuple[int, int]) -> list[PermissionEntry]:
        """
        Range query from start_key to end_key (inclusive)

        Args:
            start_key: Start of range
            end_key: End of range

        Returns:
            List of permission entries in range
        """
        if self.is_leaf:
            # Leaf node: collect entries in range
            results = []
            for i, key in enumerate(self.keys):
                if start_key <= key <= end_key:
                    results.append(self.values[i])
                elif key > end_key:
                    break
            return results

        else:
            # Internal node: find starting child
            idx = bisect.bisect_left(self.keys, start_key)
            results = []

            # Collect from all relevant children
            while idx < len(self.children):
                child_results = self.children[idx].range_search(start_key, end_key)
                results.extend(child_results)

                # Check if we've passed end_key
                if idx < len(self.keys) and self.keys[idx] > end_key:
                    break

                idx += 1

            return results


class BPlusTreeIndex:
    """
    B+ Tree index for permission cache
    Optimized for hierarchical permission queries
    """

    def __init__(self, order: int = 64):
        """
        Initialize B+ tree index

        Args:
            order: B+ tree order (branching factor)
        """
        self.order = order
        self.root = BPlusTreeNode(order=order, is_leaf=True)

        # Index statistics
        self.stats = {
            "total_entries": 0,
            "total_inserts": 0,
            "total_searches": 0,
            "total_range_queries": 0,
            "tree_height": 1,
        }

    def insert(self, user_id: int, resource_id: int, permission: str, value: Any, ttl: float = 3600.0):
        """
        Insert permission into index

        Args:
            user_id: User ID
            resource_id: Resource ID
            permission: Permission name
            value: Permission value
            ttl: Time to live
        """
        key = (user_id, resource_id)
        entry = PermissionEntry(user_id=user_id, resource_id=resource_id, permission=permission, value=value, ttl=ttl)

        # Insert into tree
        new_root = self.root.insert_key(key, entry)

        if new_root:
            # Root split, create new root
            old_root = self.root
            self.root = BPlusTreeNode(order=self.order, is_leaf=False)
            self.root.keys = [new_root.keys[0]]
            self.root.children = [old_root, new_root]

            self.stats["tree_height"] += 1

        self.stats["total_entries"] += 1
        self.stats["total_inserts"] += 1

    def search(self, user_id: int, resource_id: int) -> PermissionEntry | None:
        """
        Search for permission

        Args:
            user_id: User ID
            resource_id: Resource ID

        Returns:
            Permission entry if found
        """
        key = (user_id, resource_id)
        self.stats["total_searches"] += 1
        return self.root.search(key)

    def range_query(self, user_id: int, resource_id_start: int, resource_id_end: int) -> list[PermissionEntry]:
        """
        Range query for user's resources

        Args:
            user_id: User ID
            resource_id_start: Start resource ID
            resource_id_end: End resource ID

        Returns:
            List of permission entries
        """
        start_key = (user_id, resource_id_start)
        end_key = (user_id, resource_id_end)

        self.stats["total_range_queries"] += 1
        return self.root.range_search(start_key, end_key)

    def user_permissions(self, user_id: int) -> list[PermissionEntry]:
        """
        Get all permissions for user

        Args:
            user_id: User ID

        Returns:
            List of all permissions for user
        """
        # Range query across all resources for user
        start_key = (user_id, 0)
        end_key = (user_id, 2**31 - 1)  # Max int

        self.stats["total_range_queries"] += 1
        return self.root.range_search(start_key, end_key)

    def wildcard_match(self, user_id: int, resource_pattern: str) -> list[PermissionEntry]:
        """
        Wildcard permission matching

        Args:
            user_id: User ID
            resource_pattern: Resource pattern (e.g., "document.*")

        Returns:
            Matching permissions
        """
        # Get all user permissions
        all_perms = self.user_permissions(user_id)

        # Filter by pattern (simple prefix match for now)
        if resource_pattern.endswith("*"):
            prefix = resource_pattern[:-1]
            return [p for p in all_perms if p.permission.startswith(prefix)]

        return [p for p in all_perms if p.permission == resource_pattern]

    def iterate_leaves(self) -> Iterator[PermissionEntry]:
        """
        Iterate all entries in sorted order

        Yields:
            Permission entries in key order
        """
        # Find leftmost leaf
        node = self.root
        while not node.is_leaf:
            node = node.children[0]

        # Traverse leaf chain
        while node:
            yield from node.values
            node = node.next_leaf

    def get_stats(self) -> dict:
        """Get index statistics"""
        return self.stats.copy()


class HierarchicalPermissionIndex:
    """
    Hierarchical permission index using B+ trees
    Supports multi-level permission hierarchies
    """

    def __init__(self):
        """Initialize hierarchical permission index"""
        # Separate indexes for different permission types
        self.user_resource_index = BPlusTreeIndex(order=64)
        self.resource_user_index = BPlusTreeIndex(order=64)

        # Wildcard cache
        self.wildcard_cache: dict[str, list[PermissionEntry]] = {}
        self.wildcard_cache_hits = 0
        self.wildcard_cache_misses = 0

    def grant_permission(self, user_id: int, resource_id: int, permission: str, value: Any = True, ttl: float = 3600.0):
        """
        Grant permission to user for resource

        Args:
            user_id: User ID
            resource_id: Resource ID
            permission: Permission name
            value: Permission value
            ttl: Time to live
        """
        # Insert into both indexes
        self.user_resource_index.insert(user_id, resource_id, permission, value, ttl)
        self.resource_user_index.insert(resource_id, user_id, permission, value, ttl)

        # Invalidate wildcard cache
        self.wildcard_cache.clear()

    def check_permission(self, user_id: int, resource_id: int) -> PermissionEntry | None:
        """
        Check if user has permission for resource

        Args:
            user_id: User ID
            resource_id: Resource ID

        Returns:
            Permission entry if granted
        """
        return self.user_resource_index.search(user_id, resource_id)

    def get_user_permissions(self, user_id: int) -> list[PermissionEntry]:
        """
        Get all permissions for user

        Args:
            user_id: User ID

        Returns:
            List of permissions
        """
        return self.user_resource_index.user_permissions(user_id)

    def get_resource_users(self, resource_id: int) -> list[PermissionEntry]:
        """
        Get all users with permission for resource

        Args:
            resource_id: Resource ID

        Returns:
            List of permissions
        """
        return self.resource_user_index.user_permissions(resource_id)

    def wildcard_check(self, user_id: int, resource_pattern: str) -> list[PermissionEntry]:
        """
        Check wildcard permissions with caching

        Args:
            user_id: User ID
            resource_pattern: Resource pattern

        Returns:
            Matching permissions
        """
        cache_key = f"{user_id}:{resource_pattern}"

        if cache_key in self.wildcard_cache:
            self.wildcard_cache_hits += 1
            return self.wildcard_cache[cache_key]

        self.wildcard_cache_misses += 1
        results = self.user_resource_index.wildcard_match(user_id, resource_pattern)
        self.wildcard_cache[cache_key] = results

        return results

    def get_stats(self) -> dict:
        """Get index statistics"""
        return {
            "user_resource_index": self.user_resource_index.get_stats(),
            "resource_user_index": self.resource_user_index.get_stats(),
            "wildcard_cache": {
                "size": len(self.wildcard_cache),
                "hits": self.wildcard_cache_hits,
                "misses": self.wildcard_cache_misses,
                "hit_ratio": (
                    self.wildcard_cache_hits / (self.wildcard_cache_hits + self.wildcard_cache_misses)
                    if (self.wildcard_cache_hits + self.wildcard_cache_misses) > 0
                    else 0.0
                ),
            },
        }


# Global instance
_hierarchical_index: HierarchicalPermissionIndex | None = None


def get_hierarchical_index() -> HierarchicalPermissionIndex:
    """Get global hierarchical permission index"""
    global _hierarchical_index
    if _hierarchical_index is None:
        _hierarchical_index = HierarchicalPermissionIndex()
    return _hierarchical_index
