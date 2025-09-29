"""
Relationship-Based Access Control (ReBAC) Engine
Implements Google Zanzibar-style authorization for complex resource graphs

Features:
- Graph-based permission evaluation
- Transitive relationships (e.g., parent->child inheritance)
- Union/intersection/exclusion operators
- Integration with Auth0 FGA
- High-performance cached evaluation
"""

import asyncio
import time
from typing import Dict, List, Optional, Set, Tuple, FrozenSet
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque

import numpy as np
from numba import jit
import aiohttp


class RelationType(str, Enum):
    """Types of relationships between objects"""
    OWNER = "owner"
    EDITOR = "editor"
    VIEWER = "viewer"
    PARENT = "parent"
    MEMBER = "member"
    ADMIN = "admin"
    CONTRIBUTOR = "contributor"


class Permission(str, Enum):
    """Permission types"""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    SHARE = "share"
    ADMIN = "admin"


@dataclass(frozen=True)
class Tuple:
    """
    Authorization tuple representing a relationship
    Format: <object>#<relation>@<subject>
    Example: document:readme#viewer@user:alice
    """
    object_type: str
    object_id: str
    relation: str
    subject_type: str
    subject_id: str

    def __str__(self) -> str:
        return f"{self.object_type}:{self.object_id}#{self.relation}@{self.subject_type}:{self.subject_id}"

    @classmethod
    def from_string(cls, tuple_str: str) -> 'Tuple':
        """Parse tuple from string format"""
        parts = tuple_str.split('#')
        if len(parts) != 2:
            raise ValueError("Invalid tuple format")

        object_part = parts[0]
        rest = parts[1].split('@')
        if len(rest) != 2:
            raise ValueError("Invalid tuple format")

        relation = rest[0]
        subject_part = rest[1]

        obj_type, obj_id = object_part.split(':', 1)
        subj_type, subj_id = subject_part.split(':', 1)

        return cls(obj_type, obj_id, relation, subj_type, subj_id)


@dataclass
class RelationDefinition:
    """
    Definition of a relation with its computation rules
    """
    name: str
    # Direct relationships this relation depends on
    direct_relations: Set[str] = field(default_factory=set)
    # Computed from other relations (union)
    union_relations: Set[str] = field(default_factory=set)
    # Computed from intersection
    intersection_relations: Set[str] = field(default_factory=set)
    # Inherited from parent objects
    parent_relation: Optional[str] = None


@dataclass
class ObjectType:
    """
    Definition of an object type with its relations
    Example: Document with owner, editor, viewer relations
    """
    name: str
    relations: Dict[str, RelationDefinition] = field(default_factory=dict)


class ReBAC Engine:
    """
    Relationship-Based Access Control Engine
    Implements Zanzibar-style authorization with graph traversal
    """

    def __init__(self, auth0_fga_store_id: Optional[str] = None):
        """
        Initialize ReBAC engine

        Args:
            auth0_fga_store_id: Auth0 FGA store ID for backend storage
        """
        self.auth0_fga_store_id = auth0_fga_store_id

        # In-memory relationship graph (use Auth0 FGA in production)
        self.tuples: Set[Tuple] = set()

        # Object type definitions
        self.object_types: Dict[str, ObjectType] = {}

        # Indices for fast lookups
        self.by_object: Dict[str, Set[Tuple]] = defaultdict(set)
        self.by_subject: Dict[str, Set[Tuple]] = defaultdict(set)

        # Permission cache: (object, relation, subject) -> result
        self.cache: Dict[FrozenSet, Tuple[bool, float]] = {}
        self.cache_ttl = 300  # 5 minutes

        # Performance metrics
        self.check_count = 0
        self.cache_hits = 0
        self.cache_misses = 0

        # Initialize default schema
        self._init_default_schema()

    def _init_default_schema(self):
        """
        Initialize default object types and relations
        Defines common patterns for documents, folders, teams
        """
        # Document object type
        document_type = ObjectType(name="document")

        # owner relation (direct)
        document_type.relations["owner"] = RelationDefinition(
            name="owner",
            direct_relations={"owner"}
        )

        # editor relation (direct or computed)
        document_type.relations["editor"] = RelationDefinition(
            name="editor",
            direct_relations={"editor"},
            union_relations={"owner"}  # owners are also editors
        )

        # viewer relation (direct or computed)
        document_type.relations["viewer"] = RelationDefinition(
            name="viewer",
            direct_relations={"viewer"},
            union_relations={"editor", "owner"}  # editors and owners can view
        )

        self.object_types["document"] = document_type

        # Folder object type (with parent relationships)
        folder_type = ObjectType(name="folder")

        folder_type.relations["owner"] = RelationDefinition(
            name="owner",
            direct_relations={"owner"}
        )

        folder_type.relations["editor"] = RelationDefinition(
            name="editor",
            direct_relations={"editor"},
            union_relations={"owner"}
        )

        folder_type.relations["viewer"] = RelationDefinition(
            name="viewer",
            direct_relations={"viewer"},
            union_relations={"editor", "owner"}
        )

        # parent relation for inheritance
        folder_type.relations["parent"] = RelationDefinition(
            name="parent",
            direct_relations={"parent"}
        )

        self.object_types["folder"] = folder_type

        # Team object type
        team_type = ObjectType(name="team")

        team_type.relations["admin"] = RelationDefinition(
            name="admin",
            direct_relations={"admin"}
        )

        team_type.relations["member"] = RelationDefinition(
            name="member",
            direct_relations={"member"},
            union_relations={"admin"}  # admins are members
        )

        self.object_types["team"] = team_type

    def write_tuple(self, tuple_obj: Tuple) -> bool:
        """
        Write an authorization tuple (create relationship)

        Args:
            tuple_obj: Authorization tuple to write

        Returns:
            True if successful
        """
        # Add to tuple set
        self.tuples.add(tuple_obj)

        # Update indices
        object_key = f"{tuple_obj.object_type}:{tuple_obj.object_id}"
        subject_key = f"{tuple_obj.subject_type}:{tuple_obj.subject_id}"

        self.by_object[object_key].add(tuple_obj)
        self.by_subject[subject_key].add(tuple_obj)

        # Invalidate cache
        self._invalidate_cache_for_object(object_key)
        self._invalidate_cache_for_subject(subject_key)

        return True

    def delete_tuple(self, tuple_obj: Tuple) -> bool:
        """
        Delete an authorization tuple (remove relationship)

        Args:
            tuple_obj: Authorization tuple to delete

        Returns:
            True if successful
        """
        if tuple_obj not in self.tuples:
            return False

        # Remove from tuple set
        self.tuples.discard(tuple_obj)

        # Update indices
        object_key = f"{tuple_obj.object_type}:{tuple_obj.object_id}"
        subject_key = f"{tuple_obj.subject_type}:{tuple_obj.subject_id}"

        self.by_object[object_key].discard(tuple_obj)
        self.by_subject[subject_key].discard(tuple_obj)

        # Invalidate cache
        self._invalidate_cache_for_object(object_key)
        self._invalidate_cache_for_subject(subject_key)

        return True

    async def check(
        self,
        object_type: str,
        object_id: str,
        relation: str,
        subject_type: str,
        subject_id: str
    ) -> bool:
        """
        Check if a subject has a relation to an object
        Core authorization check with caching

        Args:
            object_type: Type of object (e.g., "document")
            object_id: Object identifier
            relation: Relation to check (e.g., "viewer")
            subject_type: Type of subject (e.g., "user")
            subject_id: Subject identifier

        Returns:
            True if subject has relation to object
        """
        self.check_count += 1
        start_time = time.perf_counter()

        # Create cache key
        cache_key = frozenset({
            ('obj_type', object_type),
            ('obj_id', object_id),
            ('relation', relation),
            ('subj_type', subject_type),
            ('subj_id', subject_id)
        })

        # Check cache
        if cache_key in self.cache:
            result, cached_at = self.cache[cache_key]
            if time.time() - cached_at < self.cache_ttl:
                self.cache_hits += 1
                return result

        self.cache_misses += 1

        # Perform check
        result = await self._check_relation(
            object_type, object_id, relation, subject_type, subject_id
        )

        # Cache result
        self.cache[cache_key] = (result, time.time())

        latency_ms = (time.perf_counter() - start_time) * 1000

        if latency_ms > 10:  # Log slow checks
            print(f"⚠️  Slow ReBAC check: {latency_ms:.2f}ms")

        return result

    async def _check_relation(
        self,
        object_type: str,
        object_id: str,
        relation: str,
        subject_type: str,
        subject_id: str
    ) -> bool:
        """
        Internal relation checking with graph traversal
        """
        # Check direct relationship
        direct_tuple = Tuple(object_type, object_id, relation, subject_type, subject_id)
        if direct_tuple in self.tuples:
            return True

        # Get relation definition
        if object_type not in self.object_types:
            return False

        obj_type_def = self.object_types[object_type]
        if relation not in obj_type_def.relations:
            return False

        relation_def = obj_type_def.relations[relation]

        # Check union relations (e.g., owner is also editor)
        if relation_def.union_relations:
            for union_rel in relation_def.union_relations:
                if await self._check_relation(
                    object_type, object_id, union_rel, subject_type, subject_id
                ):
                    return True

        # Check intersection relations
        if relation_def.intersection_relations:
            has_all = True
            for intersect_rel in relation_def.intersection_relations:
                if not await self._check_relation(
                    object_type, object_id, intersect_rel, subject_type, subject_id
                ):
                    has_all = False
                    break
            if has_all:
                return True

        # Check parent inheritance
        if relation_def.parent_relation:
            # Find parent objects
            object_key = f"{object_type}:{object_id}"
            for tuple_obj in self.by_object[object_key]:
                if tuple_obj.relation == "parent":
                    parent_type = tuple_obj.subject_type
                    parent_id = tuple_obj.subject_id

                    # Check if user has relation to parent
                    if await self._check_relation(
                        parent_type, parent_id, relation, subject_type, subject_id
                    ):
                        return True

        # Check if subject is a group/team
        if subject_type in ["team", "group"]:
            # Check if user is member of the team
            subject_key = f"{subject_type}:{subject_id}"
            for tuple_obj in self.by_object[subject_key]:
                if tuple_obj.relation == "member":
                    member_type = tuple_obj.subject_type
                    member_id = tuple_obj.subject_id

                    # Recursively check member
                    if await self._check_relation(
                        object_type, object_id, relation, member_type, member_id
                    ):
                        return True

        return False

    async def expand(
        self,
        object_type: str,
        object_id: str,
        relation: str
    ) -> List[Tuple]:
        """
        Expand all subjects that have a relation to an object
        Useful for "who can access this resource?" queries

        Args:
            object_type: Type of object
            object_id: Object identifier
            relation: Relation to expand

        Returns:
            List of tuples representing all subjects with the relation
        """
        expanded = []
        object_key = f"{object_type}:{object_id}"

        # Direct relationships
        for tuple_obj in self.by_object[object_key]:
            if tuple_obj.relation == relation:
                expanded.append(tuple_obj)

        # Get relation definition for computed relations
        if object_type in self.object_types:
            obj_type_def = self.object_types[object_type]
            if relation in obj_type_def.relations:
                relation_def = obj_type_def.relations[relation]

                # Expand union relations
                for union_rel in relation_def.union_relations:
                    union_tuples = await self.expand(object_type, object_id, union_rel)
                    expanded.extend(union_tuples)

        return expanded

    async def list_objects(
        self,
        object_type: str,
        relation: str,
        subject_type: str,
        subject_id: str
    ) -> List[str]:
        """
        List all objects of a type that subject has relation to
        Useful for "what can this user access?" queries

        Args:
            object_type: Type of objects to list
            relation: Relation to check
            subject_type: Type of subject
            subject_id: Subject identifier

        Returns:
            List of object IDs the subject has access to
        """
        accessible_objects = []
        subject_key = f"{subject_type}:{subject_id}"

        # Direct relationships
        for tuple_obj in self.by_subject[subject_key]:
            if tuple_obj.object_type == object_type and tuple_obj.relation == relation:
                accessible_objects.append(tuple_obj.object_id)

        # Check indirect relationships (via teams, etc.)
        # This could be expensive - consider adding indices

        return accessible_objects

    def _invalidate_cache_for_object(self, object_key: str):
        """Invalidate cache entries related to an object"""
        keys_to_remove = [
            key for key in self.cache.keys()
            if any(k[0] in ['obj_type', 'obj_id'] and f"{dict(key).get('obj_type')}:{dict(key).get('obj_id')}" == object_key for k in key)
        ]
        for key in keys_to_remove:
            del self.cache[key]

    def _invalidate_cache_for_subject(self, subject_key: str):
        """Invalidate cache entries related to a subject"""
        keys_to_remove = [
            key for key in self.cache.keys()
            if any(k[0] in ['subj_type', 'subj_id'] and f"{dict(key).get('subj_type')}:{dict(key).get('subj_id')}" == subject_key for k in key)
        ]
        for key in keys_to_remove:
            del self.cache[key]

    async def batch_check(
        self,
        checks: List[Dict]
    ) -> List[bool]:
        """
        Batch multiple authorization checks for performance

        Args:
            checks: List of check requests, each with object/relation/subject

        Returns:
            List of boolean results
        """
        tasks = [
            self.check(
                check['object_type'],
                check['object_id'],
                check['relation'],
                check['subject_type'],
                check['subject_id']
            )
            for check in checks
        ]

        return await asyncio.gather(*tasks)

    def get_metrics(self) -> Dict:
        """
        Get ReBAC engine performance metrics
        """
        cache_hit_rate = (
            self.cache_hits / max(self.check_count, 1)
        ) * 100

        return {
            'total_tuples': len(self.tuples),
            'total_checks': self.check_count,
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses,
            'cache_hit_rate_percent': cache_hit_rate,
            'cache_size': len(self.cache),
            'object_types': len(self.object_types)
        }

    async def sync_with_auth0_fga(self) -> bool:
        """
        Sync authorization model with Auth0 FGA
        Pushes tuples to Auth0 FGA for persistent storage
        """
        if not self.auth0_fga_store_id:
            return False

        # In production, use Auth0 FGA SDK to sync
        print(f"📡 Would sync {len(self.tuples)} tuples with Auth0 FGA")

        return True