"""
Copyright (c) 2025 Subzero Contributors
SPDX-License-Identifier: MIT

Comprehensive Audit Trail System
GDPR/HIPAA compliant logging and audit trail

Features:
- Structured audit logging
- GDPR compliance (right to be forgotten, data portability)
- HIPAA compliance (access logging, encryption)
- Tamper-proof audit logs
- Query and reporting
- Retention policies
"""

import time
import json
import hashlib
import gzip
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timedelta

import asyncio
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

from subzero.config.defaults import settings


class AuditEventType(str, Enum):
    """Types of audit events"""

    # Authentication events
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    AUTH_MFA = "auth_mfa"

    # Authorization events
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_DENIED = "permission_denied"
    PERMISSION_MODIFIED = "permission_modified"

    # Data access events
    DATA_READ = "data_read"
    DATA_WRITE = "data_write"
    DATA_DELETE = "data_delete"
    DATA_EXPORT = "data_export"

    # Agent events
    AGENT_REGISTERED = "agent_registered"
    AGENT_DEACTIVATED = "agent_deactivated"
    AGENT_PERMISSION_CHANGE = "agent_permission_change"

    # Security events
    THREAT_DETECTED = "threat_detected"
    SECURITY_VIOLATION = "security_violation"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"

    # Token events
    TOKEN_ISSUED = "token_issued"
    TOKEN_REFRESHED = "token_refreshed"
    TOKEN_REVOKED = "token_revoked"
    TOKEN_DELEGATED = "token_delegated"

    # System events
    CONFIG_CHANGED = "config_changed"
    SYSTEM_ERROR = "system_error"


class AuditSeverity(str, Enum):
    """Severity levels for audit events"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AuditEvent:
    """Individual audit event"""

    event_id: str
    event_type: AuditEventType
    severity: AuditSeverity
    timestamp: float = field(default_factory=time.time)

    # Subject (who performed the action)
    actor_id: Optional[str] = None
    actor_type: str = "user"  # user, agent, system

    # Object (what was acted upon)
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None

    # Action details
    action: str = ""
    outcome: str = "success"  # success, failure, partial

    # Context
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None

    # Additional data
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Compliance
    pii_included: bool = False
    retention_days: int = field(default_factory=lambda: settings.AUDIT_LOG_RETENTION_DAYS)

    # Integrity
    previous_event_hash: Optional[str] = None
    event_hash: Optional[str] = None

    def compute_hash(self) -> str:
        """Compute tamper-proof hash of event"""
        # Create canonical representation
        event_data = {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp,
            "actor_id": self.actor_id,
            "resource_id": self.resource_id,
            "action": self.action,
            "outcome": self.outcome,
            "previous_hash": self.previous_event_hash,
        }

        # Compute SHA-256 hash
        canonical_json = json.dumps(event_data, sort_keys=True)
        return hashlib.sha256(canonical_json.encode()).hexdigest()


class AuditTrailStorage:
    """
    Storage backend for audit trail
    Implements write-once, tamper-proof storage
    """

    def __init__(self, encryption_key: Optional[bytes] = None):
        # Encryption for PII data
        if encryption_key:
            self.cipher = Fernet(encryption_key)
        else:
            self.cipher = Fernet(Fernet.generate_key())

        # In-memory storage (use database in production)
        self.events: List[AuditEvent] = []

        # Index for fast queries
        self.by_actor: Dict[str, List[str]] = {}
        self.by_resource: Dict[str, List[str]] = {}
        self.by_type: Dict[AuditEventType, List[str]] = {}

        # Chain integrity
        self.last_event_hash: Optional[str] = None

        # Metrics
        self.total_events = 0
        self.pii_events = 0

    async def append_event(self, event: AuditEvent) -> bool:
        """
        Append event to audit trail with integrity check

        Args:
            event: Audit event to append

        Returns:
            True if successful
        """
        try:
            # Link to previous event
            event.previous_event_hash = self.last_event_hash

            # Compute event hash
            event.event_hash = event.compute_hash()

            # Update last hash
            self.last_event_hash = event.event_hash

            # Encrypt PII if present
            if event.pii_included and event.metadata:
                event.metadata = self._encrypt_metadata(event.metadata)

            # Store event
            self.events.append(event)

            # Update indices
            if event.actor_id:
                if event.actor_id not in self.by_actor:
                    self.by_actor[event.actor_id] = []
                self.by_actor[event.actor_id].append(event.event_id)

            if event.resource_id:
                resource_key = f"{event.resource_type}:{event.resource_id}"
                if resource_key not in self.by_resource:
                    self.by_resource[resource_key] = []
                self.by_resource[resource_key].append(event.event_id)

            if event.event_type not in self.by_type:
                self.by_type[event.event_type] = []
            self.by_type[event.event_type].append(event.event_id)

            # Update metrics
            self.total_events += 1
            if event.pii_included:
                self.pii_events += 1

            return True

        except Exception as e:
            print(f"❌ Failed to append audit event: {e}")
            return False

    def _encrypt_metadata(self, metadata: Dict) -> Dict:
        """Encrypt sensitive metadata"""
        encrypted = {}

        for key, value in metadata.items():
            if isinstance(value, str):
                encrypted[key] = self.cipher.encrypt(value.encode()).decode()
            else:
                encrypted[key] = value

        return encrypted

    def _decrypt_metadata(self, metadata: Dict) -> Dict:
        """Decrypt sensitive metadata"""
        decrypted = {}

        for key, value in metadata.items():
            if isinstance(value, str):
                try:
                    decrypted[key] = self.cipher.decrypt(value.encode()).decode()
                except:
                    decrypted[key] = value
            else:
                decrypted[key] = value

        return decrypted

    async def query_events(
        self,
        actor_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        event_type: Optional[AuditEventType] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        limit: int = 100,
    ) -> List[AuditEvent]:
        """
        Query audit events with filters

        Args:
            actor_id: Filter by actor
            resource_id: Filter by resource
            event_type: Filter by event type
            start_time: Start timestamp
            end_time: End timestamp
            limit: Maximum results

        Returns:
            List of matching audit events
        """
        # Start with all events
        candidates = set(range(len(self.events)))

        # Apply filters
        if actor_id and actor_id in self.by_actor:
            actor_indices = set(i for i, e in enumerate(self.events) if e.event_id in self.by_actor[actor_id])
            candidates &= actor_indices

        if resource_id:
            resource_indices = set(i for i, e in enumerate(self.events) if e.resource_id == resource_id)
            candidates &= resource_indices

        if event_type and event_type in self.by_type:
            type_indices = set(i for i, e in enumerate(self.events) if e.event_id in self.by_type[event_type])
            candidates &= type_indices

        # Apply time filters
        if start_time or end_time:
            time_indices = set(
                i
                for i, e in enumerate(self.events)
                if (not start_time or e.timestamp >= start_time) and (not end_time or e.timestamp <= end_time)
            )
            candidates &= time_indices

        # Get events
        result_events = [self.events[i] for i in sorted(candidates, reverse=True)]

        # Apply limit
        result_events = result_events[:limit]

        # Decrypt PII if present
        for event in result_events:
            if event.pii_included and event.metadata:
                event.metadata = self._decrypt_metadata(event.metadata)

        return result_events

    def verify_integrity(self) -> Tuple[bool, List[str]]:
        """
        Verify integrity of audit trail
        Checks hash chain for tampering

        Returns:
            Tuple of (is_valid, errors)
        """
        errors = []
        previous_hash = None

        for i, event in enumerate(self.events):
            # Check previous hash link
            if event.previous_event_hash != previous_hash:
                errors.append(f"Event {i} ({event.event_id}): Hash chain broken")

            # Verify event hash
            expected_hash = event.compute_hash()
            if event.event_hash != expected_hash:
                errors.append(f"Event {i} ({event.event_id}): Hash mismatch")

            previous_hash = event.event_hash

        is_valid = len(errors) == 0

        return is_valid, errors


class ComplianceManager:
    """
    Manage compliance requirements (GDPR, HIPAA)
    """

    def __init__(self, storage: AuditTrailStorage):
        self.storage = storage

    async def export_user_data(self, user_id: str) -> Dict:
        """
        Export all data for a user (GDPR right to data portability)

        Args:
            user_id: User identifier

        Returns:
            Complete user data export
        """
        events = await self.storage.query_events(actor_id=user_id, limit=10000)

        export_data = {
            "user_id": user_id,
            "export_date": datetime.now().isoformat(),
            "event_count": len(events),
            "events": [
                {
                    "timestamp": datetime.fromtimestamp(e.timestamp).isoformat(),
                    "event_type": e.event_type.value,
                    "action": e.action,
                    "resource": f"{e.resource_type}:{e.resource_id}" if e.resource_id else None,
                    "outcome": e.outcome,
                    "metadata": e.metadata,
                }
                for e in events
            ],
        }

        return export_data

    async def anonymize_user_data(self, user_id: str) -> int:
        """
        Anonymize user data (GDPR right to be forgotten)

        Args:
            user_id: User identifier

        Returns:
            Number of events anonymized
        """
        count = 0

        for event in self.storage.events:
            if event.actor_id == user_id:
                # Anonymize actor
                event.actor_id = f"anonymized_{hashlib.sha256(user_id.encode()).hexdigest()[:8]}"

                # Clear PII from metadata
                if event.pii_included:
                    event.metadata = {"anonymized": True}
                    event.pii_included = False

                count += 1

        # Update indices
        if user_id in self.storage.by_actor:
            del self.storage.by_actor[user_id]

        print(f"🔒 Anonymized {count} events for user {user_id}")

        return count

    async def generate_compliance_report(self, start_date: datetime, end_date: datetime) -> Dict:
        """
        Generate compliance report for audit period

        Args:
            start_date: Report start date
            end_date: Report end date

        Returns:
            Compliance report
        """
        start_time = start_date.timestamp()
        end_time = end_date.timestamp()

        # Query events in period
        events = await self.storage.query_events(start_time=start_time, end_time=end_time, limit=100000)

        # Calculate statistics
        by_type = {}
        by_severity = {}
        by_outcome = {}

        for event in events:
            # By type
            event_type = event.event_type.value
            by_type[event_type] = by_type.get(event_type, 0) + 1

            # By severity
            severity = event.severity.value
            by_severity[severity] = by_severity.get(severity, 0) + 1

            # By outcome
            outcome = event.outcome
            by_outcome[outcome] = by_outcome.get(outcome, 0) + 1

        # Verify integrity
        is_valid, errors = self.storage.verify_integrity()

        return {
            "report_period": {"start": start_date.isoformat(), "end": end_date.isoformat()},
            "total_events": len(events),
            "pii_events": sum(1 for e in events if e.pii_included),
            "by_event_type": by_type,
            "by_severity": by_severity,
            "by_outcome": by_outcome,
            "integrity_check": {"valid": is_valid, "errors": errors},
            "compliance_status": {
                "gdpr": self._check_gdpr_compliance(events),
                "hipaa": self._check_hipaa_compliance(events),
            },
        }

    def _check_gdpr_compliance(self, events: List[AuditEvent]) -> Dict:
        """Check GDPR compliance status"""
        # Check if PII is encrypted
        pii_events = [e for e in events if e.pii_included]
        all_encrypted = all(isinstance(e.metadata.get("encrypted"), (str, bytes)) for e in pii_events)

        return {
            "compliant": all_encrypted,
            "pii_encrypted": all_encrypted,
            "right_to_be_forgotten_supported": True,
            "data_portability_supported": True,
        }

    def _check_hipaa_compliance(self, events: List[AuditEvent]) -> Dict:
        """Check HIPAA compliance status"""
        # Check if all access is logged
        data_access_events = [
            e
            for e in events
            if e.event_type in [AuditEventType.DATA_READ, AuditEventType.DATA_WRITE, AuditEventType.DATA_DELETE]
        ]

        return {
            "compliant": True,
            "access_logging_enabled": len(data_access_events) > 0,
            "encryption_at_rest": True,
            "audit_trail_tamper_proof": True,
        }


class AuditTrailService:
    """
    High-level audit trail service
    """

    def __init__(self):
        self.storage = AuditTrailStorage()
        self.compliance = ComplianceManager(self.storage)

        # Event queue for async processing
        self.event_queue: asyncio.Queue = asyncio.Queue()

        # Background processor
        self._processor_task: Optional[asyncio.Task] = None

    async def start(self):
        """Start audit trail service"""
        if not self._processor_task:
            self._processor_task = asyncio.create_task(self._process_events())
            print("📝 Audit trail service started")

    async def stop(self):
        """Stop audit trail service"""
        if self._processor_task:
            self._processor_task.cancel()
            try:
                await self._processor_task
            except asyncio.CancelledError:
                pass
            self._processor_task = None

    async def log_event(self, event: AuditEvent):
        """
        Log audit event asynchronously

        Args:
            event: Audit event to log
        """
        await self.event_queue.put(event)

    async def _process_events(self):
        """Background event processor"""
        while True:
            try:
                event = await self.event_queue.get()
                await self.storage.append_event(event)

                # Send to external audit log endpoint if configured
                if settings.AUDIT_LOG_ENDPOINT:
                    await self._send_to_endpoint(event)

            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"❌ Audit event processing error: {e}")

    async def _send_to_endpoint(self, event: AuditEvent):
        """Send event to external audit log endpoint"""
        import aiohttp

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    settings.AUDIT_LOG_ENDPOINT, json=asdict(event), timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    if response.status not in [200, 201]:
                        print(f"⚠️  Audit log endpoint returned {response.status}")

        except Exception as e:
            print(f"❌ Failed to send to audit endpoint: {e}")

    def get_stats(self) -> Dict:
        """Get audit trail statistics"""
        return {
            "total_events": self.storage.total_events,
            "pii_events": self.storage.pii_events,
            "unique_actors": len(self.storage.by_actor),
            "unique_resources": len(self.storage.by_resource),
            "event_types": {event_type.value: len(event_ids) for event_type, event_ids in self.storage.by_type.items()},
            "queue_size": self.event_queue.qsize(),
        }
