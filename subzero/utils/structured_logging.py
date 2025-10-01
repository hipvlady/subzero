# Copyright (c) Subzero Development Team.
# Distributed under the terms of the Modified BSD License.

"""
Structured Logging for Production

This module provides JSON-structured logging for production environments,
enabling easy parsing and analysis of logs in centralized logging systems.
"""

import json
import logging
import sys
from datetime import datetime
from typing import Any, Dict, Optional


class StructuredFormatter(logging.Formatter):
    """
    JSON structured logging formatter for production.

    This formatter outputs log messages as JSON objects, making them
    easily parseable by log aggregation systems like ELK, Splunk, or
    CloudWatch.

    Parameters
    ----------
    include_extras : bool, default True
        Whether to include extra fields from log records

    Examples
    --------
    >>> handler = logging.StreamHandler()
    >>> handler.setFormatter(StructuredFormatter())
    >>> logger = logging.getLogger(__name__)
    >>> logger.addHandler(handler)
    >>> logger.info("Request processed", extra={"latency_ms": 42})
    """

    def __init__(self, include_extras: bool = True):
        """
        Initialize structured formatter.

        Parameters
        ----------
        include_extras : bool, default True
            Whether to include extra fields
        """
        super().__init__()
        self.include_extras = include_extras

    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record as JSON string.

        Parameters
        ----------
        record : logging.LogRecord
            Log record to format

        Returns
        -------
        str
            JSON-formatted log message
        """
        log_obj: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "thread": record.thread,
            "thread_name": record.threadName,
        }

        # Add process information
        log_obj["process"] = {
            "id": record.process,
            "name": record.processName,
        }

        # Add extra fields if enabled
        if self.include_extras:
            # Common extra fields for API requests
            if hasattr(record, "user_id"):
                log_obj["user_id"] = record.user_id
            if hasattr(record, "request_id"):
                log_obj["request_id"] = record.request_id
            if hasattr(record, "latency_ms"):
                log_obj["latency_ms"] = record.latency_ms
            if hasattr(record, "status_code"):
                log_obj["status_code"] = record.status_code
            if hasattr(record, "method"):
                log_obj["method"] = record.method
            if hasattr(record, "path"):
                log_obj["path"] = record.path
            if hasattr(record, "ip_address"):
                log_obj["ip_address"] = record.ip_address

        # Add exception info if present
        if record.exc_info:
            log_obj["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": self.formatException(record.exc_info),
            }

        # Add stack info if present
        if record.stack_info:
            log_obj["stack_info"] = record.stack_info

        return json.dumps(log_obj)


def setup_logging(
    log_level: str = "INFO",
    structured: bool = True,
    audit_log_file: Optional[str] = None,
) -> None:
    """
    Configure production logging.

    Sets up logging with structured JSON output for production environments
    or human-readable format for development.

    Parameters
    ----------
    log_level : str, default "INFO"
        Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    structured : bool, default True
        Use structured JSON logging (False for human-readable)
    audit_log_file : str, optional
        Path to audit log file for compliance

    Examples
    --------
    >>> # Production configuration
    >>> setup_logging(log_level="INFO", structured=True)

    >>> # Development configuration
    >>> setup_logging(log_level="DEBUG", structured=False)

    >>> # With audit trail
    >>> setup_logging(
    ...     log_level="INFO",
    ...     structured=True,
    ...     audit_log_file="/var/log/subzero/audit.log"
    ... )
    """
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Console handler with structured or standard output
    console_handler = logging.StreamHandler(sys.stdout)

    if structured:
        console_handler.setFormatter(StructuredFormatter())
    else:
        # Human-readable format for development
        format_str = "%(asctime)s - %(name)s - %(levelname)s - " "%(funcName)s:%(lineno)d - %(message)s"
        console_handler.setFormatter(logging.Formatter(format_str))

    root_logger.addHandler(console_handler)

    # Optional: File handler for audit trail
    if audit_log_file:
        try:
            file_handler = logging.FileHandler(audit_log_file)
            file_handler.setFormatter(StructuredFormatter())
            file_handler.setLevel(logging.INFO)  # Always INFO for audit
            root_logger.addHandler(file_handler)
        except (IOError, OSError) as e:
            root_logger.warning(f"Could not create audit log file: {e}")


class RequestLogger:
    """
    Context manager for request logging.

    Provides automatic logging of request start, end, duration,
    and any exceptions that occur during request processing.

    Parameters
    ----------
    logger : logging.Logger
        Logger instance to use
    request_id : str
        Unique request identifier
    method : str
        HTTP method
    path : str
        Request path
    user_id : str, optional
        Authenticated user ID

    Examples
    --------
    >>> logger = logging.getLogger(__name__)
    >>> with RequestLogger(logger, "req-123", "GET", "/api/users"):
    ...     # Process request
    ...     pass
    """

    def __init__(
        self,
        logger: logging.Logger,
        request_id: str,
        method: str,
        path: str,
        user_id: Optional[str] = None,
    ):
        """Initialize request logger context."""
        self.logger = logger
        self.request_id = request_id
        self.method = method
        self.path = path
        self.user_id = user_id
        self.start_time: Optional[float] = None

    def __enter__(self):
        """Log request start."""
        import time

        self.start_time = time.perf_counter()

        extra = {
            "request_id": self.request_id,
            "method": self.method,
            "path": self.path,
        }
        if self.user_id:
            extra["user_id"] = self.user_id

        self.logger.info("Request started", extra=extra)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Log request completion."""
        import time

        latency_ms = (time.perf_counter() - self.start_time) * 1000

        extra = {
            "request_id": self.request_id,
            "method": self.method,
            "path": self.path,
            "latency_ms": latency_ms,
        }
        if self.user_id:
            extra["user_id"] = self.user_id

        if exc_type is None:
            extra["status_code"] = 200
            self.logger.info("Request completed", extra=extra)
        else:
            extra["status_code"] = 500
            self.logger.error(
                f"Request failed: {exc_val}",
                extra=extra,
                exc_info=(exc_type, exc_val, exc_tb),
            )

        return False  # Don't suppress exception


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance.

    Parameters
    ----------
    name : str
        Logger name (typically __name__)

    Returns
    -------
    logging.Logger
        Configured logger instance

    Examples
    --------
    >>> logger = get_logger(__name__)
    >>> logger.info("Application started")
    """
    return logging.getLogger(name)
