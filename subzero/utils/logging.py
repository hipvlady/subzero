# Copyright (c) Subzero Development Team.
# Distributed under the terms of the Modified BSD License.

"""
Structured logging module for Subzero.

This module provides production-ready structured logging with JSON formatting,
context injection, and integration with monitoring systems.
"""

import json
import logging
import sys
from datetime import datetime
from enum import Enum


class LogLevel(str, Enum):
    """Log levels for Subzero."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class StructuredFormatter(logging.Formatter):
    """
    JSON structured logging formatter for production environments.

    This formatter outputs log messages as JSON objects with consistent structure,
    making them easy to parse and index in log aggregation systems.

    Attributes
    ----------
    include_exc_info : bool
        Whether to include exception information in logs

    Examples
    --------
    >>> import logging
    >>> handler = logging.StreamHandler()
    >>> handler.setFormatter(StructuredFormatter())
    >>> logger = logging.getLogger('myapp')
    >>> logger.addHandler(handler)
    >>> logger.info('Application started', extra={'version': '1.0.0'})
    """

    def __init__(self, include_exc_info: bool = True):
        """
        Initialize structured formatter.

        Parameters
        ----------
        include_exc_info : bool, default True
            Whether to include exception stack traces in log output
        """
        super().__init__()
        self.include_exc_info = include_exc_info

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

        Notes
        -----
        The output JSON object includes:
        - timestamp: ISO 8601 formatted UTC timestamp
        - level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        - logger: Logger name
        - message: Log message
        - module: Python module name
        - function: Function name
        - line: Line number
        - Extra fields from record attributes

        Examples
        --------
        >>> formatter = StructuredFormatter()
        >>> record = logging.LogRecord(
        ...     name='test', level=logging.INFO, pathname='', lineno=0,
        ...     msg='Test message', args=(), exc_info=None
        ... )
        >>> formatter.format(record)
        '{"timestamp": "2025-09-30T12:00:00.000000", "level": "INFO", ...}'
        """
        log_obj = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add process and thread information
        log_obj["process_id"] = record.process
        log_obj["thread_id"] = record.thread

        # Add extra context fields
        extra_fields = {
            "user_id": getattr(record, "user_id", None),
            "request_id": getattr(record, "request_id", None),
            "session_id": getattr(record, "session_id", None),
            "source_ip": getattr(record, "source_ip", None),
            "latency_ms": getattr(record, "latency_ms", None),
            "operation": getattr(record, "operation", None),
            "component": getattr(record, "component", None),
        }

        # Only include non-None extra fields
        for key, value in extra_fields.items():
            if value is not None:
                log_obj[key] = value

        # Add custom metadata if present
        if hasattr(record, "metadata"):
            log_obj["metadata"] = record.metadata

        # Add exception info if present
        if record.exc_info and self.include_exc_info:
            log_obj["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": self.formatException(record.exc_info),
            }

        return json.dumps(log_obj)


class SubzeroLogger:
    """
    Enhanced logger with structured logging support.

    This class wraps the standard Python logger with additional functionality
    for structured logging, context injection, and standardized message formats.

    Parameters
    ----------
    name : str
        Logger name (typically module name)
    level : LogLevel, default LogLevel.INFO
        Minimum log level to output
    structured : bool, default True
        Whether to use structured (JSON) formatting

    Examples
    --------
    >>> logger = SubzeroLogger(__name__)
    >>> logger.info("User authenticated", user_id="user123", latency_ms=45.2)
    >>> logger.error("Authentication failed", user_id="user456", error="invalid_token")
    """

    def __init__(self, name: str, level: LogLevel = LogLevel.INFO, structured: bool = True):
        """Initialize Subzero logger."""
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.value))
        self.structured = structured

        # Remove existing handlers
        self.logger.handlers.clear()

        # Add console handler
        handler = logging.StreamHandler(sys.stdout)

        if structured:
            handler.setFormatter(StructuredFormatter())
        else:
            formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            handler.setFormatter(formatter)

        self.logger.addHandler(handler)

    def _log(self, level: str, message: str, **kwargs):
        """
        Internal logging method with context injection.

        Parameters
        ----------
        level : str
            Log level
        message : str
            Log message
        **kwargs
            Additional context fields
        """
        extra = {}
        for key, value in kwargs.items():
            if key not in ["exc_info"]:
                extra[key] = value

        self.logger.log(getattr(logging, level), message, extra=extra, exc_info=kwargs.get("exc_info"))

    def debug(self, message: str, **kwargs):
        """
        Log debug message.

        Parameters
        ----------
        message : str
            Debug message
        **kwargs
            Additional context fields
        """
        self._log("DEBUG", message, **kwargs)

    def info(self, message: str, **kwargs):
        """
        Log info message.

        Parameters
        ----------
        message : str
            Info message
        **kwargs
            Additional context fields
        """
        self._log("INFO", message, **kwargs)

    def warning(self, message: str, **kwargs):
        """
        Log warning message.

        Parameters
        ----------
        message : str
            Warning message
        **kwargs
            Additional context fields
        """
        self._log("WARNING", message, **kwargs)

    def error(self, message: str, **kwargs):
        """
        Log error message.

        Parameters
        ----------
        message : str
            Error message
        **kwargs
            Additional context fields
        """
        self._log("ERROR", message, **kwargs)

    def critical(self, message: str, **kwargs):
        """
        Log critical message.

        Parameters
        ----------
        message : str
            Critical message
        **kwargs
            Additional context fields
        """
        self._log("CRITICAL", message, **kwargs)


def setup_logging(
    level: LogLevel = LogLevel.INFO,
    structured: bool = True,
    log_file: str | None = None,
) -> None:
    """
    Configure global logging for Subzero.

    This function sets up the root logger with appropriate handlers and formatters
    for production use. It supports both console and file output with structured
    (JSON) or standard formatting.

    Parameters
    ----------
    level : LogLevel, default LogLevel.INFO
        Minimum log level to output
    structured : bool, default True
        Whether to use structured (JSON) formatting
    log_file : str, optional
        Path to log file. If provided, logs are written to both console and file

    Examples
    --------
    >>> setup_logging(level=LogLevel.DEBUG, structured=True)
    >>> logger = logging.getLogger(__name__)
    >>> logger.info("Application started")

    >>> # With file output
    >>> setup_logging(level=LogLevel.INFO, log_file="/var/log/subzero.log")

    See Also
    --------
    SubzeroLogger : Enhanced logger with additional features

    Notes
    -----
    This function configures the root logger, which affects all loggers in the
    application. It should typically be called once at application startup.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.value))

    # Clear existing handlers
    root_logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)

    if structured:
        console_handler.setFormatter(StructuredFormatter())
    else:
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        console_handler.setFormatter(formatter)

    root_logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file)

        if structured:
            file_handler.setFormatter(StructuredFormatter())
        else:
            formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            file_handler.setFormatter(formatter)

        root_logger.addHandler(file_handler)


def get_logger(name: str) -> SubzeroLogger:
    """
    Get a Subzero logger instance.

    Parameters
    ----------
    name : str
        Logger name (typically __name__)

    Returns
    -------
    SubzeroLogger
        Configured logger instance

    Examples
    --------
    >>> logger = get_logger(__name__)
    >>> logger.info("Module initialized")
    """
    return SubzeroLogger(name)
