"""Sidewinder Logging System.

Sets up centralized logging for the application.
Because this is a TUI app, stdout/stderr logging is disabled or redirected
to avoid corrupting the screen. All logs go to a rotating file.
"""
import logging
import os
from logging.handlers import RotatingFileHandler

# Default log format
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


def setup_logging(level: int = logging.INFO, log_file: str = "~/.sidewinder/sidewinder.log") -> None:
    """Configure the root logger for Sidewinder.
    
    Args:
        level: Logging level (e.g., logging.DEBUG, logging.INFO).
        log_file: Path to the log file.
    """
    expanded_path = os.path.expanduser(log_file)
    os.makedirs(os.path.dirname(expanded_path), exist_ok=True)
    
    # Create rotating file handler (10 MB max size, keep 3 backups)
    handler = RotatingFileHandler(
        expanded_path,
        maxBytes=10 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    
    formatter = logging.Formatter(LOG_FORMAT)
    handler.setFormatter(formatter)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Clear existing file handlers to avoid duplicates
    if root_logger.hasHandlers():
        for h in root_logger.handlers[:]:
            if isinstance(h, RotatingFileHandler):
                root_logger.removeHandler(h)
        
    root_logger.addHandler(handler)
    
    # Also log uncaught exceptions
    def handle_exception(exc_type, exc_value, exc_traceback):
        if exc_type is None:
            return
        if issubclass(exc_type, KeyboardInterrupt):
            import sys
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        root_logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

    import sys
    sys.excepthook = handle_exception
    
    root_logger.info("--- Sidewinder Logging Initialized ---")
