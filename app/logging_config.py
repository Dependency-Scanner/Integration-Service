"""Logging configuration with IST timezone and Apache CLF format"""
import logging
import sys
from datetime import datetime
from logging import Formatter, StreamHandler

import pytz


class ISTFormatter(Formatter):
    """Custom formatter that uses IST timezone"""
    
    def formatTime(self, record, datefmt=None):
        """Format time in IST timezone"""
        ist = pytz.timezone("Asia/Kolkata")
        dt = datetime.fromtimestamp(record.created, ist)
        if datefmt:
            s = dt.strftime(datefmt)
        else:
            s = dt.strftime("%Y-%m-%d %H:%M:%S %z")
        return s


def setup_logging() -> logging.Logger:
    """Setup logging with IST timezone and structured JSON format"""
    logger = logging.getLogger("integration-service")
    logger.setLevel(logging.INFO)
    
    # Remove existing handlers
    logger.handlers = []
    
    # Console handler with IST timezone
    console_handler = StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    
    # Use structured JSON format for application logs
    formatter = ISTFormatter(
        '{"timestamp": "%(asctime)s", "service": "integration-service", '
        '"level": "%(levelname)s", "message": "%(message)s", '
        '"module": "%(name)s", "function": "%(funcName)s", "line": %(lineno)d}'
    )
    console_handler.setFormatter(formatter)
    
    logger.addHandler(console_handler)
    
    return logger

