"""Custom exception classes"""
from typing import Optional


class ServiceException(Exception):
    """Base exception for service errors"""
    
    def __init__(
        self,
        message: str,
        detail: Optional[str] = None,
        status_code: int = 500,
    ):
        self.message = message
        self.detail = detail
        self.status_code = status_code
        super().__init__(self.message)

