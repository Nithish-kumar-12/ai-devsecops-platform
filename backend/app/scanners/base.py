"""
Base Scanner Interface for all security tools.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List


class BaseScanner(ABC):
    """Abstract base class for all scanner adapters."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the scanner (e.g. 'semgrep', 'gitleaks', 'osv-scanner', 'zap')."""
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        """Category: 'sast', 'secret', 'sca', 'dast'."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the scanner CLI or service is reachable."""
        pass

    @abstractmethod
    async def scan(self, target_path: str, **kwargs) -> List[Dict[str, Any]]:
        """
        Execute scan on target_path or target_url.
        Returns normalized list of finding dictionaries.
        """
        pass
