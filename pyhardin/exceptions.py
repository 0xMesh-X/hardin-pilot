from datetime import datetime


class PyhardinError(Exception):
    def __init__(self, message: str, code: str | None = None, details: dict | None = None):
        super().__init__(message)
        self.code = code
        self.details = details or {}
        self.timestamp = datetime.utcnow()


class ConfigError(PyhardinError):
    pass


class ScannerError(PyhardinError):
    pass


class AnalyzerError(PyhardinError):
    pass


class APIRateLimitError(AnalyzerError):
    def __init__(self, message: str = "API rate limit exceeded", retry_after: int = 60, details: dict | None = None):
        super().__init__(message, code="RATE_LIMIT", details=details)
        self.retry_after = retry_after


class ReporterError(PyhardinError):
    pass


class StateError(PyhardinError):
    pass
