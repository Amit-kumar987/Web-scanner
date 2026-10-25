"""Web Security Scanner: audit security headers, cookies and CORS."""
from .scanner import scan_target, score_and_grade, summarize

__all__ = ["scan_target", "score_and_grade", "summarize"]
