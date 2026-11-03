"""Local, non-executing VBA and workbook inspection."""

from .analyzer import analyze_source, analyze_workbook
from .database import ReportStore

__all__ = ["ReportStore", "analyze_source", "analyze_workbook"]
