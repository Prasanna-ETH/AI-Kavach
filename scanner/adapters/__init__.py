"""Adapter package for communicating with target LLM endpoints."""

from scanner.adapters.base import BaseAdapter
from scanner.adapters.rest_adapter import RESTAdapter
from scanner.adapters.playwright_adapter import PlaywrightAdapter

__all__ = ["BaseAdapter", "RESTAdapter", "PlaywrightAdapter"]
