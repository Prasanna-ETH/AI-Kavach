"""Adapter package for communicating with target LLM endpoints."""

from scanner.adapters.base import BaseAdapter
from scanner.adapters.rest_adapter import RESTAdapter

__all__ = ["BaseAdapter", "RESTAdapter"]
