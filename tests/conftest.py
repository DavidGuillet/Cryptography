"""Pytest configuration and shared fixtures."""

import pytest


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "streamlit: marks tests for the Streamlit app (run with pytest tests/test_app.py)"
    )
