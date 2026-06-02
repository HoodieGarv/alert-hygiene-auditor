"""Test suite for the alert-hygiene-auditor package.

All tests use SQLite in-memory databases for isolation; no external services
are required to run the suite.  Run with:

    pytest -v --tb=short --cov=src/auditor --cov-report=term-missing
"""
