"""Data models module for Zero-Trust API Security Engine.

Step 1 maintains an empty schema foundation so future steps can introduce
database models (API request logs, anomaly events, baseline profiles, security policies)
without requiring restructuring.
"""

from app.database.connection import Base

# Placeholder: Step 1 verifies database connectivity without table schema dependencies.
# Models for behavioral baselines, request logs, and anomaly events will be introduced in Step 2+.
__all__ = ["Base"]
