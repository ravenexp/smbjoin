"""
Offline Windows AD domain join tool for Samba
"""

from .lib import get_ads_join_secrets, write_secrets_tdb, write_secrets_json

__version__ = "0.1.1"
