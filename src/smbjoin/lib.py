"""
Package as a Python library interface module

Defines the high level smbjoin package API functions.
"""

from typing import Dict

import json


def get_ads_join_secrets(
    system_hive_path: str, security_hive_path: str, sam_hive_path: str
) -> Dict[str, str]:
    """
    Extracts the required ADS configuration parameters and secrets
    from the Windows registry files.
    """

    # STUB
    return {
        "hostname": "HOSTNAME",
        "ads_domain": "DOMAIN",
        "dns_domain": "domain.company.com",
        "domain_sid": "S-1-2-3-4-5-6",
        "machine_sid": "S-1-2-3-6-5-4",
        "machine_password": "QwErTyUiOp",
    }


def write_secrets_tdb(secrets_path: str, secrets: Dict[str, str]) -> None:
    """
    Writes the ADS member parameters and secrets into a Samba TDB database.

    Convert the key names and value data formats to the ones used by Samba.
    """

    # STUB


def write_secrets_json(secrets_path: str, secrets: Dict[str, str]) -> None:
    """
    Writes the ADS member parameters and secrets into a JSON text file.
    """

    with open(secrets_path, "wt") as secrets_fd:
        json.dump(secrets, secrets_fd, indent=4)
