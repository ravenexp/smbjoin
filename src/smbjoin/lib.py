"""
Package as a Python library interface module

Defines the high level smbjoin package API functions.
"""

from typing import Dict, Union

import logging
import json

from smbjoin import reg, util

logger = logging.getLogger(__name__)


def get_ads_join_secrets(
    system_hive_path: str, security_hive_path: str, sam_hive_path: str
) -> Dict[str, str]:
    """
    Extracts the required ADS configuration parameters and secrets
    from the Windows registry files.
    """

    secrets = reg.get_registry_secrets(
        system_hive_path, security_hive_path, sam_hive_path
    )

    # Secrets dict structure:
    # {
    #    "hostname": "HOSTNAME",
    #    "ads_domain": "DOMAIN",
    #    "dns_domain": "domain.company.com",
    #    "domain_sid": "S-1-5-21-4-5-6",
    #    "machine_sid": "S-1-5-21-6-5-4",
    #    "machine_password": "QwErTyUiOp",
    # }

    logger.info("Using hostname: '%s'", secrets["hostname"])
    logger.info("Using ADS domain: '%s'", secrets["ads_domain"])
    logger.info("Using domain FQDN: '%s'", secrets["dns_domain"])
    logger.info("Using domain SID: '%s'", secrets["domain_sid"])
    logger.info("Using local machine SID: '%s'", secrets["machine_sid"])
    logger.info("Using machine password: '%s'", secrets["machine_password"])

    return secrets


def write_secrets_tdb(secrets_path: str, secrets: Dict[str, str]) -> None:
    """
    Writes the ADS member parameters and secrets into a Samba TDB database.

    Convert the key names and value data formats to the ones used by Samba.
    """

    tdb: Dict[str, Union[str, bytes]] = dict()

    # Store SEC_CHANNEL_TYPE constant
    sec_ch_key = "SECRETS/MACHINE_SEC_CHANNEL_TYPE/" + secrets["ads_domain"]
    tdb[sec_ch_key] = b"\x02\x00\x00\x00"

    # Store machine password string
    passwd_key = "SECRETS/MACHINE_PASSWORD/" + secrets["ads_domain"]
    tdb[passwd_key] = secrets["machine_password"]

    # Store DES salting principal
    realm = secrets["dns_domain"].upper()
    principal = "host/" + secrets["hostname"].lower() + "." + secrets["dns_domain"]
    salt_key = "SECRETS/SALTING_PRINCIPAL/DES/" + realm
    tdb[salt_key] = f"{principal}@{realm}"

    # Store domain SID + padding to 68 bytes
    domain_sid_key = "SECRETS/SID/" + secrets["ads_domain"]
    tdb[domain_sid_key] = util.sid_encode(secrets["domain_sid"]) + bytes(44)

    # Store local machine SID + padding to 68 bytes
    machine_sid_key = "SECRETS/SID/" + secrets["hostname"]
    tdb[machine_sid_key] = util.sid_encode(secrets["machine_sid"]) + bytes(44)

    util.tdb_save(tdb, secrets_path)


def write_secrets_json(secrets_path: str, secrets: Dict[str, str]) -> None:
    """
    Writes the ADS member parameters and secrets into a JSON text file.
    """

    with open(secrets_path, "wt") as secrets_fd:
        json.dump(secrets, secrets_fd, indent=4)
