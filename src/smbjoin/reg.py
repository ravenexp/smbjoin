"""
Windows registry files scraping module

Uses regipy to extract the ADS configuration parameters, the Windows boot key
and the LSA secrets from the registry files.
"""

from typing import Dict

import logging

# TODO: Improve regipy typing annotations and mark it as typed
from regipy import RegistryHive  # type: ignore
from regipy.exceptions import RegistryKeyNotFoundException  # type: ignore
from regipy.plugins import (  # type: ignore
    BootKeyPlugin,
    HostDomainNamePlugin,
    DomainSidPlugin,
    LocalSidPlugin,
)

from smbjoin import crypt

# Encrypted LSA encryption key location
LSA_ENC_KEY_PATH = r"\Policy\PolEKList"

# Encrypted machine account password location
LSA_MACHINE_ACC_PATH = r"\Policy\Secrets\$MACHINE.ACC\CurrVal"

logger = logging.getLogger(__name__)


def get_registry_secrets(
    system_hive_path: str, security_hive_path: str, sam_hive_path: str
) -> Dict[str, str]:
    """
    Extracts the ADS configuration parameters, the Windows boot key
    and the LSA secrets from the SYSTEM, SECURITY and SAM registry hives.
    """

    system_hive = RegistryHive(system_hive_path)
    security_hive = RegistryHive(security_hive_path)
    sam_hive = RegistryHive(sam_hive_path)

    secrets: Dict[str, str] = dict()

    dns_names_plugin = HostDomainNamePlugin(system_hive)
    dns_names_plugin.run()

    for entry in dns_names_plugin.entries:
        if entry["domain"] is not None:
            secrets["hostname"] = entry["hostname"]
            secrets["dns_domain"] = entry["domain"]

    domain_sid_plugin = DomainSidPlugin(security_hive)
    domain_sid_plugin.run()

    for entry in domain_sid_plugin.entries:
        if entry["domain_sid"] is not None:
            secrets["ads_domain"] = entry["domain_name"]
            secrets["domain_sid"] = entry["domain_sid"]

    local_sid_plugin = LocalSidPlugin(sam_hive)
    local_sid_plugin.run()

    for entry in local_sid_plugin.entries:
        if entry["machine_sid"] is not None:
            secrets["machine_sid"] = entry["machine_sid"]

    # Extract Windows Boot Key for the LSA secrets decryption
    bootkey_plugin = BootKeyPlugin(system_hive)
    bootkey_plugin.run()

    for entry in bootkey_plugin.entries:
        bootkey = entry["key"]

    logger.debug("Found BootKey: %s", bootkey.hex())

    # Extract the encrypted LSA encryption key
    lsa_ek_key = security_hive.get_key(LSA_ENC_KEY_PATH)
    lsa_enc_key = lsa_ek_key.get_value()

    logger.debug("Found raw LSAEncKey: %s", lsa_enc_key.hex())

    # Decrypt the LSA encryption key secret first
    lsa_dec_key = crypt.lsa_decrypt_secret(lsa_enc_key, bootkey)

    # Extract the 256-bit LSA encryption key from the decrypted secret plaintext
    lsa_key = lsa_dec_key[68:100]

    logger.debug("Decrypted LSAKey: %s", lsa_key.hex())

    # Extract the encrypted machine account password
    try:
        machine_acc_key = security_hive.get_key(LSA_MACHINE_ACC_PATH)
    except RegistryKeyNotFoundException as err:
        raise FileNotFoundError("Machine account password key does not exist") from err

    machine_acc = machine_acc_key.get_value()

    logger.debug("Found raw $MACHINE.ACC: %s", machine_acc.hex())

    # Decrypt the machine account secret using the obtained LSA key
    machine_dec = crypt.lsa_decrypt_secret(machine_acc, lsa_key)

    logger.debug("Decrypted $MACHINE.ACC: %s", machine_dec.hex())

    # Extract the UTF-16 encoded machine account password
    # from the decrypted secret plaintext
    machine_password = machine_dec[16:-16].decode("utf-16-le")

    logger.debug("Decrypted machine password: %s", machine_password)

    secrets["machine_password"] = machine_password

    return secrets
