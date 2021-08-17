"""
Windows registry files scraping module

Uses regipy to extract the ADS configuration parameters, the Windows boot key
and the LSA secrets from the registry files.
"""

from typing import Dict

# TODO: Improve regipy typing annotations and mark it as typed
from regipy import RegistryHive  # type: ignore
from regipy.plugins import (  # type: ignore
    BootKeyPlugin,
    HostDomainNamePlugin,
    DomainSidPlugin,
    LocalSidPlugin,
)


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

    bootkey_plugin = BootKeyPlugin(system_hive)
    bootkey_plugin.run()

    for entry in bootkey_plugin.entries:
        bootkey = entry["key"]

    # STUB
    secrets["machine_password"] = bootkey.hex()

    return secrets
