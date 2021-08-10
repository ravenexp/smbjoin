"""
Command line interface entry point functions
"""

import argparse
import logging
import os
import sys

import smbjoin

logger = logging.getLogger(__name__)


def net_ads_join() -> None:
    """
    The main `smb-net-ads-join` script entry point

    This entry point function only handles the command line arguments
    parsing and validation. It also sets up logging for the whole package.
    """

    parser = argparse.ArgumentParser(prog="smb-net-ads-join")
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="print intermediate results and debug info",
    )
    parser.add_argument(
        "-V", "--version", action="version", version=smbjoin.__version__
    )
    parser.add_argument(
        "-J",
        "--json",
        action="store_true",
        help="generate 'secrets.json' file in place of 'secrets.tdb'",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        default="secrets.tdb",
        help="generated 'secrets.tdb' file name and location",
    )
    parser.add_argument(
        "DIR",
        help="Windows registry hive files directory (e.g. '/Windows/System32/config')",
    )

    args = parser.parse_args()

    loglevel = (
        logging.DEBUG
        if args.verbose > 1
        else logging.INFO
        if args.verbose == 1
        else logging.WARNING
    )

    logging.basicConfig(stream=sys.stdout, level=loglevel)

    logger.debug("Executing smb-net-ads-join with args: %s", args)
    logger.info("Looking for Windows registry hive files in '%s'", args.DIR)

    system_hive_path = os.path.join(args.DIR, "SYSTEM")
    security_hive_path = os.path.join(args.DIR, "SECURITY")
    sam_hive_path = os.path.join(args.DIR, "SAM")

    try:
        with open(system_hive_path, "rb"):
            logger.info("Found SYSTEM hive file at '%s'", system_hive_path)
    except OSError as err:
        logger.critical("Probing SYSTEM hive file failed: %s", err)
        print("error: SYSTEM hive file not found", file=sys.stderr)
        sys.exit(401)

    try:
        with open(security_hive_path, "rb"):
            logger.info("Found SECURITY hive file at '%s'", security_hive_path)
    except OSError as err:
        logger.critical("Probing SECURITY hive file failed: %s", err)
        print("error: SECURITY hive file not found", file=sys.stderr)
        sys.exit(402)

    try:
        with open(sam_hive_path, "rb"):
            logger.info("Found SAM hive file at '%s'", sam_hive_path)
    except OSError as err:
        logger.critical("Probing SAM hive file failed: %s", err)
        print("error: SAM hive file not found", file=sys.stderr)
        sys.exit(403)

    # STUB
    print("Joined 'host' to realm 'domain.com'")
