#!/usr/bin/python
"""
BalloonTelemetry.py - Collect WSPR spots and upload positions to APRS or SondeHub

This script collects WSPR spots from various types of balloon trackers and uploads
the position data to either APRS-IS or SondeHub tracking systems.

Supported trackers:
- Z: Zachtek (keeps callsign on both packets)
- A: AB5SS (requires decoding of 2nd packet)
- Q: QRP-Labs (requires decoding of 2nd packet)
- U: U4B (requires decoding of 2nd packet)

If not already installled, use pip to install the following

    pip install aprslib
    pip install pprint

Resources
       logging - https://www.youtube.com/watch?v=KSQ4KxCtsf8 
       aprslib - https://aprs-python.readthedocs.io/en/stable/
       SondeHub-APRS gateway - https://github.com/projecthorus/sondehub-aprs-gateway 

Copyright (C) 2023 Mike Pate - K5MAP
"""

import logging
import sys
from typing import Any, Dict, Tuple

import pprint

from BalloonCfg import getBalloonCfg, putBalloonCfg, checkCfg
from constants import __version__
from getAB5SS import getAB5SS
from getQRPLabs import getQRPLabs
from getU4B import getU4B
from getZachtek import getZachtek
from miscFunctions import VerifyCallsign 
from putAprsIS import putAprsIS
from putSondeHub import putSondeHub


def setup_logging(balloon_callsign: str) -> None:
    """Configure logging for the application.

    Args:
        balloon_callsign: The callsign used for the log filename
    """
    log_file = f"{balloon_callsign}.log"
    logging.basicConfig(
        filename=log_file,
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)-8s :%(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        filemode='w'
    )
    logging.info(f"Program version {__version__}")
    logging.info("#" + ("-" * 130))

def verify_python_version() -> None:
    """Verify that the script is running on Python 3.x."""
    if sys.version_info[0] != 3:
        logging.critical('Tested only on Python ver 3.x')
        raise RuntimeError('This script requires Python 3.x')
    logging.info('Python version check passed')

def verify_callsigns(config: Dict[str, Any]) -> None:
    """Verify that all callsigns in the configuration are valid.

    Args:
        config: Dictionary containing configuration parameters

    Raises:
        ValueError: If any callsign is invalid
    """
    callsigns = {
        'uploadcallsign': config['uploadcallsign'],
        'wsprcallsign': config['wsprcallsign'],
        'ballooncallsign': config['ballooncallsign']
    }

    for name, callsign in callsigns.items():
        if not VerifyCallsign(callsign):
            logging.error(f"Callsign {callsign} ({name}) is NOT valid")
            raise ValueError(f"Invalid callsign: {callsign}")
        logging.info(f"Callsign {callsign} ({name}) is valid")

def process_tracker_data(config: Dict[str, Any]) -> Tuple[int, Dict[str, Any], str]:
    """Process data from the selected tracker type.

    Args:
        config: Dictionary containing configuration parameters

    Returns:
        Tuple containing:
        - Return code (1 for success, -1 for failure)
        - Upload data dictionary
        - Last datetime processed

    Raises:
        ValueError: If an invalid tracker type is specified
    """
    tracker_type = config['tracker']
    tracker_handlers = {
        'Z': ('Zachtek', lambda: getZachtek(
            config['wsprcallsign'],
            config['uploadcallsign'],
            config['ballooncallsign'],
            int(config['timeslot']),
            config['ldatetime'],
            config['comment']
        )),
        'A': ('AB5SS pico', lambda: getAB5SS(config, config['ldatetime'])),
        'Q': ('QRP-Labs', lambda: getQRPLabs(config, config['ldatetime'])),
        'U': ('U4B', lambda: getU4B(config, config['ldatetime']))
    }

    if tracker_type not in tracker_handlers:
        logging.critical(f"Invalid tracker type: {tracker_type}")
        raise ValueError(f"Unsupported tracker type: {tracker_type}")

    name, handler = tracker_handlers[tracker_type]
    logging.info(f"Tracker selected = {tracker_type} ({name})")
    
    return handler()

def upload_data(config: Dict[str, Any], upload_data: Dict[str, Any]) -> int:
    """Upload data to the configured destination.

    Args:
        config: Dictionary containing configuration parameters
        upload_data: Data to be uploaded

    Returns:
        0 for testing mode or success, -1 for failure

    Raises:
        ValueError: If an invalid upload site is specified
    """
    upload_site = config['uploadsite']
    upload_handlers = {
        'S': ('SondeHub', lambda: putSondeHub(upload_data)),
        'A': ('APRS-IS', lambda: putAprsIS(config['wsprcallsign'], upload_data)),
        'T': ('Testing', lambda: logging.info("Testing mode - no upload attempted"))
    }

    if upload_site not in upload_handlers:
        logging.critical(f"Invalid upload site: {upload_site}")
        raise ValueError(f"Unsupported upload site: {upload_site}")

    name, handler = upload_handlers[upload_site]
    logging.info(f"Uploading to {name}")
    
    result = handler()
    return 0 if upload_site == 'T' else (result or 0)

def main() -> int:
    """Main function to process balloon telemetry data.

    Returns:
        0 for success, 1 for failure
    """
    try:
        # Load and validate configuration
        config = getBalloonCfg()
        print(f"*** {config['ballooncallsign']} CFG ***")
        pprint.pp(config, indent=2)

        # Setup logging and verify environment
        setup_logging(config['ballooncallsign'])
        verify_python_version()
        verify_callsigns(config)
        checkCfg(config)

        # Process tracker data
        return_code, upload_data, last_datetime = process_tracker_data(config)
        if return_code == -1:
            return 1

        # Upload data if available
        if return_code == 1:
            if upload_data(config, upload_data) == -1:
                return 1
            logging.info(f"Updating last datetime in config to: {last_datetime}")
            putBalloonCfg(config['ballooncallsign'], last_datetime)

        logging.info("Application completed successfully " + "*" * 111)
        return 0

    except Exception as e:
        logging.exception(f"Unexpected error occurred: {type(e).__name__} - {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())