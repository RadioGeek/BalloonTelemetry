#!/usr/bin/python
#==============================================================================================================#
#                                                                                                              #
# getBalloonCfg -- function for reading INI file for Balloon variables                                         #
#                                                                                                              #
# Copyright (C) 2023 Mike Pate - K5MAP                                                                         #
#                                                                                                              #
# This program is free software; you can redistribute it and/or modify                                         #
# it under the terms of the GNU General Public License as published by                                         #
# the Free Software Foundation; either version 2 of the License, or                                            #
# (at your option) any later version.                                                                          #
#                                                                                                              #
# Reference https://www.pythonforbeginners.com/basics/convert-ini-file-to-dictionary-in-python                 #
#==============================================================================================================#
#
# if not already installled, use pip to install the following
#
#    pip install configupdater
#
#==============================================================================================================#

import argparse
import logging
import sys

from configupdater import ConfigUpdater

from constants import CFG_FILE


def getBalloonCfg() -> dict:
    """
    Retrieve parameters from a config file to track a balloon

    : param (none)
    : return: dict
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("bCallSign", help="Enter Balloon Callsign with SSID")
    args = parser.parse_args()

    cfgUpdater = ConfigUpdater()
    cfgUpdater.read(CFG_FILE)
    cfg = cfgUpdater.to_dict()
    return cfg[args.bCallSign.upper()]

#==============================================================================================================#

def checkCfg(bCallsign: str):
    """
    Verify each parameter for a balloon has been defined in the config file

    : param bCallsign: string
    : return: (none)
    """
    if 'tracker' not in bCallsign.keys():
        logging.error(" *** Item 'tracker' was NOT found in CFG file" )
        sys.exit( "\n*** Missing CFG item, check log file ***" )
    if 'uploadcallsign' not in bCallsign.keys():
        logging.error(" *** Item 'uploadcallsign' was NOT found in CFG file" )
        sys.exit( "\n*** Missing CFG item, check log file ***" )
    if 'wsprcallsign' not in bCallsign.keys():
        logging.error(" *** Item 'wsprcallsign' was NOT found in CFG file" )
        sys.exit( "\n*** Missing CFG item, check log file ***" )
    if 'ballooncallsign' not in bCallsign.keys():
        logging.error(" *** Item 'ballooncallsign' was NOT found in CFG file" )
        sys.exit( "\n*** Missing CFG item, check log file ***" )
    if 'timeslot' not in bCallsign.keys():
        logging.error(" *** Item 'timeslot' was NOT found in CFG file" )
        sys.exit( "\n*** Missing CFG item, check log file ***" )
    if 'comment' not in bCallsign.keys():
        logging.error(" *** Item 'comment' was NOT found in CFG file" )
        sys.exit( "\n*** Missing CFG item, check log file ***" )
    if 'uploadsite' not in bCallsign.keys():
        logging.error(" *** Item 'uploadsite' was NOT found in CFG file" )
        sys.exit( "\n*** Missing CFG item, check log file ***" )
    if 'telemetryfile' not in bCallsign.keys():
        logging.error(" *** Item 'telemetryfile' was NOT found in CFG file" )
        sys.exit( "\n*** Missing CFG item, check log file ***" )
    if 'ldatetime' not in bCallsign.keys():
        logging.error(" *** Item 'ldatetime' was NOT found in CFG file" )
        sys.exit( "\n*** Missing CFG item, check log file ***" )
    if bCallsign['tracker'] == 'U' and 'channel' not in bCallsign.keys():
        logging.error(" *** Item 'channel' was NOT found in CFG file" )
        sys.exit( "\n*** Missing CFG item, check log file ***" )
    if bCallsign['tracker'] == 'U' and 'band' not in bCallsign.keys():
        logging.error(" *** Item 'band' was NOT found in CFG file" )
        sys.exit( "\n*** Missing CFG item, check log file ***" )
    return

#==============================================================================================================#

def putBalloonCfg(Balloon: str, lDateTime: str):
    """
    Update balloon parameters in the config file

    : param Balloon: string, lDateTime: string
    : return: (none)
    """
    # save last datetime to ini
    cfgUpdater = ConfigUpdater()
    cfgUpdater.read(CFG_FILE)
    cfgUpdater[Balloon]['ldatetime'].value = lDateTime
    cfgUpdater.update_file()    
    return
