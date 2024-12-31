#!/usr/bin/python
#==============================================================================================================#
#                                                                                                              #
# putSondeHub - routine to upload balloon telemetry data to SondeHub                                           #
#                                                                                                              #
# Copyright (C) 2023 Mike Pate - K5MAP                                                                         #
#                                                                                                              #
# This program is free software; you can redistribute it and/or modify                                         #
# it under the terms of the GNU General Public License as published by                                         #
# the Free Software Foundation; either version 2 of the License, or                                            #
# (at your option) any later version.                                                                          #
#                                                                                                              #
# This program is distributed in the hope that it will be useful,                                              #
# but WITHOUT ANY WARRANTY; without even the implied warranty of                                               #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                                                #
# GNU General Public License for more details.                                                                 #
#                                                                                                              #
# You should have received a copy of the GNU General Public License along                                      #
# with this program; if not, write to the Free Software Foundation, Inc.,                                      #
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.                                                  #
#                                                                                                              #
#==============================================================================================================#
#
# if not already installled, use pip to install the following
#
#    pip install requests
#    pip install pprint
#
#==============================================================================================================#

import logging
import traceback

import requests

#--------------------------------------------------------------------------------------------------------------#

def putSondeHub(aSondeData: list[dict]) -> int:
    """
    Function to build list of json data structure to upload to SondeHub

    : param aSondeData: list
    : return: integer
    """
    logging.info("#" + ("-"*130))
    logging.info(" Function putSondeHub start" )

    print(aSondeData)

    headers = {
      'accept': 'text/plain',
      'Content-Type': 'application/json',
    }

    #------------ upload new position data to SondeHub -----------------------------#
    try:
        response = requests.put('https://api.v2.sondehub.org/amateur/telemetry', headers=headers, json=aSondeData)
    except requests.exceptions.HTTPError as errh:
        logging.critical(f" Http Error: {errh}")
        return -1
    except requests.exceptions.ConnectionError as errc:
        logging.critical(f" Error Connecting: {errc}")
        return -1
    except requests.exceptions.Timeout as errt:
        logging.critical(f" Timeout Error: {errt}")
        return -1
    except requests.exceptions.RequestException as err:
        logging.critical(f" Unknown Error: {err}")
        return -1
    except:
        logging.exception(f" ***** Unknown Connect Error - {traceback.format_exc()}" )
        return -1

    #print("Response code = ", response.status_code)         # 200 = data accepted and saved; 500 = data not accepted
    logging.debug(f" Data to be uploaded -- {aSondeData}")
    logging.info(f" Number of records uploaded to SondeData = {len(aSondeData)}")

    return 0
