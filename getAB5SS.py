#!/usr/bin/python
#==============================================================================================================#
#                                                                                                              #
# getAB5SS                                                                                                     #
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
#    pip install urllib3
#
#==============================================================================================================#
#  Resources
#       Github for AB5SS pico tracker:  ???
#==============================================================================================================#

import logging
import traceback
import urllib.request, urllib.error
import json
import csv
from socket import *
import pprint

from SolarPos import *
from miscFunctions import *
from constants import __version__, SOFTWARE_NAME

#--------------------------------------------------------------------------------------------------------------#

def matchAB5SSRecords(jWSPRRec1: list[dict], jWSPRRec2: list[dict]) -> list[dict]:
    """
    Determine if 1st record has a matching 2nd record

    : param jWSPRRec1: list, jWSPRRec2: list
    : return: list
    """
    # determine if 2nd record avilable to process
    logging.info(f" Starting record matching process")

    print(f"jWSPRRec1 len = {len(jWSPRRec1)}")
    print(f"jWSPRRec2 len = {len(jWSPRRec2)}")

    aDateTime = []
    aMatch = []
    for i in range(0, len(jWSPRRec1)):
        try:
            aDateTime.index(jWSPRRec1[i]['time'])
        except ValueError:
            aDateTime.append(jWSPRRec1[i]['time'])
            sDateTime = adjDateTime(jWSPRRec1[i]['time'])           # find 2nd record time based on 1st record
            match = False
            for j, element in enumerate(jWSPRRec2):
                if element['time'] == sDateTime:
                    match = True
                    break
            # process both records
            if match == True:
                aMatch.append(jWSPRRec1[i])
                aMatch.append(jWSPRRec2[j])
                logging.debug(f" Found 1st record to process = {jWSPRRec1[i]['tx_sign']}, {jWSPRRec1[i]['time']}, {jWSPRRec1[i]['tx_loc']}, {jWSPRRec1[i]['band']}")
                logging.debug(f" Found 2nd record to process = {jWSPRRec2[j]['tx_sign']}, {jWSPRRec2[j]['time']}, {jWSPRRec2[j]['tx_loc']}, {jWSPRRec2[j]['band']}")
            else:
                logging.debug(f" Found 1st record to process but no match = {jWSPRRec1[i]['tx_sign']}, {jWSPRRec1[i]['time']}, {jWSPRRec1[i]['tx_loc']}, {jWSPRRec1[i]['band']}")

    return aMatch

#--------------------------------------------------------------------------------------------------------------#

def decodeAB5SS(Packet1: dict, Packet2: dict) -> dict:
    """
    Use both packets to decode telemetry data

    : param Packet1: dict, Packet2: dict
    : return: dict
    """
    # Telemetry data
    #   Grid -  concatenate the grid from the packet (XX99) with the last 2 characters from the 2nd packet callsign
    #   Channel # - first char of callsign is first digit of channel #; 3rd char of callsign is second digit of channel 
    #   Speed - ASCII value for 4th char of callsign from 2nd packet; add to ASCII value of "A"; multiple by 5
    #   Temp - ???
    #   Altitude - take power (dBm) from first packet & lookup alt1 in table; take power (dBm) from second packet & lookup
    #              alt2 in table; add both values together to obtain altitude in meters
    #   Sat status - ???
    PowerTable = {
        0: {'alt1' : 0, 'alt2' : 0},
        3: {'alt1' : 1000, 'alt2' : 60},
        7: {'alt1' : 2000, 'alt2' : 120},
        10: {'alt1' : 3000, 'alt2' : 180},
        13: {'alt1' : 4000, 'alt2' : 240},
        17: {'alt1' : 5000, 'alt2' : 300},
        20: {'alt1' : 6000, 'alt2' : 360},
        23: {'alt1' : 7000, 'alt2' : 420},
        27: {'alt1' : 8000, 'alt2' : 480},
        30: {'alt1' : 9000, 'alt2' : 540},
        33: {'alt1' : 10000, 'alt2' : 600},
        37: {'alt1' : 11000, 'alt2' : 660},
        40: {'alt1' : 12000, 'alt2' : 720},
        43: {'alt1' : 13000, 'alt2' : 780},
        47: {'alt1' : 14000, 'alt2' : 840},
        50: {'alt1' : 15000, 'alt2' : 900},
        53: {'alt1' : 16000, 'alt2' : 960},
        57: {'alt1' : 17000, 'alt2' : 0},
        60: {'alt1' : 18000, 'alt2' : 0},
    }

    Callsign1 = Packet1['tx_sign']
    sGrid = Packet1['tx_loc']
    Callsign2 = Packet2['tx_sign']
    Band = Packet1['band']
    Power1 = Packet1['power']
    Power2 = Packet2['power']
    
    # maidenhead grid
    Grid = sGrid + Callsign2[-2:].lower()

    # channel #
    digit1 = int(Callsign2[0]) * 10
    digit2 = int(Callsign2[2])
    Channel = digit1 + digit2

    # speed (??/hr)
    Speed = (ord(Callsign2[3]) - ord("A")) * 5

    # altitude (meters)
    Altitude = PowerTable[Power1]['alt1'] + PowerTable[Power2]['alt2']

    # Sat status
    a = ord(Callsign2[1])
    if (a - ord("0")) > 9:
        Sat = chr(((a - 7) % 3) + ord("0"))
    else:
        Sat = chr((a % 3) + ord("0"))

    # temp (celius)
    x = a
    if (x - ord("0")) > 9:
        Temp = (int(((x - ord(Sat) - 7)) / 3) * 5) - 30
    else:
        Temp = (int((x - ord(Sat)) / 3) * 5) - 30

    # Get the Sun's apparent location in the sky
    location = ( Packet1['tx_lat'], Packet1['tx_lon'] )
    date_time = datetime.datetime.strptime(Packet1['time'], "%Y-%m-%d %H:%M:%S")
    #when = (2022, 7, 4, 11, 20, 0, 0)
    when = (date_time.year, date_time.month, date_time.day, date_time.hour, date_time.minute, date_time.second, 0)
    #print(when)
    azimuth, elevation = SunPosition(when, location, True)
    #print(f"azimuth = {azimuth}, elevation = {elevation}")

    logging.debug(f" Telemetry data:  callsign1 = {Callsign1}, callsign2 = {Callsign2}, time = {Packet1['time']}, " +
                  f"channel = {Channel}, grid = {Grid}, sats = {Sat}, speed = {Speed}, alt(m) = {Altitude}, temp(c) = {Temp}, azimuth = {azimuth}, elevation = {elevation}")

    TelemetryData = {
        "callsign1" : Callsign1,
        "callsign2" : Callsign2,
        "time" : Packet1['time'],
        "channel" : Channel,
        "grid" : Grid,
        "sats" : Sat,
        "speed" : Speed,
        "altitude" : Altitude,
        "temp" : Temp,
        "azimuth" : azimuth,
        "elevation" : elevation
    }
    #print(TelemetryData)

    return TelemetryData

#--------------------------------------------------------------------------------------------------------------#

def convertCallsign(bCfg: dict) -> str:
    """
    Convert data to determine callsign of 2nd packet

    : param bCfg: dict
    : return callsign: string
    """
    # Process to convert data to callsign of 2nd packet
    #   1st char - take the first digit of channel #, convert to int and add ASCII code for 'zero'; then take result and convert back to char
    #   2nd char
    #      if temp minus (-30) / 5
    #   3rd char - take remainder of second digit of channel # divided by 10; add ASCII code for 'zero'; convert result back to char
    #   4th char - if speed greater than 129, assign "Z" else
    #      integer of speed / 5 plus ASCII of "A" then convert result back to string      
    #   5th char - take 5th char of Grid square
    #   6th char - take 6th char of Grid square
    gridSquare = "EL29KO"       # !!!!!!!!!!!!!!!!!!!!!!!!
    speed = 89                  # !!!!!!!!!!!!!!!!!!!!!!!!
    temp = 25                   # !!!!!!!!!!!!!!!!!!!!!!!!
    sat = 2                     # !!!!!!!!!!!!!!!!!!!!!!!!
    altitude = 13180            # !!!!!!!!!!!!!!!!!!!!!!!!

    # 1st char
    a = bCfg['channel'][0]      # first digit of channel #
    b = int(a)                  # convert to integer
    c = ord("0")                # convert "zero" to ASCII value
    d = chr(int(a) + ord("0"))
    char1 = d

    # 2nd char
    a = ((int((temp-(-30))/5) *3 ) + sat)
    if a > 9:
        b = ((int((temp-(-30))/5) *3 ) + 7 + sat + ord("0"))
    else:
        b = ((int((temp-(-30))/5) *3 ) + sat + ord("0"))
    char2 = chr(b)

    # 3rd char
    a = bCfg['channel'][1]      # second digit of channel #
    b = int(a)                  # convert to integer
    c = b % 10
    d = chr(c + ord("0"))
    char3 = d

    # 4th char
    if speed > 129:
        char4 = "Z"
    else:
        a = int(speed/5)
        b = chr(a + ord("A"))
        char4 = b

    # 5th char
    char5 = gridSquare[-2]

    # 6th char
    char6 = gridSquare[-1]

    nCallsign = char1 + char2 + char3 + char4 + char5 + char6
    logging.info(f" 2nd packet Callsign = {nCallsign}")

    return nCallsign

#--------------------------------------------------------------------------------------------------------------#

def getAB5SS(bCfg: dict, last_date: str):
    """
    Function to retrieve WSPR records, match 2 records, create data structure and then upload to APRS-IS or SondeHub

    : param bCfg: dict, last_date: string (YYYY-MM-DD HH:MM:SS)
    : return: integer, dict, string
    """
    wCallsign = bCfg['wsprcallsign']
    BalloonCallsign = bCfg['ballooncallsign']
    logging.info("#" + ("-"*130))
    logging.info(" Function AB5SS start" )

    # Takes a CALLSIGN and gets WSPR spots for that callsign from WSPR Live
    query = "SELECT * FROM rx WHERE tx_sign='" + wCallsign + "' AND time > '" + last_date + "' ORDER BY time"
    #query = "SELECT * FROM rx WHERE tx_sign='" + wCallsign + "' AND time > '2022-10-21 00:00:00' AND time < '2022-10-22 00:00:00' ORDER BY time"

    logging.info(" SQL query = " + query )

    url = "https://db1.wspr.live/?query=" + urllib.parse.quote_plus(query + " FORMAT JSON")

    # download contents from wspr.live
    try:
        contents = urllib.request.urlopen(url).read()
    except urllib.error.URLError as erru:
        logging.critical(f" URL error - {erru.reason}" )
        return -1, None, None
    except urllib.error.HTTPError as errh:
        logging.critical(f" HTTP error - {errh}" )
        return -1, None, None
    except socket.timeout as errt:
        logging.critical(f" Connection timeout - {errt}" )
        return -1, None, None
    except:
        logging.critical(f" Unexpected error calling URL - {traceback.format_exc()}" )
        return -1, None, None

    # check on how many rows returned
    jWsprData = json.loads(contents.decode("UTF-8"))["data"]
    record_count = len(jWsprData)
    logging.info(f" WSPR Live records downloaded = {record_count}" )
    if record_count < 1:
        logging.warning(" Exit function, insufficient WSPR records to process" )
        return 0, None, None

    pprint.pp(jWsprData)
    print("-"*40)

    callsign = jWsprData[record_count-1]['tx_sign']
    grid = jWsprData[record_count-1]['tx_loc']
    band = jWsprData[record_count-1]['band']
    #query = "SELECT * FROM rx WHERE tx_sign <> '" + callsign + "' AND band=" + str(band) + " AND tx_loc='" + grid + "' AND time > '2022-10-21 00:00:00' AND time < '2022-10-22 00:00:00' ORDER BY time"
    query = "SELECT * FROM rx WHERE tx_sign <> '" + callsign + "' AND band=" + str(band) + " AND tx_loc='" + grid + "' AND time > '" + last_date + "' ORDER BY time"

    logging.info(" SQL query = " + query )

    url = "https://db1.wspr.live/?query=" + urllib.parse.quote_plus(query + " FORMAT JSON")

    # download contents from wspr.live
    try:
        contents = urllib.request.urlopen(url).read()
    except urllib.error.URLError as erru:
        logging.critical(f" URL error - {erru.reason}" )
        return -1, None, None
    except urllib.error.HTTPError as errh:
        logging.critical(f" HTTP error - {errh}" )
        return -1, None, None
    except socket.timeout as errt:
        logging.critical(f" Connection timeout - {errt}" )
        return -1, None, None
    except:
        logging.critical(f" Unexpected error calling URL - {traceback.format_exc()}" )
        return -1, None, None

    jWsprData2 = json.loads(contents.decode("UTF-8"))["data"]
    record_count = len(jWsprData2)
    logging.info(f" WSPR Live records downloaded = {record_count}" )
    if record_count < 1:
        logging.warning(" Exit function, insufficient matching WSPR records to process" )
        return 0, None, None

    #pprint.pp(jWsprData2)

    # process records downloaded and match
    aMatch = matchAB5SSRecords(jWsprData, jWsprData2)
    logging.info(f" Number of matched records = {len(aMatch)}" )
    if len(aMatch) < 2:
        # no matches to process
        logging.warning(f" Insuficient number of records to process" )
        return 0, None, None

    # decode records
    jDecodedData = {}
    jUploadData = []
    for i in range(0, len(aMatch), 2):
        jDecodedData[i] = decodeAB5SS(aMatch[i], aMatch[i+1])

        # reformat time from WSPR format to Zulu
        datetime1 = reformatDateTime(aMatch[i]['time'], 0)
        datetime2 = reformatDateTime(aMatch[i]['time'], 10)

        # add telemetry data
        # build strComment  channel, Sats?, voltage?, alt(m), 0C?, grid, callsign2, callsign1, comment
        #strComment = str(jDecodedData[i]['channel']) + " Sats " + jDecodedData[i]['sats'] + str(jDecodedData[i]['altitude']) + "m " 
        #strComment += str(jDecodedData[i]['temp']) + "C " + jDecodedData[i]['grid'] + " " + jDecodedData[i]['callsign2'] + " " + jDecodedData[i]['callsign1'] + " " + bCfg['comment']
        strComment = str(" GPS " + jDecodedData[i]['sats'] + " " + jDecodedData[i]['temp']) + "C " str(jDecodedData[i]['altitude']) + "m " 
        strComment += str(jDecodedData[i]['speed']) + "kt " + jDecodedData[i]['grid'] + " " + jDecodedData[i]['callsign2'] + " " + bCfg['comment']
        
        # put data into jUploadData format for uploading
        lat, lon = GridtoLatLon(jDecodedData[i]['grid'])
        JSON = {"software_name" : SOFTWARE_NAME, "software_version" : __version__, "uploader_callsign" : bCfg['uploadcallsign'], "time_received" : datetime1,
            "payload_callsign" : BalloonCallsign, "datetime" : datetime2, "lat" : round(lat,3), "lon" : round(lon,3), "alt" : jDecodedData[i]['altitude'], 
            "sats" : jDecodedData[i]['sats'], "temp" : jDecodedData[i]['temp'], "grid" : jDecodedData[i]['grid'], "comment" : strComment}
        jUploadData.append(JSON)


    logging.info(f" Decoding completed, record count = {len(jUploadData)}" )
    pprint.pp(jUploadData, indent=2)
 
    # create data file for John
    if bCfg['telemetryfile'] == 'Y':
        logging.info(f" Saving telemetry data to CSV file" )
        #pprint.pp(jDecodedData, indent=2)
        outputFilename = BalloonCallsign + ".csv"
        with open(outputFilename, 'w') as file:
            csv_file = csv.writer(file)
            csv_file.writerow(jDecodedData[0].keys())     # write header from keys
            for item in jDecodedData:
                csv_file.writerow(jDecodedData[item].values())

    return 1, jUploadData, aMatch[i]['time']

    """
    >>> dicts = [
        { "name": "Tom", "age": 10 },
        { "name": "Mark", "age": 5 },
        { "name": "Pam", "age": 7 },
        { "name": "Dick", "age": 12 }
    ]
    >>> next((item for item in dicts if item["name"] == "Pam"), False)
    {'name': 'Pam', 'age': 7}
    >>> next((item for item in dicts if item["name"] == "Sam"), False)
    False
    >>>

    next((item for item in dicts if item.get("name") and item["name"] == "Pam"), None)

    for i in range(len(jWSPRRec1)):
        if next((item for item in aResults if item['time'] == jWSPRRec1[i]['time']), False) == False:
            aResults.append(jWSPRRec1[i])

    print(f"aResults = {aResults}")
    print(f"aResults len = {len(aResults)}")
    """
