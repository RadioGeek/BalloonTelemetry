#!/usr/bin/python
#==============================================================================================================#
#                                                                                                              #
# aprsUtilies - collction of functions used by wsprAPRSBridge.py                                               #
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
#    pip install aprslib3
#    pip install maidenhead
#
#==============================================================================================================#
#
#  Convert QTH locator (or Maidenhead) to Lat/Lon:  https://www.giangrandi.org/electronics/radio/qthloccalc.shtml 
#  Formula to convert grid to lat/lon:  https://www.m0nwk.co.uk/how-to-convert-maidenhead-locator-to-latitude-and-longitude/
#  Solar calc:  https://pvlib-python.readthedocs.io/en/stable/_modules/pvlib/solarposition.html 

import calendar
import datetime
import math
import re  #regex
import time

import aprslib
import maidenhead as mh

#--------------------------------------------------------------------------------------------------------------#

def getPassCode(strCallsign: str) -> str:
    """
    Takes a CALLSIGN and returns passcode for APRS-IS

    : param strCallsign: ham callsign
    : return: 4-digit integer
    """
    PassCode = aprslib.passcode(strCallsign)
    return PassCode

#--------------------------------------------------------------------------------------------------------------#

def adjDateTime(sDateTime: str) -> str:
    """
    Takes a datetime string (YYYY-MM-DD HH:MM:SS) and adds 2 minutes

    : param sDateTime: string 
    : return: string
    """
    given_time = datetime.datetime.strptime(sDateTime, "%Y-%m-%d %H:%M:%S")
    future = given_time + datetime.timedelta(minutes=2)
    adjDT = future.strftime("%Y-%m-%d %H:%M:%S")
    return adjDT

#--------------------------------------------------------------------------------------------------------------#

def deldupWspr(spotlist: list[dict]) -> list[dict]:
    """
    Elminate duplicate records based on callsign & time

    : param spotlist: WSPR list of records
    : return: WSPR list
    """
    rc = 0
    rc_max = len(spotlist) - 1
    if rc_max > 1:
        while rc < rc_max:
            if (spotlist[rc]['time'] == spotlist[rc+1]['time']) and (spotlist[rc]['tx_sign'] == spotlist[rc+1]['tx_sign']):
                del spotlist[rc]
                rc_max -= 1
            else:
                rc += 1
    return spotlist

#--------------------------------------------------------------------------------------------------------------#

def deg_to_dms(deg: float, type='lat') -> str:
    """
    Convert decial degrees (99.9999) to degree, minute, seconds

    : param deg: float, type: lat or lon
    : return: string (DDDMM.SSc where c = N, S, W, E)
    """
    decimals, number = math.modf(deg)
    d = int(number)
    m = int(decimals * 60)
    s = (deg - d - m / 60) * 3600.00
    compass = {
        'lat': ('N','S'),
        'lon': ('E','W')
    }
    compass_str = compass[type][0 if d >= 0 else 1]
    dStr = f"{abs(d):02}" if type == 'lat' else f"{abs(d):03}"
    return f'{dStr}{abs(m):02}.{abs(s):02.0f}{compass_str}'

#--------------------------------------------------------------------------------------------------------------#

def GridtoLatLon(grid: str) -> tuple[float, float]:
    """
    Convert a 6-char maidenhead grid to latitude, longitude in middle of grid

    : param grid: string
    : return: lat, lon
    """
    return mh.to_location(grid, center=True)

#--------------------------------------------------------------------------------------------------------------#

def FreqToBand(freq: float) -> int:
    """
    Takes frequency (float) and returns integer portion of frequency

    : param freq: float
    : return: integer
    """
    # 14097093 example from WSPR frequency field
    # 10, 12, 15, 17, 20, 40, 80
    f = freq / 1000000
    if f < 4.0:
        band = 80
    elif f < 7.2:
        band = 40
    elif f < 10.2:
        band = 30
    elif f < 14.5:
        band = 20
    elif f < 18.2:
        band = 17
    elif f < 21.5:
        band = 15
    elif f < 24.99:
        band = 12
    elif f < 29.8:
        band = 10
    else:
        band = 0
    return band

#--------------------------------------------------------------------------------------------------------------#

def UTCtoEpoch(strDateTime: str, fCode: int) -> int:
    """
    Convert datetime string to Epoch time integer

    : param strDateTime: string, fcode: time format (i.e. 'YYYY-MM-DD HH:MM:SS')
    : return: integer
    """
    #intEpoch = calendar.timegm(time.strptime(strDateTime, '%Y-%m-%d %H:%M:%S'))
    intEpoch = calendar.timegm(time.strptime(strDateTime, fCode))
    return intEpoch

#--------------------------------------------------------------------------------------------------------------#

def reformatDateTime(strDateTime: str, offset: int) -> str:
    """
    Reformat datetime string and adjust new time string by offset

    : param strDateTime: string with format 'YYYY-MM-DD HH:MM:SS', offset: integer in seconds
    : return: string with format 'YYYY-MM-DDTHH:MM:SS.SSSZ'
    """
    t1 = datetime.datetime.strptime(strDateTime, "%Y-%m-%d %H:%M:%S")
    if offset > 0:
        t2 = t1 + datetime.timedelta(seconds=offset)
    else:
        t2 = t1
    #datetime1 = t1.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    return t2.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

#--------------------------------------------------------------------------------------------------------------#

def EpochtoUTC(intEpoch: int, fcode: int) -> str:
    """
    Convert Epoch integer to datetime string

    : param intEpoch: integer, fcode: format of output string (i.e. '%Y-%m-%d %H:%M:%S')
    : return: string
    """
    # strDateTime = datetime.datetime.fromtimestamp(intEpoch).strftime('%Y-%m-%d %H:%M:%S')
    strDateTime = datetime.datetime.utcfromtimestamp(intEpoch).strftime(fcode)
    return strDateTime

#--------------------------------------------------------------------------------------------------------------#

def VerifyCallsign(strCallSign: str) -> bool:
    """
    Verify callsign is a value ham radio callsign

    : param strCallSign: string
    : return: boolen (True, False)
    """
    callsign = strCallSign
    if (i := strCallSign.find('-')) > 0:
        callsign = strCallSign[0:i]
    if (i := strCallSign.find('/')) > 0:
        callsign = strCallSign[0:i]

    if (re.search('^(?:(?:[1-9][A-Z][A-Z]?)|(?:[A-Z][2-9A-Z]?))[0-9][A-Z]{1,3}$', callsign) ) :
        return True
    else:
        return False
    

"""
if __name__ == "__main__":
    #logging.info("Current Log Level : {}\n".format(logging.getLevel()))
    #sDateTime = '2023-08-02 23:58:00'
    #x = adjDateTime(sDateTime)
    #print(f" sDateTime = {sDateTime}, adjDateTime = {x}")
    
    lat, lon = GridtoLatLon('EL29fx')
    print(f"lat = {lat:.3f}, lon = {lon:.3f}")
"""