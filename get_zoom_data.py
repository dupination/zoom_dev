#!/usr/bin/env python3
# get_zoom_data.py
# Ryan Dupuy 1-2022

# API
# Extreme: https://documentation.extremenetworks.com/Extreme%20Campus%20Controller/v5.46/API/index_gateway_api.html
# Extreme: https://extremeportal.force.com/ExtrArticleDetail?an=000077243
# Zoom: https://marketplace.zoom.us/docs/api-reference/phone/methods

import math
from requests import get
import jwt
import requests
import json
import urllib3
import pandas as pd
import config as c
from time import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# TEST API key and API secret
# API_KEY = c.ZOOM_API_KEY_TEST
# API_SEC = c.ZOOM_API_SEC_TEST
# MAIN_SITE = "UNI Campus"

# PROD API key and API secret
API_KEY = c.ZOOM_API_KEY
API_SEC = c.ZOOM_API_SEC
MAIN_SITE = "Main Site"


# Observium API key and API secret
API_USER = c.OBVS_API_USER
API_PASS = c.OBVS_API_PASS

# Extreme API
username = c.EXTR_API_USER
password = c.EXTR_API_PASS

# GLOBALS
AP_BRIEF = {}
BSSID = {}
CONTROLLERS = ["10.10.192.120", "10.19.3.120"]
LIMIT = 300
NEXT_TOKEN = ''
API_HEADERS = {}
SITE_IDS = {}
ERL_ADDRESS_IDS = []
ERL_LOCATION_IDS = []
SWITCHES = []
SWITCH_IDS = {}
PORTS = pd.DataFrame()

# Determine if we need a proxy
PROXIES = {
    "http": 'http://proxy.it-nis.uni.edu:8080',
    "https": 'http://proxy.it-nis.uni.edu:8080',
}

try:
    if requests.head('https://zoom.us', timeout=1):
        PROXIES = {}
except:
    pass

#############################################
# Core Functions
#############################################


def main_request(baseurl, parm_name1, parm_value1, parm_name2, parm_value2):
    parameters = {
        parm_name1: parm_value1,
        parm_name2: parm_value2
    }
    data = requests.get(baseurl, headers=API_HEADERS,
                        params=parameters, verify=False, proxies=PROXIES).json()
    # print(json.dumps(data))
    global NEXT_TOKEN
    NEXT_TOKEN = data['next_page_token']
    return data


def parse_json(response, field_name, dict_name):
    datalist = []
    for item in response[dict_name]:
        if field_name in item:
            item_list = {
                'id': item['id'],
                field_name: item[field_name]
            }
            datalist.append(item_list)
    return datalist


def get_pages(response):
    return math.ceil(response['total_records']/LIMIT)


def get_id(dict_name, field_name, field_value):
    for i in dict_name:
        if i[field_name] == field_value:
            return i['id']


def getZoomToken():
    # Generate a token
    # using the pyjwt library
    token = jwt.encode({'iss': API_KEY, 'exp': time() +
                       99000}, API_SEC, algorithm='HS256')
    headers = {'authorization': 'Bearer %s' % token,
               'content-type': 'application/json'}
    return headers


def getExtremeToken(controller):
    url = 'https://' + controller + ':5825/management/v1/oauth2/token'
    payload = json.dumps(
        {"grantType": "password", "userId": username, "password": password})
    headers = {'Content-Type': 'application/json'}
    response = requests.request(
        "POST", url, headers=headers, data=payload, verify=False, allow_redirects=False)

    if response.status_code != 200:
        print("Failed to obtain token from the OAuth 2.0 server")
    else:
        # Successfuly obtained a new token
        tokens = json.loads(response.text)
        return tokens['access_token']


def getAllSiteIDs():
    # Not checking for pagination because there is only one site or less than 300
    url = "https://api.zoom.us/v2/phone/sites?page_size=300"
    return requests.get(url, headers=API_HEADERS, verify=False, proxies=PROXIES).json()

#############################################
# Address & Location IDs Function
#############################################


def getAllEmergencyAddressIDs():
    url = "https://api.zoom.us/v2/phone/emergency_addresses?page_size=" + \
        str(LIMIT)
    siteID = getSiteID(MAIN_SITE)
    parsed_data = []
    global NEXT_TOKEN

    # First call to get page numbers then reset page token
    NEXT_TOKEN = ''
    data = main_request(url, 'site_id', siteID, 'next_page_token', NEXT_TOKEN)
    NEXT_TOKEN = ''

    for x in range(1, get_pages(data)+1):
        parsed_data.extend(
            parse_json(
                main_request(url, 'site_id', siteID,
                             'next_page_token', NEXT_TOKEN),
                'address_line2',
                'emergency_addresses'
            ))

    return parsed_data


def getAllLocationIDs():
    url = "https://api.zoom.us/v2/phone/locations?page_size="+str(LIMIT)
    parsed_data = []
    global NEXT_TOKEN

    # First call to get page numbers then reset page token
    NEXT_TOKEN = ''
    data = main_request(url, 'site_id', '', 'next_page_token', NEXT_TOKEN)
    NEXT_TOKEN = ''

    for x in range(1, get_pages(data)+1):
        parsed_data.extend(
            parse_json(
                main_request(url, 'site_id', '',
                             'next_page_token', NEXT_TOKEN),
                'name',
                'locations'
            ))

    return parsed_data

#############################################
# Access Functions
#############################################


def getbuildingName(code):
    # Converts building code to site name
    bld_list = open('./static/bldg_key.csv', 'r')
    name = ""
    for line in bld_list:
        data = line.strip().split(",")
        if(code == data[0]):
            name = (data[2]+"("+data[9]+")")
            break
    bld_list.close()
    return name


def getBuidlingAddress(code):
    bld_list = open('./static/bldg_key.csv', 'r')
    address = ""
    for line in bld_list:
        data = line.strip().split(",")
        if(code == data[0]):
            address = data[3]+" "+data[4]+","+data[5]+","+data[6]+","+data[8]
            break
    bld_list.close()
    return address


def getSiteID(bname):
    for i in SITE_IDS['sites']:
        if i['name'] == bname:
            return i['id']

#############################################
# Build Zoom Structure
#############################################
def createAllBSSIDAdrLoc(step):
    # Assigns BSSID to correct building
    # Used for controllers (10.10.192.120, 10.19.3.120)
    for ap in BSSID:
        # Changing AP names to fit building name
        modifyAP = ap.replace('AWC-', 'AWA-').replace('UAP-', 'UAPO-').replace(
            'PV1-', 'PVL1-').replace('PV3-', 'PVL3-').replace(
                'TPC-', 'NRV-').replace('CET-', 'SBR-')
        code = modifyAP.split("-")
        bldName = getbuildingName(code[0])
        # Converting list to str
        str_bssid = ','.join(map(str, BSSID[ap]))
        # Send to Zoom
        # Create Address with Room Data
        address = getBuidlingAddress(code[0]).split(",")
        # Checks for malformed AP Names
        if bldName:
            if step == 1:
                # Step 1
                createAddress(address[0], bldName+" WIRELESS LOCATION NEAR: " +
                              modifyAP, address[1], address[2], address[3])
            elif step == 2:
                # Step 2 - to reduce the calls made for address ID
                # Create Location referencing location
                createBSSIDLocation(
                    code[0], bldName+" WIRELESS LOCATION NEAR: "+modifyAP, modifyAP, str_bssid)
        else:
            print("No Location or Address Created For AP "+ap)

def createAllHardwiredAdrLoc(step):
    # Assigns Port to correct building
    for index, row in PORTS.iterrows():
        code = row['Alias'].split(" ")
        bldName = getbuildingName(code[0])
        address = getBuidlingAddress(code[0]).split(",")
        if bldName and address:
            if step == 1:
                createAddress(
                    address[0], bldName+" RM "+row['Alias'], address[1], address[2], address[3])
            elif step == 2:
                createHardwiredLocation(code[0], bldName+" RM "+row['Alias'])
            elif step == 3:
                updateHardwiredLocation(
                    bldName+" RM "+row['Alias'], row['Port'], row['ChassisID'], row['Port_Mac'])
        else:
            # Catching for bad alias or blanks
            print("Malformed Alias: "+row)

#############################################
# Zoom Load Functions
#############################################


def createAddress(address1, address2, city, state, zip):
    # Can create duplicate of same address
    # Checking if address2 line is already created
    if(not get_id(ERL_ADDRESS_IDS, 'address_line2', address2)):
        siteID = getSiteID(MAIN_SITE)
        address = {
            "site_id": siteID,
            "country": "US",
            "address_line1": address1,
            "address_line2": address2,
            "state_code": state,
            "city": city,
            "zip": zip
        }
        API_POST_URL = 'https://api.zoom.us/v2/phone/emergency_addresses'
        r = requests.post(API_POST_URL, headers=API_HEADERS,
                          data=json.dumps(address),proxies=PROXIES)
        if(201 != r.status_code):
            print(address2+" Exit Code 7: "+r.text)


def createBSSIDLocation(code, bname, ap_name, bssid):
    siteID = getSiteID(MAIN_SITE)
    emergency_address_id = get_id(ERL_ADDRESS_IDS, 'address_line2', bname)
    location_id = get_id(ERL_LOCATION_IDS, 'name',
                         "WIRELESS LOCATION NEAR: "+ap_name)
    # Check if address is made
    if(emergency_address_id):
        bssid_location = {
            "site_id": siteID,
            "name": "WIRELESS LOCATION NEAR: "+ap_name,
            "emergency_address_id": emergency_address_id,
            "bssid": bssid,
            "parent_location_id": get_id(ERL_LOCATION_IDS, 'name', code)
        }

        # Checks if location exist else update it
        if(not location_id):
            API_POST_URL = 'https://api.zoom.us/v2/phone/locations'

            r = requests.post(API_POST_URL, headers=API_HEADERS,
                              data=json.dumps(bssid_location),proxies=PROXIES)
            if(201 != r.status_code):
                print(code+" Exit Code 6: "+r.text)
            else:
                print("Created new AP location: " + ap_name)
        else:
            API_PATCH_URL = 'https://api.zoom.us/v2/phone/locations/' + location_id
            r = requests.patch(API_PATCH_URL, headers=API_HEADERS,
                               data=json.dumps(bssid_location),proxies=PROXIES)
            if(204 != r.status_code):
                print(code+ " " + bname + " " + ap_name +" Exit Code 5: "+r.text)


def updateHardwiredLocation(name, port, chassis_mac, port_mac):
    locationID = get_id(ERL_LOCATION_IDS, 'name', name)
    if(locationID):
        settings = {
            "network_switches": [
                {
                    "port": port,
                    "mac_address": chassis_mac
                },
                {
                    "port": port_mac,
                    "mac_address": chassis_mac
                }
            ]
        }

        API_PATCH_URL = 'https://api.zoom.us/v2/phone/locations/'+locationID
        r = requests.patch(API_PATCH_URL, headers=API_HEADERS,
                           data=json.dumps(settings),proxies=PROXIES)
        if(204 != r.status_code):
            print(name+" "+port+" "+chassis_mac+" "+port_mac+" Exit Code 4: "+r.text)


def createHardwiredLocation(code, name):
    siteID = getSiteID(MAIN_SITE)
    emergency_address_id = get_id(ERL_ADDRESS_IDS, 'address_line2', name)
    location_id = get_id(ERL_LOCATION_IDS, 'name', name)
    if(emergency_address_id and not location_id):
        hardwired_location = {
            "site_id": siteID,
            "name": name,
            "emergency_address_id": emergency_address_id,
            "parent_location_id": get_id(ERL_LOCATION_IDS, 'name', code)
        }

        API_POST_URL = 'https://api.zoom.us/v2/phone/locations'
        r = requests.post(API_POST_URL, headers=API_HEADERS,
                          data=json.dumps(hardwired_location),proxies=PROXIES)
        if(201 != r.status_code):
            print(code+" Problem Exit Code 3: "+r.text)
            print(location_id + " " + hardwired_location + " " + emergency_address_id + " " + name + " " + code)
        else:
            print("Created new hardwired lcoation: "+name)       
    elif not emergency_address_id:
        print("Could not find address: "+name)
    # elif location_id:
    #     print("Duplicated Location: "+name + location_id)
    # else:
    #     print("Something else is wrong: "+ location_id + name)
#############################################

# Extreme BSSID Info
#############################################


def getExtremeAPData():
    # Stored AP Names into global var for reference
    for x in CONTROLLERS:
        api_call_headers = {'Authorization': 'Bearer ' + getExtremeToken(x)}
        ap_name_url = 'https://' + x + ':5825/management/v1/aps' + '?brief=true'
        data = requests.get(
            ap_name_url, headers=api_call_headers, verify=False).json()
        for ap in data:
            AP_BRIEF[ap['serialNumber']] = ap['apName']


def getExtremeAPName(serial):
    return AP_BRIEF[serial]


def getExtremeBSSID():
    global BSSID
    for x in CONTROLLERS:
        api_call_headers = {'Authorization': 'Bearer ' + getExtremeToken(x)}
        inventory_url = 'https://' + x + ':5825/management/v1/aps' + '?inventory=true'
        inventory_data = requests.get(
            inventory_url, headers=api_call_headers, verify=False).json()

        for ap in inventory_data:
            # Get building to assign to
            apName = getExtremeAPName(ap['serialNumber'])
            # Finding all BSSID on radios
            radios = ap['radios']
            if len(radios) == 0:
                continue
            radio1 = radios[0]
            radio2 = radios[1]
            wlanlist1 = radio1['wlan']
            wlanlist2 = radio2['wlan']
            wlans = []
            if len(wlanlist1) != 0:
                for w in wlanlist1:
                    wlans.append(w['bssid'])

            if len(wlanlist2) != 0:
                for w in wlanlist2:
                    wlans.append(w['bssid'])
            BSSID[apName] = wlans
#############################################

# Hardwired Data
#############################################


def getAllSwitchesAliasData(switch_list):
    # Returns all ports with alias for all switches - ignores blanks ports
    ports = pd.DataFrame()
    for x in switch_list:
        data = get('https://observium.it-nis.uni.edu/api/v0/ports?device_id=' +
                   getDeviceID(x), auth=(API_USER, API_PASS)).json()
        for i in data['ports']:
            if 'ge.' in data['ports'][i]['ifName'] and data['ports'][i]['ifAlias']:
                port = pd.DataFrame({
                    'Switch': [x],
                    'Port': [data['ports'][i]['ifName']],
                    'Alias': [data['ports'][i]['ifAlias']],
                    'Port_Mac': [data['ports'][i]['human_mac']],
                    'ChassisID': getChassisID(data)
                })
                ports = pd.concat([ports, port], ignore_index=True)
    return ports


def getAllDeviceID():
    # Return Observium switch ID
    return get(f'https://observium.it-nis.uni.edu/api/v0/devices?fields=hostname,device_id', auth=(API_USER, API_PASS)).json()


def getChassisID(data):
    for i in data['ports']:
        if 'vlan.0.2018' in data['ports'][i]['ifName']:
            return [data['ports'][i]['human_mac']]


def getDeviceID(switch_ip):
    for i in SWITCH_IDS['devices']:
        if SWITCH_IDS['devices'][i]['hostname'] == switch_ip:
            return SWITCH_IDS['devices'][i]['device_id']


def getExtremeSwitches():
    # Excludes C5 Switches
    switches = []
    data = get('https://observium.it-nis.uni.edu/api/v0/devices?os=enterasys',
               auth=(API_USER, API_PASS)).json()
    for i in data['devices']:
        if 'K10' in data['devices'][i]['sysDescr'] or '7100' in data['devices'][i]['sysDescr'] or 'K6' in data['devices'][i]['sysDescr']:
            switches.append(data['devices'][i]['ip'])
    return switches
#############################################


def deleteLocationAddress(id, location):
    # Removing Location
    API_DELETE_URL = 'https://api.zoom.us/v2/phone/locations/'+id
    r = requests.delete(API_DELETE_URL, headers=API_HEADERS,proxies=PROXIES)
    # Checking return status code
    if(204 != r.status_code):
        print("Can't delete Location "+location + " Exit Code 2: "+r.text)
    else:
        print("Removed Location "+location)
        # Okay to remove address
        for address in ERL_ADDRESS_IDS:
            if location in address['address_line2']:
                API_DELETE_URL = 'https://api.zoom.us/v2/phone/emergency_addresses/' + \
                    address['id']
                r2 = requests.delete(API_DELETE_URL, headers=API_HEADERS,proxies=PROXIES)
                if(204 != r2.status_code):
                    print("Can't delete Address " +
                          location + " Exit Code 1: "+r2.text)
                else:
                    print("Removed Address "+location)


def deletions():
    for location in ERL_LOCATION_IDS:
        # Checking if APs can be removed from Zoom
        if "WIRELESS LOCATION NEAR: " in location['name']:
            # Modify AP name because of building code issues
            modified_location = location['name'].replace('WIRELESS LOCATION NEAR: ', '').replace(
                'AWA-', 'AWC-').replace('UAPO-', 'UAP-').replace(
                'PVL1-', 'PV1-').replace('PVL3-', 'PV3-').replace(
                'NRV-', 'TPC-').replace('SBR-', 'CET-')
            # If AP is not in any of our controllers delete it!
            if modified_location not in BSSID:
                # Removing Location
                print("Deleting BSSID " + location['name'])
                deleteLocationAddress(location['id'], location['name'])
        elif ") RM " in location['name']:
            # Hardwired Check
            # If the port moves to a different switch or a different port it will be updated from main
            # Port renames - old port is deleted and new is created
            # Process to verify port alias and check for duplicates
            # Getting just alias
            modified_location = location['name'].split(") RM ")
            # Searching for alias in dataframe
            results = PORTS.loc[PORTS['Alias'] == modified_location[1]]
            # If name is found - skip - else delete it
            if results.empty:
                print("Deleting Port " + modified_location[1])
                deleteLocationAddress(location['id'], location['name'])


def constructor():
    global API_HEADERS
    global SITE_IDS
    global ERL_ADDRESS_IDS
    global ERL_LOCATION_IDS
    global SWITCHES
    global SWITCH_IDS
    global PORTS

    API_HEADERS = getZoomToken()
    SITE_IDS = getAllSiteIDs()
    ERL_ADDRESS_IDS = getAllEmergencyAddressIDs()
    ERL_LOCATION_IDS = getAllLocationIDs()

    SWITCHES = getExtremeSwitches()
    SWITCH_IDS = getAllDeviceID()
    test = ["10.18.152.60"]
    PORTS = getAllSwitchesAliasData(SWITCHES)

    getExtremeAPData()
    getExtremeBSSID()


def main():
    global ERL_ADDRESS_IDS
    global ERL_LOCATION_IDS
    global API_HEADERS

    constructor()

    print("Starting Deletions")
    deletions()
    print("Finished Deletions")

    # Refreshing Headers
    API_HEADERS = getZoomToken()

    # Extreme BSSID Load
    # Run 2 times because of IDs refresh
    print("Starting BSSID Load")
    for i in range(1,3):
        print("Starting Step: "+ str(i))
        createAllBSSIDAdrLoc(i)
        ERL_ADDRESS_IDS = getAllEmergencyAddressIDs()
        ERL_LOCATION_IDS = getAllLocationIDs()
    print("Finished BSSID Load")

    # Refreshing Headers
    API_HEADERS = getZoomToken()
    
    # Extreme Hardwire Load
    # Run three times because of IDs refresh
    print("Starting Switch Load")
    for i in range(1,4):
        print("Starting Step: "+ str(i))
        createAllHardwiredAdrLoc(i)
        ERL_ADDRESS_IDS = getAllEmergencyAddressIDs()
        ERL_LOCATION_IDS = getAllLocationIDs()
    print("Finished Switch Load")

main()

# To Do
# import bld_key to pandas
