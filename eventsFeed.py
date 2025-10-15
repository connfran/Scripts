# eventsFeed.py
#
#
# Version: 1.0.1
# Author: Peter Lee, May 2022
#
# Changes since 1.0:
# - ensure_ascii=False when sending network stream
#x
# This script takes as input an API key and account ID, and returns events in JSON format
# from the event queue associated with that account ID. Requires events feed to be enabled
# in the Cato management console before events will be placed in the queue. Optional parameters
# include a marker value to initialise with and the path to a file in which to store the marker
# between runs (necessary to preserve place in the event queue). Also an event type and event
# subtype filter, for retrieving events only for certain types/subtypes.
#
# The eventsFeed API query supports multiple output formats - the script uses the fieldsMap format
# which displays nicely as a JSON key:value collection.
#
# The script provides the -n option for sending events as a stream to a TCP socket, and the -z option
# for sending events directly into Microsoft Sentinel.
#
# Usage: eventsFeed.py [options]
#
# Options:
#   -h, --help          show this help message and exit
#   -K API_KEY          API key
#   -I IDAccount ID
#   -PPrettify output
#   -pPrint event records
#   -n STREAM_EVENTS    Send events over network to host:port TCP
#   -z SENTINEL         Send events to Sentinel customerid:sharedkey
#   -m MARKER           Initial marker value (default is "", which means start
# of the queue)
#   -c CONFIG_FILE      Config file location (default ./config.txt)
#   -t EVENT_TYPES      Comma-separated list of event types to filter on
#   -s EVENT_SUB_TYPES  Comma-separated list of event sub types to filter on
#   -f fetch_limit      Stop execution if a fetch returns less than this number
# of events (default=1)
#   -r RUNTIME_LIMIT    Stop execution if total runtime exceeds this many
# seconds (default=infinite)
#   -vPrint debug info
#   -VPrint detailed debug info
#
# Examples:
#
# To run the script with key=YOURAPIKEY for account ID 1714 for the first time, pulling all events
# and storing the marker in the default location (./config.txt) without displaying events:
#   python3 eventsFeed.py -K YOURAPIKEY -I 1714 -m ""
#
# Running the script from the start with debug enabled so you can see the fetch logic in action:
#   python3 eventsFeed.py -K YOURAPIKEY -I 1714 -m "" -v
#
# To show events, use the -p parameter:
#   python3 eventsFeed.py -K YOURAPIKEY -I 1714 -p
#
# For more human readable events, use -pP
#   python3 eventsFeed.py -K YOURAPIKEY -I 1714 -pP
#
# To print human readable events to screen and send raw events to TCP port 8000 on 192.168.1.1:
#   python3 eventsFeed.py -K YOURAPIKEY -I 1714 -pP -n 192.168.1.1:8000
#
# To only see connectivity type events:
#   python3 eventsFeed.py -K YOURAPIKEY -I 1714 -p -t Connectivity
#
# To only see NG Anti Malware and Anti Malware subtype events:
#   python3 eventsFeed.py -K YOURAPIKEY -I 1714 -p -s "NG Anti Malware,Anti Malware"
#
# This script is supplied as a demonstration of how to access the Cato API with Python. It
# is not an official Cato release and is provided with no guarantees of support. Error handling
# is restricted to the bare minimum required for the script to work with the API, and may not be
# sufficient for production environments.
#
# All questions or feedback should be sent to api@catonetworks.com

import base64
import datetime
import hmac
import hashlib
import json
import os
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request
import logging  # Added for logging.info and logging.error in send function
from optparse import OptionParser

########################################################################################
########################################################################################
########################################################################################
# Helper functions and globals

# Log debug output
def log(text):
    if options.verbose or options.veryverbose:
        print(f"LOG {datetime.datetime.utcnow()}> {text}")

# Log detailed debug output
def logd(text):
    if options.veryverbose:
        log(text)

# Send GQL query string to API, return JSON
def send(query):
    global api_call_count
    retry_count = 0
    data = {'query': query}
    headers = {'x-api-key': options.api_key, 'Content-Type': 'application/json'}
    no_verify = ssl._create_unverified_context()
    
    while True:
        if retry_count > 10:
            print("FATAL ERROR: retry count exceeded")
            sys.exit(1)
        try:
            request = urllib.request.Request(url='https://api.catonetworks.com/api/v1/graphql2',
                data=json.dumps(data).encode("ascii"),headers=headers)
            response = urllib.request.urlopen(request, context=no_verify, timeout=30)
            api_call_count += 1
        except Exception as e:
          log(f"ERROR {retry_count}: {e}, sleeping 2 seconds then retrying")
          time.sleep(2)
          retry_count += 1
          continue
        result_data = response.read()
        if result_data[:48] == b'{"errors":[{"message":"rate limit for operation:':
          log("RATE LIMIT sleeping 5 seconds then retrying")
          time.sleep(5)
          continue
        break
    result = json.loads(result_data.decode('utf-8','replace'))
    if "errors" in result:
        log(f"API error: {result_data}")
        return False,result
    return True,result

########################################################################################
########################################################################################
########################################################################################
# Azure Sentinel functions

def build_signature(customer_id, shared_key, date, content_length):
    x_headers = 'x-ms-date:' + date
    string_to_hash = f"POST\n{content_length}\napplication/json\n{x_headers}\n/api/logs"
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id, encoded_hash)
    return authorization

def post_data(customer_id, shared_key, body):
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)  # Assuming body is a string
    
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length)
    
    headers = {
        'content-type': 'application/json',
        'Authorization': signature,
        'Log-Type': 'CatoEvents',
        'Time-generated-field': 'event_timestamp',
        'x-ms-date': rfc1123date
    }
    
    no_verify = ssl._create_unverified_context()
    
    try:
        request = urllib.request.Request(url='https://' + customer_id + '.ods.opinsights.azure.com/api/logs?api-version=2016-04-01',
                data=body,headers=headers)
        response = urllib.request.urlopen(request, context=no_verify)
    except urllib.error.URLError as e:
      print(f"Azure API ERROR:{e}")
      sys.exit(1)
    except OSError as e:
      print(f"Azure API ERROR: {e}")
      sys.exit(1)
    return response.code

########################################################################################
########################################################################################
########################################################################################
# Start of the main program

api_call_count = 0
start = datetime.datetime.now()

# Process options
parser = OptionParser()
parser.add_option("-K", dest="api_key", help="API key")
parser.add_option("-I", dest="ID", help="Account ID")
parser.add_option("-P", dest="prettify", action="store_true", help="Prettify output")
parser.add_option("-p", dest="print_events", action="store_true", help="Print event records")
parser.add_option("-n", dest="stream_events", help="Send events over network to host:port TCP")
parser.add_option("-z", dest="sentinel", help="Send events to Sentinel customerid:sharedkey")
parser.add_option("-m", dest="marker", help="Initial marker value (default is \"\", which means start of the queue)")
parser.add_option("-c", dest="config_file", help="Config file location (default ./config.txt)")
parser.add_option("-t", dest="event_types", help="Comma-separated list of event types to filter on")
parser.add_option("-s", dest="event_sub_types", help="Comma-separated list of event sub types to filter on")
parser.add_option("-f", dest="fetch_limit", help="Stop execution if a fetch returns less than this number of events (default=1)")
parser.add_option("-r", dest="runtime_limit", help="Stop execution if total runtime exceeds this many seconds (default=infinite)")
parser.add_option("-v", dest="verbose", action="store_true", help="Print debug info")
parser.add_option("-V", dest="veryverbose", action="store_true", help="Print detailed debug info")
(options, args) = parser.parse_args()

if options.api_key is None or options.ID is None:
    parser.print_help()
    sys.exit(1)

# Handle config file and marker
config_file = "./config.txt"
marker = ""
if options.config_file is None:
    log(f"No config file specified, using default: {config_file}")
else:
    config_file = options.config_file
    log(f"Using config file from -c parameter: {config_file}")

if options.marker is None:
    log("No marker value supplied, setting marker = \"\"")
    if os.path.isfile(config_file):
        log(f"Found config file: {config_file}")
        with open(config_file, "r") as file_obj:
            try:
                marker = file_obj.readlines()[0].strip()
                log(f"Read marker from config_file: {marker}")
            except IndexError as e:
                log(str(e))
                log(f"Couldn't read marker from config file, leaving marker as {marker}")
    else:
        log("Config file does not exist, sticking with default marker")
else:
    marker = options.marker
    log(f"Using marker value from -m parameter: {marker}")

# Process event type filters
if options.event_types is not None:
    log(f"Event type filter parameter: {options.event_types}")
    event_type_strings = options.event_types.split(',')
    log("Event type strings:" + str(event_type_strings).replace('\'', '"'))
    event_filter_string = '{"fieldName":"event_type","operator":"in","values":' + json.dumps(event_type_strings) + '}'
    log(f"Event filter string: {event_filter_string}")
else:
    event_filter_string = ""

# Process event sub-type filters
if options.event_sub_types is not None:
    log(f"Event sub type filter parameter: {options.event_sub_types}")
    event_subtype_strings = options.event_sub_types.split(',')
    log("Event sub type strings:" + str(event_subtype_strings).replace('\'', '"'))
    event_subfilter_string = '{"fieldName":"event_sub_type","operator":"in","values":' + json.dumps(event_subtype_strings) + '}'
    log(f"Event sub filter string: {event_subfilter_string}")
else:
    event_subfilter_string = ""

# Process network options
if options.stream_events is not None:
    network_elements = options.stream_events.split(":")
    if len(network_elements) != 2:
        print("Error: -n value must be in the form of host:port")
        parser.print_help()
        sys.exit(1)

# Process Sentinel options
if options.sentinel is not None:
    sentinel_elements = options.sentinel.split(":")
    if len(sentinel_elements) != 2:
        print("Error: -z value must be in the form of customerid:sharedkey")
        parser.print_help()
        sys.exit(1)

# Fetch threshold
FETCH_THRESHOLD = 1 if options.fetch_limit is None else int(options.fetch_limit)

# Runtime threshold
RUNTIME_LIMIT = sys.maxsize if options.runtime_limit is None else int(options.runtime_limit)

# API call loop
iteration = 1
total_count = 0
while True:
    query = '''
{
  eventsFeed(accountIDs:[''' + options.ID + ''']
    marker:"''' + marker + '''"
    filters:[''' + event_filter_string + "," + event_subfilter_string + '''])
  {
    marker
    fetchedCount
    accounts {
      id
      records {
        time
        fieldsMap
      }
    }
  }
}'''
    
    logd(query)
    success, resp = send(query)
    
    if not success:
        print(resp)
        sys.exit(1)
    
    logd(resp)
    marker = resp["data"]["eventsFeed"]["marker"]
    fetched_count = int(resp["data"]["eventsFeed"]["fetchedCount"])
    total_count += fetched_count
    line = f"Iteration: {iteration}, Fetched: {fetched_count}, Total: {total_count}, Marker: {marker}"
    
    if "accounts" in resp["data"]["eventsFeed"] and len(resp["data"]["eventsFeed"]["accounts"]) > 0:
        records = resp["data"]["eventsFeed"]["accounts"][0]["records"]
        if len(records) > 0:
            line += f" First: {records[0]['time']}, Last: {records[-1]['time']}"
    
    log(line)
    
    # Print output
    if options.print_events:
        for event in resp["data"]["eventsFeed"]["accounts"][0]["records"]:
            event["fieldsMap"]["event_timestamp"] = event["time"]
            if options.prettify:
                print(json.dumps(event["fieldsMap"], indent=2, ensure_ascii=False))
            else:
                print(json.dumps(event["fieldsMap"], ensure_ascii=False))
    
    # Network stream
    if options.stream_events is not None:
        logd(f"Sending events to {network_elements[0]}:{network_elements[1]}")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:  # Establish connection per iteration
                s.connect((network_elements[0], int(network_elements[1])))
                for event in resp["data"]["eventsFeed"]["accounts"][0]["records"]:
                    event["fieldsMap"]["event_timestamp"] = event["time"]
                    s.sendall(json.dumps(event["fieldsMap"], ensure_ascii=False).encode("utf-8"))
        except Exception as e:
            log(f"Network error: {e}")
    
    # Send to Microsoft Sentinel
    if options.sentinel is not None:
        logd(f"Sending events to Azure workspace ID {sentinel_elements[0]}")
        body = []
        for event in resp["data"]["eventsFeed"]["accounts"][0]["records"]:
            event["fieldsMap"]["event_timestamp"] = event["time"]
            body.append(event["fieldsMap"])
        response_status = post_data(sentinel_elements[0], sentinel_elements[1], json.dumps(body))
        if response_status < 200 or response_status > 299:
            print(f"Send to Azure returned {response_status}, exiting")
            sys.exit(1)
        logd(f"Send to Azure response code: {response_status}")
    
    # Write marker back out
    logd(f"Writing marker to {config_file}")
    with open(config_file, "w") as file_obj:
        file_obj.write(marker)
    
    iteration += 1
    
    if fetched_count < FETCH_THRESHOLD:
        log(f"Fetched count {fetched_count} less than threshold {FETCH_THRESHOLD}, stopping")
        break
    
    elapsed = datetime.datetime.now() - start
    if elapsed.total_seconds() > RUNTIME_LIMIT:
        log(f"Elapsed time {elapsed.total_seconds()} exceeds runtime limit {RUNTIME_LIMIT}, stopping")
        break

end = datetime.datetime.now()
log(f"OK: {total_count} events from {api_call_count} API calls in {end - start}")