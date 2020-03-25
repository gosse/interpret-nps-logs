#!/usr/bin/env python3 

import csv
import argparse
import sys

parser = argparse.ArgumentParser()
parser.add_argument("filename", help="name of log file to be parsed")
args = parser.parse_args()


# How to read NPS log files - https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc771748(v=ws.10)?redirectedfrom=MSDN
columns = [ "ComputerName","ServiceName","Record-Date","Record-Time","Packet-Type","User-Name","Fully-Qualified-Distinguished-Name","Called-Station-ID","Calling-Station-ID","Callback-Number","Framed-IP-Address","NAS-Identifier","NAS-IP-Address","NAS-Port","Client-Vendor","Client-IP-Address","Client-Friendly-Name","Event-Timestamp","Port-Limit","NAS-Port-Type","Connect-Info","Framed-Protocol","Service-Type","Authentication-Type","Policy-Name","Reason-Code","Class","Session-Timeout","Idle-Timeout","Termination-Action","EAP-Friendly-Name","Acct-Status-Type","Acct-Delay-Time","Acct-Input-Octets","Acct-Output-Octets","Acct-Session-Id","Acct-Authentic","Acct-Session-Time","Acct-Input-Packets","Acct-Output-Packets","Acct-Terminate-Cause","Acct-Multi-Ssn-ID","Acct-Link-Count","Acct-Interim-Interval","Tunnel-Type","Tunnel-Medium-Type","Tunnel-Client-Endpt","Tunnel-Server-Endpt","Acct-Tunnel-Conn","Tunnel-Pvt-Group-ID","Tunnel-Assignment-ID","Tunnel-Preference","MS-Acct-Auth-Type","MS-Acct-EAP-Type","MS-RAS-Version","MS-RAS-Vendor","MS-CHAP-Error","MS-CHAP-Domain","MS-MPPE-Encryption-Types","MS-MPPE-Encryption-Policy","Proxy-Policy-Name","Provider-Type","Provider-Name","Remote-Server-Address","MS-RAS-Client-Name","MS-RAS-Client-Version" ]

packettype = {
  "1": "Access-Request",
  "2": "Access-Accept",
  "3": "Access-Reject",
  "4": "Accounting-Request"
}

authenticationtype = {
  "1": "PAP",
  "2": "CHAP",
  "3": "MS-CHAP",
  "4": "MS-CHAP v2",
  "5": "EAP",
  "7": "None",
  "8": "Custom"
}

reasoncode = {
  "0": "IAS_SUCCESS",
  "1": "IAS_INTERNAL_ERROR",
  "2": "IAS_ACCESS_DENIED",
  "3": "IAS_MALFORMED_REQUEST",
  "4": "IAS_GLOBAL_CATALOG_UNAVAILABLE",
  "5": "IAS_DOMAIN_UNAVAILABLE",
  "6": "IAS_SERVER_UNAVAILABLE",
  "7": "IAS_NO_SUCH_DOMAIN",
  "8": "IAS_NO_SUCH_USER",
  "16": "IAS_AUTH_FAILURE",
  "17": "IAS_CHANGE_PASSWORD_FAILURE",
  "18": "IAS_UNSUPPORTED_AUTH_TYPE",
  "32": "IAS_LOCAL_USERS_ONLY",
  "33": "IAS_PASSWORD_MUST_CHANGE",
  "34": "IAS_ACCOUNT_DISABLED",
  "35": "IAS_ACCOUNT_EXPIRED",
  "36": "IAS_ACCOUNT_LOCKED_OUT",
  "37": "IAS_INVALID_LOGON_HOURS",
  "38": "IAS_ACCOUNT_RESTRICTION",
  "48": "IAS_NO_POLICY_MATCH",
  "64": "IAS_DIALIN_LOCKED_OUT",
  "65": "IAS_DIALIN_DISABLED",
  "66": "IAS_INVALID_AUTH_TYPE",
  "67": "IAS_INVALID_CALLING_STATION",
  "68": "IAS_INVALID_DIALIN_HOURS",
  "69": "IAS_INVALID_CALLED_STATION",
  "70": "IAS_INVALID_PORT_TYPE",
  "71": "IAS_INVALID_RESTRICTION",
  "80": "IAS_NO_RECORD",
  "96": "IAS_SESSION_TIMEOUT",
  "97": "IAS_UNEXPECTED_REQUEST"
}

# open the logfile and read it 
with open(args.filename) as csvfile:
  reader = csv.reader(csvfile, delimiter=',')
  for row in reader:
    print("\n\n\n########################## ")
    for i, log in enumerate(row):
      if log:
        if columns[i] == "Packet-Type":
          print(columns[i], ": ", log, " (", packettype.get(log), ")", sep="")
        elif columns[i] == "Authentication-Type":
          print(columns[i], ": ", log, " (", authenticationtype.get(log), ")", sep="")
        elif columns[i] == "Reason-Code":
          print(columns[i], ": ", log, " (", reasoncode.get(log), ")", sep="")
        else:
          print(columns[i], ": ", log, sep="")
    print("########################## ")
