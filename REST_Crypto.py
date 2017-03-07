#!usr/bin/python3

#My first Python3 script to call a REST-API on an ASR1K
#version 1.0 03/06/17
#Stephen Orr

import requests
import json
import getpass
import ipaddress
from pprint import pprint


def getIP():
    #get the REST-API ip address of the host IPv4 or IPv6
    notIP = True #variable to make sure the entry is a valid IP
    while notIP:
        try:
            host = input("REST-API IP Address: ")
            if ipaddress.ip_address(host).version == 4:
                host_addr = str(ipaddress.ip_address(host))
            else:
                 host_addr = "["+str(ipaddress.ip_address(host))+"]"
            notIP = False
        except ValueError:
            print('Entry is not a valid IP Address:', host)
    return(host_addr)

def getAuth():
    #get the username and password and store them in a dictionary
    credentials = {
        'username' : input("Username:"),
        'password' : getpass.getpass()
    }
    return (credentials)

def getToken(userauth, hostAddr):
    #construct http post for token
    #userauth - dictionary of username and password
    #hostAddr - IP address of API
    requests.packages.urllib3.disable_warnings()
    url = "https://"+hostAddr+":55443/api/v1/auth/token-services"
    print (url)
    headers = {
        "content-type": "application/json"
    }
    try:
        response = requests.post(url, auth=(userauth['username'],userauth['password']), headers=headers, verify=False)
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print (err)
        exit()
    except requests.exceptions.RequestException as err:
        print (err)
        exit()

    data = response.json()
    pprint ("Token for %s : %s" % (hostAddr, data['token-id']))

def main():
    print("Python Script to access REST-API")
    login = getAuth() #get userid and password
    host_ip = getIP() #get ipaddress
    token = getToken(login, host_ip) #get the token


if __name__ == "__main__":
    main()
