#!usr/bin/python3

"""
Python3 script to call a REST-API on a Cisco IOS-XE device
Program asks for the username/password and IP Address of host
then it gets the REST access Token and finally prints:
    IP Address (v4 or v6)
    Name
    Interfaces
    IKE and IPSec Policies
version 0.321 03/21/17
Stephen Orr
"""

import requests
import json
import getpass
import ipaddress
from pprint import pprint


def getIP():
    """
    function that gets the REST-API Host ip address for user can be
    either IPv4 or IPv6 returns a string of the IP Address
    """
    notIP = True #variable to make sure the entry is a valid IP
    while notIP:
        try:
            host = input("REST-API IP Address: ")
            if ipaddress.ip_address(host).version == 4:
                host_addr = str(ipaddress.ip_address(host))
            else:
                 if ipaddress.ip_address(host).version == 6:
                     host_addr = "["+str(ipaddress.ip_address(host))+"]"
            notIP = False
        except ValueError:
            print('Entry is not a valid IP Address:', host)
    return(host_addr)


def getAuth():
    """
    function that gets the username and password to access the REST-API
    returns a dictonary with username and password
    """
    credentials = {
        'username' : input("Username:"),
        'password' : getpass.getpass()
    }
    return (credentials)


def getToken(userauth, hostAddr):
    """
    function that constructs the http post for the session authentication token
    input is username/password and returns the token
    userauth - dictionary of username and password
    hostAddr - IP address of REST-API
    """
    requests.packages.urllib3.disable_warnings()
    url = "https://"+hostAddr+":55443/api/v1/auth/token-services"
    headers = {
        "content-type": "application/json"
    }
    try:
        response = requests.post(
                        url,
                        auth=(userauth['username'],userauth['password']),
                        headers=headers,
                        verify=False
        )
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print (err)
        exit()
    except requests.exceptions.RequestException as err:
        print (err)
        exit()
    data = response.json()
    pprint ("Token for %s : %s" % (hostAddr, data['token-id']))
    return (data['token-id'])


def getHostname(hostAddr, sessionToken):
    """
    function to get the hostname - takes in the following
    sessionToken - authorization token
    hostAddr - IP address of REST-API
    returns the hostname
    """
    requests.packages.urllib3.disable_warnings()
    url = "https://"+hostAddr+":55443/api/v1//global/host-name"
    headers = {
        "content-type": "application/json",
        "X-AUTH-TOKEN": sessionToken
    }
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print (err)
        exit()
    except requests.exceptions.RequestException as err:
        print (err)
        exit()
    data = response.json()
    print ("Hostname is", data['host-name'])
    return(data['host-name'])


def getInterfaces(hostAddr, sessionToken):
    """ Funtion that gets the devices interfaces
        sessionToken - authorization token
        hostAddr - IP address of REST-API

        The json data for the interfaces are stored as a dictionary "items"
        inside that dictionary is an array of unnamed dictionaries that you need
        to iterate through to get the interface values.
    """
    requests.packages.urllib3.disable_warnings()
    url = "https://"+hostAddr+":55443/api/v1/interfaces"
    headers = {
        "content-type": "application/json",
        "X-AUTH-TOKEN": sessionToken
    }
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print (err)
        exit()
    except requests.exceptions.RequestException as err:
        print (err)
        exit()
    interface_list = response.json()
    print("Interfaces")
    interface = 0
    while interface < len(interface_list['items']):
        print(interface_list['items'][interface]['if-name'], "IP Address", interface_list['items'][interface]['ip-address'])
        interface +=1


def getIke(hostAddr, sessionToken):
    """ Function to get the Ike policy information
    sessionToken - authorization token
    hostAddr - IP address of REST-API

    The json data for the IKE Policies are stored in a dictionary "items"
    inside that dictionary is an array of unnamed dictionaries that you need
    to iterate through to get the IKE Policies.
    """
    requests.packages.urllib3.disable_warnings()
    url = "https://"+hostAddr+":55443/api/v1/vpn-svc/ike/policies"
    headers = {
        "content-type": "application/json",
        "X-AUTH-TOKEN": sessionToken
    }
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print (err)
        exit()
    except requests.exceptions.RequestException as err:
        print (err)
        exit()
    ikePolicies = response.json()
    if ikePolicies["items"] == []:
        print ("No IKE policies defined")
    else:
        print("IKE Policies")
        for policy in ikePolicies["items"]:
            pprint(policy)


def getIPSec(hostAddr, sessionToken):
    """ Function to get the IPSec policy information
    sessionToken - authorization token
    hostAddr - IP address of REST-API

    The json data for the IPSec Policies are stored in a dictionary "items"
    inside that dictionary is an array of unnamed dictionaries that you need
    to iterate through to get the IPSec Policies.
    """
    requests.packages.urllib3.disable_warnings()
    url = "https://"+hostAddr+":55443/api/v1/vpn-svc/ipsec/policies"
    headers = {
        "content-type": "application/json",
        "X-AUTH-TOKEN": sessionToken
    }
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print (err)
        exit()
    except requests.exceptions.RequestException as err:
        print (err)
        exit()
    ipsecPolicies = response.json()
    if ipsecPolicies["items"] == []:
        print("No IPSec policies defined")
    else:
        print("IPsec Policies")
        for policy in ipsecPolicies["items"]:
            pprint(policy)



def main():
    print("Python 3 Code to access REST-API")
    login = getAuth() #get userid and password
    host_ip = getIP() #get ipaddress
    token = getToken(login, host_ip) #get the token
    hostname = getHostname(host_ip, token)
    getInterfaces(host_ip, token)
    getIke(host_ip, token)
    getIPSec(host_ip, token)

if __name__ == "__main__":
    main()
