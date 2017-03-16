#!usr/bin/python3

#Python3 script to call a REST-API on an ASR1K
#version 0.315 03/15/17
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
    #construct http post for token - REST-API needs a token
    #userauth - dictionary of username and password
    #hostAddr - IP address of REST-API
    requests.packages.urllib3.disable_warnings()
    url = "https://"+hostAddr+":55443/api/v1/auth/token-services"
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
    return (data['token-id'])


def getHostname(hostAddr, sessionToken):
    #get the hostname
    #sessionToken - authorization token
    #hostAddr - IP address of REST-API
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
    #get the devices interfaces
    #sessionToken - authorization token
    #hostAddr - IP address of REST-API
    #interface_list - a dictionary with key 'items" of an array of dictionaries
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
    #get the Ike policy information
    #sessionToken - authorization token
    #hostAddr - IP address of REST-API
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
    ikeData = response.json()
    print("Ike Policies")
    pprint(ikeData['items'])

def getIPSec(hostAddr, sessionToken):
    #get the IPSec policy information
    #sessionToken - authorization token
    #hostAddr - IP address of REST-API
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
    ipsecData = response.json()
    print("IPSec Policies")
    pprint(ipsecData['items'])


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
