# REST-API
Python3 script to access REST-API on an ASR1K

Minimal ASR1K/IOS-XE configuration is located in REST-API-ASR1K.txt

Dependencies
pip install requests

Version 1:
 1. Takes in username/password and IP address of rest API for IOS-XE and returns token-id
 2. Prints out a list of interfaces


End goal is to check the crypto settings (IPSec, SSH etc) on an IOS-XE platform and provide recommendations on cipher strength.
