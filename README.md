# REST-API
Python3 script to access REST-API on an ASR1K

Minimal ASR1K/IOS-XE configuration is located in REST-API-ASR1K.txt

REST-API ASR1k configuration guide:
http://www.cisco.com/c/en/us/td/docs/routers/csr1000/software/configuration/b_CSR1000v_Configuration_Guide/b_CSR1000v_Configuration_Guide_chapter_01101.pdf


Dependencies
pip install requests

Version 1:
 1. Takes in username/password and IP address of rest API for IOS-XE (assumes default port of 55443)
 2. Prints out a list of interfaces


End goal is to check the crypto settings (IPSec, SSH etc) on an IOS-XE platform and provide recommendations on cipher strength.
