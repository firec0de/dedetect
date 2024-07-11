# DeDetect

## A tool for Deauthentication Attacks, Rogue and Fake Wireless Access Points Detection Through Fingerprinting with Telegram Notifications

Inspired by the tool snappy by spiderlabs at: https://github.com/SpiderLabs/snap.py for the Detection of Rogue and Fake Wireless APs.

Author: firec0de

## Prerequisites
Install required libraries by running: 
```
pip install -r requirements.txt
```
Check and turn on Monitor Mode for your interface:
```
sudo iwconfig # to see interface name and current mode
sudo ip link set INTERFACE_NAME down # turn interface off
sudo iw INTERFACE_NAME set monitor none # switch mode to monitor
sudo ip link set INTERFACE_NAME up # turn interface on
```
## Run: 
```
sudo python dedetect.py <interface> <chat_id> <token>
```

### Dont forget to Define the wait time between notifications for Telegram.
```
wait_time = 1  # in seconds
```

#### Telegram Bot Tutorial
https://core.telegram.org/bots/tutorial
