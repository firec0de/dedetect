# DeDetect

## A tool for Deauthentication Attacks, Rogue and Fake Wireless Access Points Detection Through Fingerprinting with Telegram Notifications

Inspired by the tool snappy by spiderlabs at: https://github.com/SpiderLabs/snappy for the Detection of Rogue and Fake Wireless APs.

Author: firec0de

## Prerequisites
Install required libraries by running: 
```
pip install -r requirements.txt
```
Check and turn on Monitor Mode for your interface:
```
sudo iwconfig
sudo ip link set wlan0 down
sudo iw wlan0 set monitor none
sudo ip link set wlan0 up
```
## Run: 
### Usage without notification: 
```
sudo python dedetect.py <interface>
```
### Usage with telegram notification:
```
sudo python dedetect.py <interface> <chat_id> <token>
```

#### Wait time between notifications for Telegram:
```
wait_time = 1  # in seconds
```

#### Telegram Bot Tutorial
https://core.telegram.org/bots/tutorial
