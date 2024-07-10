# DeDetect

## A tool for Deauthentication Attacks, Rogue and Fake Wireless Access Points Detection Through Fingerprinting with Telegram Notifications

Inspired by the tool snappy by spiderlabs at: https://github.com/SpiderLabs/snap.py for the Detection of Rogue and Fake Wireless APs.

Author: firec0de

### Define the wait time between notifications, API Token and Channel ID before sending the Telegram notification.
```
wait_time = X # in seconds
TOKEN = "XXXXXXXXXXXXXXXXXX"
chat_id = "XXXXXXXXXX"
```

### Set interface name Ex: "wlan0".
### Tool sets the interface on Monitor by default otherwise remove Monitor:True from thread arguments and set it on monitor mode yourself.
```
thread1 = threading.Thread(target=sniff,
                               kwargs={"iface": "wlan0", "monitor": True,"prn": parse, "filter": "wlan type mgt subtype beacon"})
```
