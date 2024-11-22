# KoinDNS
DNS Spoof checker created by KoinSec s a lightweight CLI tool designed to detect anomalies in DNS resolutions. It helps identify potential DNS spoofing by resolving domain names to IP addresses and comparing the results with trusted IPs.

# Installation
step 1
```
pip3 install termcolor
```

step 2

``` 
chmod +x koindns.py
```

Step 3
```
sudo mv koindns.py /usr/local/bin/koindns
```

# Usage

```
koindns -d <domain> [-t <trusted IPs>]
```
