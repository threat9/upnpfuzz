# UPnPFuzz

UPnPFuzz is a specialized fuzzing tool designed for testing and discovering vulnerabilities within devices and software that implement the Universal Plug and Play (UPnP) protocol.

## Community
Join community on [Embedded Exploitation Discord](https://discord.gg/UCXARN2vBx).

## Installation

### Use of PyPI

```commandline
pip install upnpfuzz
```

### Local
```commandline
git clone https://github.com/threat9/upnpfuzz
cd upnpfuzz
python -m venv venv
source venv/bin/activate
python setup.py install
```
## Usage

### Discover UPnP devices

```commandline
> upnpfuzz --discover
                        upnpfuzz (v1.0.0) by threat9
[*] Using network timeout for discovery: 5
[*] Discovering UPnP devices...
[+] 192.168.2.1:1900 - http://192.168.2.1:8000/ssdp/desc-DSM-lbr0.xml - Synology/DSM/192.168.2.1
[+] 192.168.2.1:1900 - http://169.254.70.46:8000/ssdp/desc-DSM-eth0.xml - Synology/DSM/169.254.70.46
[+] 192.168.2.1:1900 - http://:8000/ssdp/desc-DSM-bwlan1.xml - Synology/DSM/
[+] 192.168.2.1:1900 - http://:8000/ssdp/desc-DSM-bwlan0.xml - Synology/DSM/
[+] 192.168.2.1:1900 - http://192.168.2.1:46560/rootDesc.xml - Synology DSM UPnP/1.1 MiniUPnPd/2.
```

### Discover UPnP devices using custom network timeout

```commandline
> upnpfuzz --discover --network-timeout 10
                        upnpfuzz (v1.0.0) by threat9
[*] Using network timeout for discovery: 10.0
[*] Discovering UPnP devices...
[+] 192.168.2.1:1900 - http://192.168.2.1:8000/ssdp/desc-DSM-lbr0.xml - Synology/DSM/192.168.2.1
[+] 192.168.2.1:1900 - http://169.254.70.46:8000/ssdp/desc-DSM-eth0.xml - Synology/DSM/169.254.70.46
[+] 192.168.2.1:1900 - http://:8000/ssdp/desc-DSM-bwlan1.xml - Synology/DSM/
[+] 192.168.2.1:1900 - http://:8000/ssdp/desc-DSM-bwlan0.xml - Synology/DSM/
[+] 192.168.2.1:1900 - http://192.168.2.1:46560/rootDesc.xml - Synology DSM UPnP/1.1 MiniUPnPd/2.0
```

### Targeting SSDP - Simple Service Discovery Protocol

Specifying the target address via `--ssdp` parameter.
```commandline
upnpfuzz --ssdp 192.168.2.1:1900 --raw
```

### Targeting SOAP - UPnP Control Messaging

Specifying the target address via `--soap` parameter.

```commandline
upnpfuzz --soap http://192.168.2.1:46560/rootDesc.xml --raw
```

### Targeting ESP - Event Subscription

Specifying the target address via `--esp` parameter.

```commandline
upnpfuzz --esp http://192.168.2.1:46560/rootDesc.xml --raw
```

### Generating requests without fuzzing

```commandline
upnpfuzz --ssdp 192.168.2.1:1900 --raw
```

### Fuzzing for command injections

```commandline
upnpfuzz --ssdp 192.168.2.1:1900 --injection
```

### Fuzzing for overflows

```commandline
upnpfuzz --ssdp 192.168.2.1:1900 --overflow
```

### Fuzzing using radamsa

```commandline
upnpfuzz --ssdp 192.168.2.1:1900 --radamsa
```

### Fuzzing using random strategy (injection/overflow/radamsa)
```commandline
upnpfuzz --ssdp 192.168.2.1:1900 --fuzz
```

### Additional Parameters

Use of `--delay` parameter. Specifying the amount of seconds that should be waited after sending every request.
```commandline
upnpfuzz --esp http://192.168.2.1:46560/rootDesc.xml --fuzz --delay 1
```

Use of `--alive-url` parameter. The url is checked after sending every request to verify if the target is still alive.
```commandline
upnpfuzz --esp http://192.168.2.1:46560/rootDesc.xml --fuzz --alive-url http://192.168.2.1:46560/rootDesc.xml
```

Use of `--crash-dir` parameter. Specifying the directory where the crashes should be saved.
```commandline
upnpfuzz --esp http://192.168.2.1:46560/rootDesc.xml --fuzz --alive-url http://192.168.2.1:46560/rootDesc.xml --crash-dir /tmp/crashes/
```

Use of `--restart-cmd`. Specifying the command (or script) that should be executed once the target crashed in order to restart the target.
```commandline
upnpfuzz --esp http://192.168.2.1:46560/rootDesc.xml --fuzz --alive-url http://192.168.2.1:46560/rootDesc.xml --restart-cmd /tmp/restart_target.sh
```

Use of `--radamsa-path`. Specifying the path to radamsa binary.
```commandline
upnpfuzz --esp http://192.168.2.1:46560/rootDesc.xml --fuzz --radamsa-path /Users/user/git/radamsa/bin/radamsa
```
