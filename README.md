# PVT
PCAP visualization tool

<p align="center">
  <img src="https://raw.githubusercontent.com/Sh3lldor/PVT/main/static/pics/icon.png">
</p>

## Table of Contents
- [Overview](#Overview)
- [Docker Installation](#Docker)
- [Credits](#Credits)


## Overview

The Server panel will display all added server and basic information about the server such as: owned user, open port and if has been pwned.

## Docker

Build with docker-compose
```
cd PVT
docker-compose up -d
```

Start/Stop the container
```
sudo docker-compose start/stop
```

Save/Load PVT
```
docker save PVT:latest neo4j:latest > PVT.tar
docker load < PVT.tar
```

## Credits
* Pictures and Icons
    * https://www.iconfinder.com
        * licensed by - https://creativecommons.org/licenses/by/4.0
