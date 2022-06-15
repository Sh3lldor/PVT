# PVT
PCAP visualization tool

<p align="center">
  <img src="https://raw.githubusercontent.com/Sh3lldor/PVT/main/static/pics/icon.png">
</p>

## Table of Contents
- [Overview](#Overview)
- [Pictures](#Pics)
- [Docker Installation](#Docker)
- [Credits](#Credits)


## Overview
PVT will visualize a given PCAP with neo4j and neovis in an easy and intuitive way.

## Pics

<p align="center">
  <img src="https://raw.githubusercontent.com/Sh3lldor/PVT/main/static/pics/1.png">
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/Sh3lldor/PVT/main/static/pics/2.png">
</p>

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
