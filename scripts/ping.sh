#!/bin/bash
#ping.sh

ping -c 1 192.168.1.30
ping -c 1 192.168.1.34
ping -c 1 192.168.1.33
ping -c 1 192.168.1.32

telnet 192.168.1.30 8001
telnet 192.168.1.34 8002
telnet 192.168.1.33 8003
telnet 192.168.1.32 8004