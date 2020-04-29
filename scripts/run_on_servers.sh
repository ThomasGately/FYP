#run_on_servers.sh
#!/bin/bash

hostname=$(hostname -I 2>&1)

if [[ $hostname == *"192.168.1.21"* ]]; then
	./build/main.out test_server 6969 $hostname;
fi
if [[ $hostname == *"192.168.1.34"* ]]; then
	./build/main.out test_server 9001 $hostname
fi
if [[ $hostname == *"192.168.1.33"* ]]; then
	./build/main.out test_server 9002 $hostname
fi
if [[ $hostname == *"192.168.1.32"* ]]; then
	./build/main.out test_server 9003 $hostname
fi
if [[ $hostname == *"192.168.1.30"* ]]; then
	./build/main.out test_server 9004 $hostname
fi


#ssh -t ubuntu@192.168.1.34 "cd FYP; sudo ./build/test_server.out 9001 192.168.1.34 &"
#ssh -t ubuntu@192.168.1.33 "cd FYP; sudo ./build/test_server.out 9002 192.168.1.33 &"
#ssh -t ubuntu@192.168.1.32 "cd FYP; sudo ./build/test_server.out 9003 192.168.1.32 &"
#ssh -t ubuntu@192.168.1.30 "cd FYP; sudo ./build/test_server.out 9004 192.168.1.30 &"