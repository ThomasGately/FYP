#run_on_servers.sh
#!/bin/bash


ssh -t ubuntu@192.168.1.34 "cd FYP; sudo ./build/test_server.out 9001 192.168.1.34 &"
ssh -t ubuntu@192.168.1.33 "cd FYP; sudo ./build/test_server.out 9002 192.168.1.33 &"
ssh -t ubuntu@192.168.1.32 "cd FYP; sudo ./build/test_server.out 9003 192.168.1.32 &"
ssh -t ubuntu@192.168.1.30 "cd FYP; sudo ./build/test_server.out 9004 192.168.1.30 &"