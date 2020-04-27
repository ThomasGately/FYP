#deploy.sh
#!/bin/bash

cmd="sudo kill $(ps aux | grep 'test_server.out' | awk '{print $2}')";

ssh -t ubuntu@192.168.1.34 $cmd
ssh -t ubuntu@192.168.1.33 $cmd
ssh -t ubuntu@192.168.1.32 $cmd
ssh -t ubuntu@192.168.1.30 $cmd