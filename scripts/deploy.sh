#deploy.sh
#!/bin/bash

cmd="rm -fr FYP; git clone git@github.com:ThomasGately/FYP.git; git clone git@github.com:ThomasGately/fyp_test_Repository_1.git FYP/project;  git checkout origin/testing_new_socket; make -C FYP"

ssh -t ubuntu@192.168.1.34 $cmd
ssh -t ubuntu@192.168.1.33 $cmd
ssh -t ubuntu@192.168.1.32 $cmd
ssh -t ubuntu@192.168.1.30 $cmd