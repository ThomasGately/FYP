#run_stuff.sh
#!/bin/bash

#ssh-copy-id ubuntu@192.168.1.34
#ssh-copy-id ubuntu@192.168.1.33
#ssh-copy-id ubuntu@192.168.1.32
#ssh-copy-id ubuntu@192.168.1.30

#cmd='make -C FYP/'
#cmd='sudo apt update; sudo apt install libssl-dev build-essential zlib1g-dev cmake -y'
#cmd='git clone git@github.com:ThomasGately/fyp_test_Repository_1.git project/'
#cmd='git clone git@github.com:ThomasGately/fyp_test_Repository_1.git FYP/project/'
#cmd='cd FYP/project; git pull'
#cmd='cd FYP; git checkout -- .; git pull --force; make -C FYP/'
#cmd='git clone --recursive https://github.com/sebastiandev/zipper.git;cd zipper;mkdir build;cd build;cmake ../;make;sudo make install'
cmd='git clone --recursive https://github.com/sebastiandev/zipper.git;cd zipper;mkdir build;cd build;cmake ../;make;sudo make install'

ssh -t ubuntu@192.168.1.34 $cmd
ssh -t ubuntu@192.168.1.33 $cmd
ssh -t ubuntu@192.168.1.32 $cmd
ssh -t ubuntu@192.168.1.30 $cmd
