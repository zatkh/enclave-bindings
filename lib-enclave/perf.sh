#!/bin/bash

OUT=$1
PERF_PATH=perf
#$HOME/Documents/linux-4.15.11/tools/perf/perf
ITTER=$2
EXE=$3


#sudo $PERF_PATH stat -o ./results/$1.txt $EXE
rm -rf test.db
sudo $PERF_PATH stat -o ./results/$1_ukh.txt -r $ITTER -B --event=cpu-cycles:{k,u,h} --event=bus-cycles:{k,u,h} --event=cycles:{k,u,h} --event=instructions:{k,u,h} --event=cache-references:{k,u,h} --event=cache-misses:{k,u,h} --event=bus-cycles:{k,u,h} -D 5 $EXE
rm -rf test.db
sudo $PERF_PATH stat -o ./results/$1.txt -r $ITTER -B -a -ddd -D 5 $EXE
rm -rf test.db
sudo $PERF_PATH stat -o ./results/$1_l1.txt -r $ITTER -B -e L1-dcache-loads,L1-dcache-load-misses,L1-dcache-stores -ddd -D 5 $EXE
rm -rf test.db
sudo $PERF_PATH stat -o ./results/$1_tlb.txt -r $ITTER -B -e dTLB-loads,dTLB-load-misses,dTLB-prefetch-misses -ddd -D 5 $EXE
rm -rf test.db
sudo $PERF_PATH stat -o ./results/$1_llc.txt -r $ITTER -B -e LLC-loads,LLC-load-misses,LLC-stores,LLC-prefetches -ddd -D 5 $EXE
rm -rf test.db
strace -c -o ./results/$1_all_syscalls.txt $EXE
rm -rf test.db

#sudo $PERF_PATH status -o ./results/$1.txt $EXE
