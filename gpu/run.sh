#!/bin/bash 
nvcc -O3 -arch=sm_75 -Xptxas -v miner.cu -o miner
./miner