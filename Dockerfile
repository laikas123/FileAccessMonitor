FROM ubuntu:22.10

RUN apt-get update && \
    apt-get upgrade && \
    apt-get install nano && \
    apt-get update && \
    apt-get install -y apt-transport-https ca-certificates curl clang llvm jq && \
    apt-get install -y libelf-dev libpcap-dev libbfd-dev binutils-dev build-essential make && \
    apt-get install -y linux-tools-common linux-tools-generic bpfcc-tools && \
    apt-get install -y python3-pip && \
    apt-get install -y git && \
    git clone https://github.com/libbpf/libbpf.git && \
    cd libbpf/src && \
    make install && \
    cd / &&\
    git clone --recurse-submodules https://github.com/libbpf/bpftool.git && \
    cd bpftool/src && \
    make install && \
    cd / && \
    git clone https://github.com/laikas123/FileAccessMonitor.git 
    