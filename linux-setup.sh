#!/bin/bash

git pull && \
cargo xtask build --release && \
sudo cp nullnet-ebpf.service /etc/systemd/system/ && \
sudo systemctl enable nullnet-ebpf && \
sudo systemctl restart nullnet-ebpf
