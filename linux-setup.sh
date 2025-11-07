#!/bin/bash

# Update nullnet.service file
sudo cp nullnet_ebpf.service /etc/systemd/system/ && \
sudo systemctl enable nullnet_ebpf && \
git checkout main && \
git pull && \
cargo xtask build --release && \
sudo reboot
