#!/usr/bin/env bash

cd pf-runner
chmod +x scripts/system-setup.sh
scripts/system-setup.sh update
scripts/system-setup.sh upgrade
scripts/system-setup.sh setup-venv
scripts/system-setup.sh install-base
make build
sudo make install
