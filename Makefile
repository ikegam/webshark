# Build and deploy webshark to a Linux gateway over SSH.
#
# webshark is meant to run only while debugging: deploy installs it but does
# not enable or start it.
#
#   make deploy                      # build, copy, install (stays stopped)
#   make start [DURATION=2h]         # open the UI port on the LAN and start;
#                                    # it stops by itself after DURATION
#   make stop                        # stop now and close the UI port
#   make deploy HOST=10.0.0.1 IFACE=eth1 BIND=10.0.0.1:3000 LAN_IFACE=eth1
#   make data                        # download GeoIP + OUI (MAC vendor) data now
#   make status | make logs | make undeploy
#
# Requirements on the target: tshark (dumpcap with capture capabilities),
# systemd, sudo, ufw. The binary is a static musl build, so no Rust toolchain
# is needed there.

HOST      ?= 192.168.0.1
IFACE     ?= enp3s0
BIND      ?= $(HOST):3000
LAN_IFACE ?= enp3s0
PORT      := $(lastword $(subst :, ,$(BIND)))
DURATION  ?= 2h
TARGET    := x86_64-unknown-linux-musl
BIN       := target/$(TARGET)/release/webshark
SSH       ?= ssh
SCP       ?= scp

.PHONY: all build test fmt-check check deploy remote-install start stop data geoip status logs undeploy clean

all: build

build:
	cargo build --release --target $(TARGET)

test:
	cargo test

fmt-check:
	cargo fmt -- --check

check: test build

# Files are staged in a private directory made by `mktemp -d` on the target
# (mode 0700, owned by the SSH user): a fixed /tmp path could be pre-created
# by another local user, who could then swap in a script that gets installed
# and run as root.
deploy: check
	@stage=$$($(SSH) $(HOST) 'mktemp -d /tmp/webshark-deploy.XXXXXXXX') && test -n "$$stage" && \
	  echo "staging in $(HOST):$$stage" && \
	  { $(SCP) $(BIN) deploy/webshark.service deploy/webshark-ctl deploy/webshark-data-update deploy/webshark-data.service deploy/webshark-data.timer $(HOST):$$stage/ && \
	    sed -e 's|@BIND@|$(BIND)|' -e 's|@IFACE@|$(IFACE)|' -e 's|@LAN_IFACE@|$(LAN_IFACE)|' deploy/webshark.env | $(SSH) $(HOST) "cat > $$stage/webshark.env" && \
	    $(MAKE) --no-print-directory remote-install STAGE=$$stage; } || \
	  { $(SSH) $(HOST) "rm -rf $$stage"; echo "deploy failed; removed $$stage" >&2; exit 1; }
	@echo "==> installed (not running). Start a debugging session with: make start [DURATION=2h]"

remote-install:
	@test -n "$(STAGE)" || { echo "STAGE is not set (use make deploy)" >&2; exit 1; }
	$(SSH) $(HOST) 'set -e; \
	  command -v tshark >/dev/null || { echo "tshark is not installed on $(HOST)" >&2; exit 1; }; \
	  id webshark >/dev/null 2>&1 || sudo useradd --system --no-create-home --shell /usr/sbin/nologin webshark; \
	  sudo usermod -aG wireshark webshark; \
	  sudo install -m 0755 $(STAGE)/webshark /usr/local/bin/webshark; \
	  sudo install -m 0644 $(STAGE)/webshark.service /etc/systemd/system/webshark.service; \
	  sudo install -m 0644 $(STAGE)/webshark.env /etc/default/webshark; \
	  sudo install -m 0755 $(STAGE)/webshark-data-update /usr/local/sbin/webshark-data-update; \
	  sudo install -m 0755 $(STAGE)/webshark-ctl /usr/local/sbin/webshark-ctl; \
	  sudo install -m 0644 $(STAGE)/webshark-data.service $(STAGE)/webshark-data.timer /etc/systemd/system/; \
	  if [ -e /etc/systemd/system/webshark-geoip.timer ]; then \
	    sudo systemctl disable --now webshark-geoip.timer >/dev/null 2>&1 || true; \
	    sudo rm -f /etc/systemd/system/webshark-geoip.service /etc/systemd/system/webshark-geoip.timer /usr/local/sbin/webshark-geoip-update; \
	  fi; \
	  rm -rf $(STAGE); \
	  sudo systemctl daemon-reload; \
	  sudo systemctl disable webshark >/dev/null 2>&1 || true; \
	  sudo systemctl enable --now webshark-data.timer >/dev/null 2>&1; \
	  if systemctl is-active --quiet webshark; then sudo systemctl restart webshark; echo "restarted the running session"; fi; \
	  /usr/local/sbin/webshark-ctl status'

# Debugging session: the UI port is opened on the LAN interface only (the WAN
# side stays closed) and webshark stops by itself after DURATION.
start:
	$(SSH) $(HOST) 'sudo /usr/local/sbin/webshark-ctl start $(DURATION)'

stop:
	$(SSH) $(HOST) 'sudo /usr/local/sbin/webshark-ctl stop'

# Download/refresh GeoIP + OUI data now (also refreshed monthly by a timer).
data:
	$(SSH) $(HOST) 'sudo /usr/local/sbin/webshark-data-update'

geoip: data

status:
	$(SSH) $(HOST) '/usr/local/sbin/webshark-ctl status'

logs:
	$(SSH) $(HOST) 'journalctl -u webshark -n 100 --no-pager'

undeploy:
	$(SSH) $(HOST) 'sudo /usr/local/sbin/webshark-ctl stop 2>/dev/null || true; \
	  sudo systemctl disable --now webshark webshark-data.timer; \
	  sudo rm -f /etc/systemd/system/webshark.service /etc/systemd/system/webshark-data.service \
	    /etc/systemd/system/webshark-data.timer /usr/local/sbin/webshark-data-update /usr/local/sbin/webshark-ctl \
	    /usr/local/bin/webshark /etc/default/webshark; \
	  sudo systemctl daemon-reload; \
	  sudo ufw delete allow in on $(LAN_IFACE) to any port $(PORT) proto tcp || true'

clean:
	cargo clean
