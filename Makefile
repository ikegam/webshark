# Build and deploy WebShark to a Linux gateway over SSH.
#
#   make deploy                      # build, copy, install, (re)start, open firewall
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
TARGET    := x86_64-unknown-linux-musl
BIN       := target/$(TARGET)/release/webshark
SSH       ?= ssh
SCP       ?= scp
STAGE     := /tmp/webshark-deploy

.PHONY: all build test fmt-check check deploy remote-install firewall data geoip status logs undeploy clean

all: build

build:
	cargo build --release --target $(TARGET)

test:
	cargo test

fmt-check:
	cargo fmt -- --check

check: test build

deploy: check
	$(SSH) $(HOST) 'mkdir -p $(STAGE)'
	$(SCP) $(BIN) deploy/webshark.service deploy/webshark-data-update deploy/webshark-data.service deploy/webshark-data.timer $(HOST):$(STAGE)/
	sed -e 's|@BIND@|$(BIND)|' -e 's|@IFACE@|$(IFACE)|' deploy/webshark.env | $(SSH) $(HOST) 'cat > $(STAGE)/webshark.env'
	$(MAKE) --no-print-directory remote-install firewall
	@echo "==> WebShark: http://$(BIND)/"

remote-install:
	$(SSH) $(HOST) 'set -e; \
	  command -v tshark >/dev/null || { echo "tshark is not installed on $(HOST)" >&2; exit 1; }; \
	  id webshark >/dev/null 2>&1 || sudo useradd --system --no-create-home --shell /usr/sbin/nologin webshark; \
	  sudo usermod -aG wireshark webshark; \
	  sudo install -m 0755 $(STAGE)/webshark /usr/local/bin/webshark; \
	  sudo install -m 0644 $(STAGE)/webshark.service /etc/systemd/system/webshark.service; \
	  sudo install -m 0644 $(STAGE)/webshark.env /etc/default/webshark; \
	  sudo install -m 0755 $(STAGE)/webshark-data-update /usr/local/sbin/webshark-data-update; \
	  sudo install -m 0644 $(STAGE)/webshark-data.service $(STAGE)/webshark-data.timer /etc/systemd/system/; \
	  if [ -e /etc/systemd/system/webshark-geoip.timer ]; then \
	    sudo systemctl disable --now webshark-geoip.timer >/dev/null 2>&1 || true; \
	    sudo rm -f /etc/systemd/system/webshark-geoip.service /etc/systemd/system/webshark-geoip.timer /usr/local/sbin/webshark-geoip-update; \
	  fi; \
	  rm -rf $(STAGE); \
	  sudo systemctl daemon-reload; \
	  sudo systemctl enable webshark >/dev/null 2>&1; \
	  sudo systemctl enable --now webshark-data.timer >/dev/null 2>&1; \
	  sudo systemctl restart webshark; \
	  sleep 2; systemctl is-active webshark'

# Allow the UI only from the LAN interface; the WAN side stays closed.
firewall:
	$(SSH) $(HOST) 'sudo ufw allow in on $(LAN_IFACE) to any port $(PORT) proto tcp comment webshark'

# Download/refresh GeoIP + OUI data now (also refreshed monthly by a timer).
data:
	$(SSH) $(HOST) 'sudo /usr/local/sbin/webshark-data-update'

geoip: data

status:
	$(SSH) $(HOST) 'systemctl status webshark --no-pager -l | head -20'

logs:
	$(SSH) $(HOST) 'journalctl -u webshark -n 100 --no-pager'

undeploy:
	$(SSH) $(HOST) 'sudo systemctl disable --now webshark webshark-data.timer; \
	  sudo rm -f /etc/systemd/system/webshark.service /etc/systemd/system/webshark-data.service \
	    /etc/systemd/system/webshark-data.timer /usr/local/sbin/webshark-data-update \
	    /usr/local/bin/webshark /etc/default/webshark; \
	  sudo systemctl daemon-reload; \
	  sudo ufw delete allow in on $(LAN_IFACE) to any port $(PORT) proto tcp || true'

clean:
	cargo clean
