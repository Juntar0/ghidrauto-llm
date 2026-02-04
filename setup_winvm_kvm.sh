#!/usr/bin/env bash
set -euo pipefail

# Ubuntu 24.04: Create a Windows VM using KVM/libvirt with a host-only network.
#
# Usage:
#   chmod +x setup_winvm_kvm.sh
#   ISO_PATH=/home/ubuntu/isos/Win11.iso VM_NAME=win11-eval ./setup_winvm_kvm.sh
#
# Notes:
# - This script does NOT download Windows ISOs.
# - It creates a host-only libvirt network (no forwarding) and a VM attached to it.
# - For safety/compatibility, the default NIC model is e1000e.
# - Win11 often expects UEFI + TPM. TPM is optional here (TPM=1). You can also bypass checks in the installer.

# === CONFIG (override via env) ===
VM_NAME="${VM_NAME:-win11-eval}"
ISO_PATH="${ISO_PATH:-/path/to/Win11_English_x64.iso}"   # <-- set this
DISK_GB="${DISK_GB:-80}"
RAM_MB="${RAM_MB:-8192}"
VCPUS="${VCPUS:-4}"

# Host-only libvirt network
NET_NAME="${NET_NAME:-hostonly}"
NET_CIDR="${NET_CIDR:-192.168.56.0/24}"
NET_GW="${NET_GW:-192.168.56.1}"
DHCP_START="${DHCP_START:-192.168.56.50}"
DHCP_END="${DHCP_END:-192.168.56.200}"

# VM disk path
DISK_PATH="${DISK_PATH:-/var/lib/libvirt/images/${VM_NAME}.qcow2}"

# If you want UEFI (recommended for Win11)
UEFI="${UEFI:-1}"   # 1=yes, 0=no
TPM="${TPM:-0}"     # 1=yes, 0=no

# === sanity ===
if [[ ! -f "$ISO_PATH" ]]; then
  echo "ERROR: ISO not found at: $ISO_PATH"
  echo "Set ISO_PATH=/path/to/windows.iso"
  exit 1
fi

echo "[1/5] Installing KVM/libvirt tooling..."
sudo apt-get update
sudo apt-get install -y \
  qemu-kvm \
  libvirt-daemon-system \
  libvirt-clients \
  virt-install \
  ovmf \
  swtpm

echo "[2/5] Enabling libvirt..."
sudo systemctl enable --now libvirtd

echo "[3/5] Adding current user to libvirt/kvm groups (re-login required)..."
sudo usermod -aG libvirt,kvm "$USER" || true

echo "[4/5] Creating host-only libvirt network: $NET_NAME"
if sudo virsh net-info "$NET_NAME" >/dev/null 2>&1; then
  echo "Network $NET_NAME already exists. Skipping create."
else
  TMP_XML="$(mktemp)"
  cat >"$TMP_XML" <<XML
<network>
  <name>${NET_NAME}</name>
  <forward mode='none'/>
  <bridge name='virbr56' stp='on' delay='0'/>
  <ip address='${NET_GW}' netmask='255.255.255.0'>
    <dhcp>
      <range start='${DHCP_START}' end='${DHCP_END}'/>
    </dhcp>
  </ip>
</network>
XML
  sudo virsh net-define "$TMP_XML"
  sudo virsh net-autostart "$NET_NAME"
  sudo virsh net-start "$NET_NAME"
  rm -f "$TMP_XML"
fi

echo "[5/5] Creating VM disk + defining VM: $VM_NAME"
if sudo virsh dominfo "$VM_NAME" >/dev/null 2>&1; then
  echo "VM $VM_NAME already exists. Skipping virt-install."
  echo "If you want to recreate it:"
  echo "  sudo virsh undefine --nvram $VM_NAME"
  echo "  sudo rm -f $DISK_PATH"
  exit 0
fi

sudo qemu-img create -f qcow2 "$DISK_PATH" "${DISK_GB}G"

EXTRA_ARGS=()
if [[ "$UEFI" == "1" ]]; then
  EXTRA_ARGS+=( --boot uefi )
fi

if [[ "$TPM" == "1" ]]; then
  EXTRA_ARGS+=( --tpm backend.type=emulator,backend.version=2.0,model=tpm-crb )
fi

sudo virt-install \
  --name "$VM_NAME" \
  --memory "$RAM_MB" \
  --vcpus "$VCPUS" \
  --cpu host \
  --disk "path=$DISK_PATH,format=qcow2,bus=sata" \
  --cdrom "$ISO_PATH" \
  --network "network=$NET_NAME,model=e1000e" \
  --graphics spice \
  --sound ich9 \
  --video qxl \
  --os-variant win11 \
  --features kvm_hidden=on \
  --noautoconsole \
  "${EXTRA_ARGS[@]}"

echo
echo "Done."
echo "Next:"
echo "  - Re-login (group changes) or run: newgrp libvirt"
echo "  - VM console: virt-manager (GUI) or: sudo virsh console $VM_NAME"
echo "  - Inside Windows, find/set IP: ipconfig"
echo "  - Recommended: set Windows static IP in ${NET_CIDR} (e.g., 192.168.56.50)"
