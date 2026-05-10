#!/usr/bin/env bash

# Mitigate CopyFail (https://copy.fail) by not loading affected kernel modules
# GitHub: https://github.com/theori-io/copy-fail-CVE-2026-31431
# Check to ensure this script is running as root (or with sudo)
# Check to see if / is mounted read-only. If it is, re-mount as rw. Re-mount
#   back to read-only when the script is done

modules=(
  algif_aead
)

if [[ $(id -u) != 0 ]]; then
  echo "Error: This program must be run as root" >&2
  exit 1
fi

remounted=false
if findmnt -n -o OPTIONS / | grep -qw ro; then
  mount -o remount,rw /
  (( $? != 0 )) echo "Error: Could not remount root as read-write" >&2 && exit 1
  remounted=true
fi

printf "install %s /bin/false\n" "${modules[@]}" > /etc/modprobe.d/copyfail.conf
rmmod "${modules[@]}"
sudo modprobe -r "${modules[@]}"

if $remounted; then
  mount -o remount,ro /
  (( $? != 0 )) echo "Error: Could not remount root as read-only" >&2 && exit 1
fi

