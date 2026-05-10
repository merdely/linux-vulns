#!/usr/bin/env bash

# Mitigate DirtyFrag (https://github.com/v4bel/dirtyfrag)
# Check to ensure this script is running as root (or with sudo)
# Check to see if / is mounted read-only. If it is, re-mount as rw. Re-mount
#   back to read-only when the script is done

modules=(
  esp4
  esp6
  rxrpc
)

if [[ $(id -u) != 0 ]]; then
  echo "Error: This program must be run as root" >&2
  exit 1
fi

remounted=false
if findmnt -n -o OPTIONS / | grep -qw ro; then
  mount -o remount,rw /
  (( $? != 0 )) && echo "Error: Could not remount root as read-write" >&2 && exit 1
  remounted=true
fi

printf "install %s /bin/false\n" "${modules[@]}" > /etc/modprobe.d/dirtyfrag.conf
rmmod "${modules[@]}"
sudo modprobe -r "${modules[@]}"

if $remounted; then
  mount -o remount,ro /
  (( $? != 0 )) && echo "Error: Could not remount root as read-only" >&2 && exit 1
fi

