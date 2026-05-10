#!/usr/bin/env bash

# Mitigate CopyFail2 (https://afflicted.sh/blog/posts/copy-fail-2.html)
# GitHub: https://github.com/0xdeadbeefnetwork/Copy_Fail2-Electric_Boogaloo
# Check to ensure this script is running as root (or with sudo)
# Check to see if / is mounted read-only. If it is, re-mount as rw. Re-mount
#   back to read-only when the script is done

modules=(
  nft_xfrm
  xfrm4_tunnel
  xfrm6_tunnel
  xfrm_algo
  xfrm_interface
  xfrm_ipcomp
  xfrm_iptfs
  xfrm_user
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

printf "install %s /bin/false\n" "${modules[@]}" > /etc/modprobe.d/copyfail2.conf
rmmod "${modules[@]}"
sudo modprobe -r "${modules[@]}"

if $remounted; then
  mount -o remount,ro /
  (( $? != 0 )) echo "Error: Could not remount root as read-only" >&2 && exit 1
fi

