#!/bin/bash
# Secure WireGuard For CentOS, Debian, Ubuntu, Raspbian, Arch, Fedora, Redhat

# Sanity Checks and automagic
function root-check() {
  if [[ "$EUID" -ne 0 ]]; then
    echo "Sorry, you need to run this as root"
    exit
  fi
}

# Root Check
root-check

# Detect Operating System
function dist-check() {
  if [ -e /etc/centos-release ]; then
    DISTRO="CentOS"
  elif [ -e /etc/debian_version ]; then
    DISTRO=$( lsb_release -is )
  elif [ -e /etc/arch-release ]; then
    DISTRO="Arch"
  elif [ -e /etc/fedora-release ]; then
    DISTRO="Fedora"
  elif [ -e /etc/redhat-release ]; then
    DISTRO="Redhat"
  else
    echo "Your distribution is not supported (yet)."
    exit
  fi
}

# Check distro
dist-check

# Install Wireguard
function install-wireguard-client() {
  if [ "$DISTRO" == "Ubuntu" ]; then
    apt-get update
    apt-get install software-properties-common -y
    add-apt-repository ppa:wireguard/wireguard -y
    apt-get update
    apt-get install wireguard resolvconf linux-headers-$(uname -r) -y
  elif [ "$DISTRO" == "Debian" ]; then
    echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable.list
    printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable
    apt-get update
    apt-get install wireguard resolvconf linux-headers-$(uname -r) -y
  elif [ "$DISTRO" == "Raspbian" ]; then
    apt-get update
    echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable.list
    apt-get install dirmngr -y
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 04EE7237B7D453EC
    printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable
    apt-get update
    apt-get install wireguard raspberrypi-kernel-headers resolvconf -y
  elif [ "$DISTRO" == "Arch" ]; then
    pacman -Syy
    pacman -S openresolv wireguard-tools wireguard-arch
  elif [[ "$DISTRO" = 'Fedora' ]]; then
    dnf update
    dnf copr enable jdoss/wireguard -y
    dnf install kernel-devel-$(uname -r) resolvconf wireguard-dkms wireguard-tools -y
  elif [ "$DISTRO" == "CentOS" ]; then
    yum update
    wget -O /etc/yum.repos.d/wireguard.repo https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo
    yum install epel-release -y
    yum install wireguard-dkms wireguard-tools resolvconf kernel-headers-$(uname -r) kernel-devel-$(uname -r) -y
  elif [ "$DISTRO" == "Redhat" ]; then
    yum update
    wget -O /etc/yum.repos.d/wireguard.repo https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo
    yum install epel-release -y
    yum install wireguard-dkms wireguard-tools resolvconf kernel-headers-$(uname -r) kernel-devel-$(uname -r) -y
  fi
}

# Install WireGuard Client
install-wireguard-client
