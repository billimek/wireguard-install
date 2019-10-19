#!/bin/bash
# Secure WireGuard For CentOS, Debian, Ubuntu, Raspbian, Arch, Fedora, Redhat

# Check Root Function
function root-check() {
  if [[ "$EUID" -ne 0 ]]; then
    echo "Hello there non ROOT user, you need to run this as ROOT."
    exit
  fi
}

# Root Check
root-check

# Checking For Virtualization
function virt-check() {
  # Deny OpenVZ
  if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo "OpenVZ virtualization is not supported (yet)."
    exit
  fi
  # Deny LXC
  if [ "$(systemd-detect-virt)" == "lxc" ]; then
    echo "LXC virtualization is not supported (yet)."
    exit
  fi
}

# Virtualization Check
virt-check

# Detect Operating System
function dist-check() {
  if [ -e /etc/centos-release ]; then
    DISTRO="CentOS"
  elif [ -e /etc/debian_version ]; then
    DISTRO=$(lsb_release -is)
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

# Check Operating System
dist-check

# Wireguard Public Network Interface
WIREGUARD_PUB_NIC="wg0"
# Location For WG_CONFIG
WG_CONFIG="/etc/wireguard/$WIREGUARD_PUB_NIC.conf"
if [ ! -f "$WG_CONFIG" ]; then
  # Yes or No For Questions
  INTERACTIVE=${INTERACTIVE:-yes}
  # Private Subnet Ipv4
  PRIVATE_SUBNET_V4=${PRIVATE_SUBNET_V4:-"10.8.0.0/24"}
  # Private Subnet Mask IPv4
  PRIVATE_SUBNET_MASK_V4=$(echo "$PRIVATE_SUBNET_V4" | cut -d "/" -f 2)
  # IPv4 Getaway
  GATEWAY_ADDRESS_V4="${PRIVATE_SUBNET_V4::-4}1"
  # Private Subnet Ipv6
  PRIVATE_SUBNET_V6=${PRIVATE_SUBNET_V6:-"fd42:42:42::0/64"}
  # Private Subnet Mask IPv6
  PRIVATE_SUBNET_MASK_V6=$(echo "$PRIVATE_SUBNET_V6" | cut -d "/" -f 2)
  # IPv6 Getaway
  GATEWAY_ADDRESS_V6="${PRIVATE_SUBNET_V6::-4}1"

  # Detect IPV4
  function detect-ipv4() {
    if type ping >/dev/null 2>&1; then
      PING="ping -c3 google.com > /dev/null 2>&1"
    else
      PING6="ping -4 -c3 google.com > /dev/null 2>&1"
    fi
    if eval "$PING"; then
      IPV4_SUGGESTION="y"
    else
      IPV4_SUGGESTION="n"
    fi
  }

  # Detect IPV4
  detect-ipv4

  # Test outward facing IPV4
  function test-connectivity-v4() {
    if [ "$SERVER_HOST_V4" == "" ]; then
      SERVER_HOST_V4="$(wget -qO- -t1 -T2 ipv4.icanhazip.com)"
      if [ "$INTERACTIVE" == "yes" ]; then
        read -rp "System public IPV4 address is $SERVER_HOST_V4. Is that correct? [y/n]: " -e -i "$IPV4_SUGGESTION" CONFIRM
        if [ "$CONFIRM" == "n" ]; then
          echo "Aborted. Use environment variable SERVER_HOST_V4 to set the correct public IP address."
        fi
      fi
    fi
  }

  # Test IPV4 Connectivity
  test-connectivity-v4

  # Detect IPV6
  function detect-ipv6() {
    if type ping >/dev/null 2>&1; then
      PING6="ping6 -c3 ipv6.google.com > /dev/null 2>&1"
    else
      PING6="ping -6 -c3 ipv6.google.com > /dev/null 2>&1"
    fi
    if eval "$PING6"; then
      IPV6_SUGGESTION="y"
    else
      IPV6_SUGGESTION="n"
    fi
  }

  # Test IPV6 Connectivity
  detect-ipv6

  # Test outward facing IPV6
  function test-connectivity-v6() {
    if [ "$SERVER_HOST_V6" == "" ]; then
      SERVER_HOST_V6="$(wget -qO- -t1 -T2 ipv6.icanhazip.com)"
      if [ "$INTERACTIVE" == "yes" ]; then
        read -rp "System public IPV6 address is $SERVER_HOST_V6. Is that correct? [y/n]: " -e -i "$IPV6_SUGGESTION" CONFIRM
        if [ "$CONFIRM" == "n" ]; then
          echo "Aborted. Use environment variable SERVER_HOST_V6 to set the correct public IP address."
        fi
      fi
    fi
  }

  # Test IPV6 Connectivity
  test-connectivity-v6

  # Detect public interface and pre-fill for the user
  function server-pub-nic() {
    if [ "$SERVER_PUB_NIC" == "" ]; then
      SERVER_PUB_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
      if [ "$INTERACTIVE" == "yes" ]; then
        read -rp "System public nic address is $SERVER_PUB_NIC. Is that correct? [y/n]: " -e -i y CONFIRM
        if [ "$CONFIRM" == "n" ]; then
          echo "Aborted. Use environment variable SERVER_PUB_NIC to set the correct public IP address."
        fi
      fi
    fi
  }

  # Run The Function
  server-pub-nic

  # Determine host port
  function set-port() {
    echo "What port do you want WireGuard server to listen to?"
    echo "   1) 51820 (Recommended)"
    echo "   2) Custom (Advanced)"
    echo "   3) Random [1024-65535]"
    until [[ "$PORT_CHOICE" =~ ^[1-3]$ ]]; do
      read -rp "Port choice [1-3]: " -e -i 1 PORT_CHOICE
    done
    # Apply port response
    case $PORT_CHOICE in
    1)
      SERVER_PORT="51820"
      ;;
    2)
      until [[ "$SERVER_PORT" =~ ^[0-9]+$ ]] && [ "$SERVER_PORT" -ge 1 ] && [ "$SERVER_PORT" -le 65535 ]; do
        read -rp "Custom port [1-65535]: " -e -i 51820 SERVER_PORT
      done
      ;;
    3)
      SERVER_PORT=$(shuf -i1024-65535 -n1)
      echo "Random Port: $SERVER_PORT"
      ;;
    esac
  }

  # Set Port
  set-port

  # Determine Keepalive interval.
  function nat-keepalive() {
    echo "What do you want your keepalive interval to be?"
    echo "   1) 25 (Default)"
    echo "   2) 0 "
    echo "   3) Custom (Advanced)"
    until [[ "$NAT_CHOICE" =~ ^[1-3]$ ]]; do
      read -rp "Nat Choice [1-3]: " -e -i 1 NAT_CHOICE
    done
    # Nat Choices
    case $NAT_CHOICE in
    1)
      NAT_CHOICE="25"
      ;;
    2)
      NAT_CHOICE="0"
      ;;
    3)
      until [[ "$NAT_CHOICE " =~ ^[0-9]+$ ]] && [ "$NAT_CHOICE " -ge 1 ] && [ "$NAT_CHOICE " -le 25 ]; do
        read -rp "Custom NAT [0-25]: " -e -i 25 NA_CHOICE
      done
      ;;
    esac
  }

  # Keepalive
  nat-keepalive

  # Custom MTU or default settings
  function mtu-set() {
    echo "What MTU do you want to use?"
    echo "   1) 1280 (Recommended)"
    echo "   2) 1420"
    echo "   3) Custom (Advanced)"
    until [[ "$MTU_CHOICE" =~ ^[1-3]$ ]]; do
      read -rp "MTU choice [1-3]: " -e -i 1 MTU_CHOICE
    done
    case $MTU_CHOICE in
    1)
      MTU_CHOICE="1280"
      ;;
    2)
      MTU_CHOICE="1420"
      ;;
    3)
      until [[ "$MTU_CHOICE" =~ ^[0-9]+$ ]] && [ "$MTU_CHOICE" -ge 1 ] && [ "$MTU_CHOICE" -le 1500 ]; do
        read -rp "Custom MTU [1-1500]: " -e -i 1500 MTU_CHOICE
      done
      ;;
    esac
  }

  # Set MTU
  mtu-set

  # What ip version would you like to be available on this VPN?
  function ipvx-select() {
    echo "What IPv do you want to use to connect to WireGuard server?"
    echo "   1) IPv4 (Recommended)"
    echo "   2) IPv6 (Advanced)"
    until [[ "$SERVER_HOST" =~ ^[1-2]$ ]]; do
      read -rp "IP Choice [1-2]: " -e -i 1 SERVER_HOST
    done
    case $SERVER_HOST in
    1)
      SERVER_HOST="$SERVER_HOST_V4"
      ;;
    2)
      SERVER_HOST="[$SERVER_HOST_V6]"
      ;;
    esac
  }

  # IPv4 or IPv6 Selector
  ipvx-select

  # Do you want to disable IPv4 or IPv6 or leave them both enabled?
  function disable-ipvx() {
    echo "Do you want to disable IPv4 or IPv6 on the server?"
    echo "   1) No (Recommended)"
    echo "   2) IPV4"
    echo "   3) IPV6"
    until [[ "$DISABLE_HOST" =~ ^[1-3]$ ]]; do
      read -rp "Disable Host Choice [1-3]: " -e -i 1 DISABLE_HOST
    done
    case $DISABLE_HOST in
    1)
      DISABLE_HOST="$(
        echo "net.ipv4.ip_forward=1" >>/etc/sysctl.d/wireguard.conf
        echo "net.ipv6.conf.all.forwarding=1" >>/etc/sysctl.d/wireguard.conf
        sysctl --system
      )"
      ;;
    2)
      DISABLE_HOST="$(
        echo "net.ipv4.conf.all.disable_ipv4=1" >>/etc/sysctl.d/wireguard.conf
        echo "net.ipv4.conf.default.disable_ipv4=1" >>/etc/sysctl.d/wireguard.conf
        echo "net.ipv6.conf.all.forwarding=1" >>/etc/sysctl.d/wireguard.conf
        sysctl --system
      )"
      ;;
    3)
      DISABLE_HOST="$(
        echo "net.ipv6.conf.all.disable_ipv6 = 1" >>/etc/sysctl.d/wireguard.conf
        echo "net.ipv6.conf.default.disable_ipv6 = 1" >>/etc/sysctl.d/wireguard.conf
        echo "net.ipv6.conf.lo.disable_ipv6 = 1" >>/etc/sysctl.d/wireguard.conf
        echo "net.ipv4.ip_forward=1" >>/etc/sysctl.d/wireguard.conf
        sysctl --system
      )"
      ;;
    esac
  }

  # Disable Ipv4 or Ipv6
  disable-ipvx

  # Would you like to allow connections to your LAN neighbors?
  function client-allowed-ip() {
    echo "What traffic do you want the client to forward to wireguard?"
    echo "   1) Everything (Recommended)"
    echo "   2) Exclude Private IPs (Allows LAN IP connections)"
    until [[ "$CLIENT_ALLOWED_IP" =~ ^[1-2]$ ]]; do
      read -rp "Client Allowed IP Choice [1-2]: " -e -i 1 CLIENT_ALLOWED_IP
    done
    case $CLIENT_ALLOWED_IP in
    1)
      CLIENT_ALLOWED_IP="0.0.0.0/0,::/0"
      ;;
    2)
      CLIENT_ALLOWED_IP="0.0.0.0/5, 8.0.0.0/7, 11.0.0.0/8, 12.0.0.0/6, 16.0.0.0/4, 32.0.0.0/3, 64.0.0.0/2, 128.0.0.0/3, 160.0.0.0/5, 168.0.0.0/6, 172.0.0.0/12, 172.32.0.0/11, 172.64.0.0/10, 172.128.0.0/9, 173.0.0.0/8, 174.0.0.0/7, 176.0.0.0/4, 192.0.0.0/9, 192.128.0.0/11, 192.160.0.0/13, 192.169.0.0/16, 192.170.0.0/15, 192.172.0.0/14, 192.176.0.0/12, 192.192.0.0/10, 193.0.0.0/8, 194.0.0.0/7, 196.0.0.0/6, 200.0.0.0/5, 208.0.0.0/4, ::/0, 176.103.130.130/32, 176.103.130.131/32"
      ;;
    esac
  }

  # Traffic Forwarding
  client-allowed-ip

  # Would you like to install Unbound.
  function ask-install-dns() {
    read -rp "Do You Want To Install Unbound (y/n): " -e -i y INSTALL_UNBOUND
  if [ "$INSTALL_UNBOUND" == "n" ]; then
    read -rp "Do You Want To Install Pi-Hole (y/n): " -e -i y INSTALL_PIHOLE
  fi
  }

  # Ask To Install DNS
  ask-install-dns

  # What would you like to name your first WireGuard peer?
  function client-name() {
    echo "Tell me a name for the client config file. Use one word only, no special characters. (No Spaces)"
    read -rp "Client Name: " -e CLIENT_NAME
  }

  # Client Name
  client-name

  # Install WireGuard Server
function install-wireguard-server() {
  # Installation begins here.
  if [ "$DISTRO" == "Ubuntu" ]; then
    apt-get update
    apt-get install software-properties-common -y
    add-apt-repository ppa:wireguard/wireguard -y
    apt-get update
    apt-get install wireguard qrencode linux-headers-"$(uname -r)" haveged curl resolvconf -y
  elif [ "$DISTRO" == "Debian" ]; then
    apt-get update
    echo "deb http://deb.debian.org/debian/ unstable main" >/etc/apt/sources.list.d/unstable.list
    printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' >/etc/apt/preferences.d/limit-unstable
    apt-get update
    apt-get install wireguard qrencode linux-headers-"$(uname -r)" haveged curl resolvconf -y
  elif [ "$DISTRO" == "Raspbian" ]; then
    apt-get update
    echo "deb http://deb.debian.org/debian/ unstable main" >/etc/apt/sources.list.d/unstable.list
    apt-get install dirmngr -y
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 04EE7237B7D453EC
    printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' >/etc/apt/preferences.d/limit-unstable
    apt-get update
    apt-get install wireguard qrencode raspberrypi-kernel-headers haveged curl resolvconf -y
  elif [ "$DISTRO" == "Arch" ]; then
    pacman -S linux-headers wireguard-tools wireguard-arch haveged qrencode curl resolvconf 
  elif [ "$DISTRO" = 'Fedora' ]; then
    dnf update -y
    dnf copr enable jdoss/wireguard -y
    dnf install qrencode kernel-headers-"$(uname -r)" kernel-devel-"$(uname -r)" wireguard-dkms wireguard-tools haveged curl resolvconf -y
  elif [ "$DISTRO" == "CentOS" ]; then
    yum update -y
    wget -O /etc/yum.repos.d/wireguard.repo https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo
    yum install epel-release -y
    yum install wireguard-dkms wireguard-tools qrencode kernel-headers-"$(uname -r)" kernel-devel-"$(uname -r)" haveged curl resolvconf -y
  elif [ "$DISTRO" == "Redhat" ]; then
    yum update -y
    wget -O /etc/yum.repos.d/wireguard.repo https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo
    yum install epel-release -y
    yum install wireguard-dkms wireguard-tools qrencode kernel-headers-"$(uname -r)" kernel-devel-"$(uname -r)" haveged curl resolvconf -y
  fi
  }

  # Install WireGuard Server
  install-wireguard-server

  # Function to install unbound
  function install-unbound() {
  if [ "$INSTALL_UNBOUND" = "y" ]; then
  # Installation Begins Here
  if [ "$DISTRO" == "Ubuntu" ]; then
    # Install Unbound
    apt-get install unbound unbound-host e2fsprogs -y
    # Set Config
    echo 'server:
    num-threads: 4
    verbosity: 1
    root-hints: "/etc/unbound/root.hints"
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    interface: 0.0.0.0
    interface: ::0
    max-udp-size: 3072
    access-control: 0.0.0.0/0                 refuse
    access-control: 10.8.0.0/24               allow
    private-address: 10.8.0.0/24
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-referral-path: yes
    unwanted-reply-threshold: 10000000
    val-log-level: 1
    cache-min-ttl: 1800
    cache-max-ttl: 14400
    prefetch: yes
    qname-minimisation: yes
    prefetch-key: yes' >/etc/unbound/unbound.conf
    # Apply settings
    systemctl stop systemd-resolved
    systemctl disable systemd-resolved
  elif [ "$DISTRO" == "Debian" ]; then
    # Install Unbound
    apt-get install unbound unbound-host e2fsprogs -y
    # Set Config
    echo 'server:
    num-threads: 4
    verbosity: 1
    root-hints: "/etc/unbound/root.hints"
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    interface: 0.0.0.0
    interface: ::0
    max-udp-size: 3072
    access-control: 0.0.0.0/0                 refuse
    access-control: 10.8.0.0/24               allow
    private-address: 10.8.0.0/24
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-referral-path: yes
    unwanted-reply-threshold: 10000000
    val-log-level: 1
    cache-min-ttl: 1800
    cache-max-ttl: 14400
    prefetch: yes
    qname-minimisation: yes
    prefetch-key: yes' >/etc/unbound/unbound.conf
  elif [ "$DISTRO" == "Raspbian" ]; then
    # Install Unbound
    apt-get install unbound unbound-host e2fsprogs -y
    # Set Config
    echo 'server:
    num-threads: 4
    verbosity: 1
    root-hints: "/etc/unbound/root.hints"
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    interface: 0.0.0.0
    interface: ::0
    max-udp-size: 3072
    access-control: 0.0.0.0/0                 refuse
    access-control: 10.8.0.0/24               allow
    private-address: 10.8.0.0/24
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-referral-path: yes
    unwanted-reply-threshold: 10000000
    val-log-level: 1
    cache-min-ttl: 1800
    cache-max-ttl: 14400
    prefetch: yes
    qname-minimisation: yes
    prefetch-key: yes' >/etc/unbound/unbound.conf
  elif [[ "$DISTRO" == "CentOS" ]]; then
    # Install Unbound
    yum install unbound unbound-libs -y
    sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
    sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
    sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
    sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
    sed -i 's|use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf
  elif [[ "$DISTRO" == "Fedora" ]]; then
    dnf install unbound unbound-host -y
    sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
    sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
    sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
    sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
    sed -i 's|use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf
  elif [[ "$DISTRO" == "Arch" ]]; then
    pacman -S unbound unbound-host
    mv /etc/unbound/unbound.conf /etc/unbound/unbound.conf.old
    echo 'server:
    use-syslog: yes
    do-daemonize: no
    username: "unbound"
    directory: "/etc/unbound"
    trust-anchor-file: trusted-key.key
    root-hints: root.hints
    interface: 10.8.0.0
    access-control: 10.8.0.0 allow
    port: 53
    num-threads: 2
    use-caps-for-id: yes
    harden-glue: yes
    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes
    prefetch: yes' >/etc/unbound/unbound.conf
  fi
    # Set DNS Root Servers
    wget -O /etc/unbound/root.hints https://www.internic.net/domain/named.cache
    # Setting Client DNS For Unbound On WireGuard
    CLIENT_DNS="10.8.0.1"
    # Allow the modification of the file
    chattr -i /etc/resolv.conf
    # Disable previous DNS servers
    sed -i "s|nameserver|#nameserver|" /etc/resolv.conf
    sed -i "s|search|#search|" /etc/resolv.conf
    # Set localhost as the DNS resolver
    echo "nameserver 127.0.0.1" >> /etc/resolv.conf
    # Use -i to enable modifications
    chattr +i /etc/resolv.conf
    # Restart unbound
  if pgrep systemd-journal; then
    systemctl enable unbound
    systemctl restart unbound
  else
    service unbound restart
  fi
fi
  }

  # Running Install Unbound
  install-unbound

  # Install Pi-Hole
  function install-pihole() {
  if [ "$INSTALL_PIHOLE" = "y" ]; then
    curl -sSL https://install.pi-hole.net | bash
  fi
    # Set Client DNS
    CLIENT_DNS="10.8.0.1"
}

  # Run The Function
  install-pihole

  # Set correct time
  function set-correct-time() {
  dpkg-reconfigure tzdata
  }

  # Run the function
  set-correct-time

  # WireGuard Set Config
  function wireguard-setconf() {
    SERVER_PRIVKEY=$(wg genkey)
    SERVER_PUBKEY=$(echo "$SERVER_PRIVKEY" | wg pubkey)
    CLIENT_PRIVKEY=$(wg genkey)
    CLIENT_PUBKEY=$(echo "$CLIENT_PRIVKEY" | wg pubkey)
    CLIENT_ADDRESS_V4="${PRIVATE_SUBNET_V4::-4}3"
    CLIENT_ADDRESS_V6="${PRIVATE_SUBNET_V6::-4}3"
    PRESHARED_KEY=$(wg genpsk)
    mkdir -p /etc/wireguard
    mkdir -p /etc/wireguard/clients
    touch $WG_CONFIG && chmod 600 $WG_CONFIG
    # Set Wireguard settings for this host and first peer.

    echo "# $PRIVATE_SUBNET_V4 $PRIVATE_SUBNET_V6 $SERVER_HOST:$SERVER_PORT $SERVER_PUBKEY $CLIENT_DNS $MTU_CHOICE $NAT_CHOICE $CLIENT_ALLOWED_IP
[Interface]
Address = $GATEWAY_ADDRESS_V4/$PRIVATE_SUBNET_MASK_V4,$GATEWAY_ADDRESS_V6/$PRIVATE_SUBNET_MASK_V6
ListenPort = $SERVER_PORT
PrivateKey = $SERVER_PRIVKEY
PostUp = iptables -A FORWARD -i $WIREGUARD_PUB_NIC -j ACCEPT; iptables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; ip6tables -A FORWARD -i $WIREGUARD_PUB_NIC -j ACCEPT; ip6tables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; iptables -A INPUT -s $PRIVATE_SUBNET_V4 -p udp -m udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
PostDown = iptables -D FORWARD -i $WIREGUARD_PUB_NIC -j ACCEPT; iptables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; ip6tables -D FORWARD -i $WIREGUARD_PUB_NIC -j ACCEPT; ip6tables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; iptables -D INPUT -s $PRIVATE_SUBNET_V4 -p udp -m udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
SaveConfig = false
# $CLIENT_NAME start
[Peer]
PublicKey = $CLIENT_PUBKEY
PresharedKey = $PRESHARED_KEY
AllowedIPs = $CLIENT_ADDRESS_V4/32,$CLIENT_ADDRESS_V6/128
# $CLIENT_NAME end" >$WG_CONFIG

    echo "# $CLIENT_NAME
[Interface]
Address = $CLIENT_ADDRESS_V4/$PRIVATE_SUBNET_MASK_V4,$CLIENT_ADDRESS_V6/$PRIVATE_SUBNET_MASK_V6
DNS = $CLIENT_DNS
MTU = $MTU_CHOICE
PrivateKey = $CLIENT_PRIVKEY
[Peer]
AllowedIPs = $CLIENT_ALLOWED_IP
Endpoint = $SERVER_HOST:$SERVER_PORT
PersistentKeepalive = $NAT_CHOICE
PresharedKey = $PRESHARED_KEY
PublicKey = $SERVER_PUBKEY" >"/etc/wireguard/clients"/"$CLIENT_NAME"-$WIREGUARD_PUB_NIC.conf
    # Generate QR Code
    qrencode -t ansiutf8 -l L <"/etc/wireguard/clients"/"$CLIENT_NAME"-$WIREGUARD_PUB_NIC.conf
    # Echo the file
    echo "Client Config --> "/etc/wireguard/clients"/"$CLIENT_NAME"-$WIREGUARD_PUB_NIC.conf"
    # Restart WireGuard
    if pgrep systemd-journal; then
      systemctl enable wg-quick@$WIREGUARD_PUB_NIC
      systemctl restart wg-quick@$WIREGUARD_PUB_NIC
    else
      service wg-quick@$WIREGUARD_PUB_NIC restart
    fi
  }

  # Setting Up Wireguard Config
  wireguard-setconf

# After WireGuard Install
else

  # Already installed what next?
  function wireguard-next-questions() {
    echo "Looks like Wireguard is already installed."
    echo "What do you want to do?"
    echo "   1) Show WireGuard Interface"
    echo "   2) Start WireGuard Interface"
    echo "   3) Stop WireGuard Interface"
    echo "   4) Add WireGuard Peer"
    echo "   5) Remove WireGuard Peer"
    echo "   6) Uninstall WireGuard Interface"
    echo "   7) Exit"
    until [[ "$WIREGUARD_OPTIONS" =~ ^[1-7]$ ]]; do
      read -rp "Select an Option [1-7]: " -e -i 1 WIREGUARD_OPTIONS
    done
    case $WIREGUARD_OPTIONS in
    1)
      if pgrep systemd-journal; then
        wg show
      else
        sudo wg show
      fi
      ;;
    2)
      if pgrep systemd-journal; then
        systemctl start wg-quick@$WIREGUARD_PUB_NIC
      else
        service wg-quick@$WIREGUARD_PUB_NIC start
      fi
      ;;
    3)
      if pgrep systemd-journal; then
        systemctl stop wg-quick@$WIREGUARD_PUB_NIC
      else
        service wg-quick@$WIREGUARD_PUB_NIC stop
      fi
      ;;
    4)
      echo "Tell me a new name for the client config file. Use one word only, no special characters. (No Spaces)"
      read -rp "New client name: " -e NEW_CLIENT_NAME
      CLIENT_PRIVKEY=$(wg genkey)
      CLIENT_PUBKEY=$(echo "$CLIENT_PRIVKEY" | wg pubkey)
      PRESHARED_KEY=$(wg genpsk)
      PRIVATE_SUBNET_V4=$(head -n1 $WG_CONFIG | awk '{print $2}')
      PRIVATE_SUBNET_MASK_V4=$(echo "$PRIVATE_SUBNET_V4" | cut -d "/" -f 2)
      PRIVATE_SUBNET_V6=$(head -n1 $WG_CONFIG | awk '{print $3}')
      PRIVATE_SUBNET_MASK_V6=$(echo "$PRIVATE_SUBNET_V6" | cut -d "/" -f 2)
      SERVER_HOST=$(head -n1 $WG_CONFIG | awk '{print $4}')
      SERVER_PUBKEY=$(head -n1 $WG_CONFIG | awk '{print $5}')
      CLIENT_DNS=$(head -n1 $WG_CONFIG | awk '{print $6}')
      MTU_CHOICE=$(head -n1 $WG_CONFIG | awk '{print $7}')
      NAT_CHOICE=$(head -n1 $WG_CONFIG | awk '{print $8}')
      CLIENT_ALLOWED_IP=$(head -n1 $WG_CONFIG | awk '{print $9}')
      LASTIP4=$(grep "/32" $WG_CONFIG | tail -n1 | awk '{print $3}' | cut -d "/" -f 1 | cut -d "." -f 4)
      LASTIP6=$(grep "/128" $WG_CONFIG | tail -n1 | awk '{print $3}' | cut -d "/" -f 1 | cut -d "." -f 4)
      CLIENT_ADDRESS_V4="${PRIVATE_SUBNET_V4::-4}$((LASTIP4 + 1))"
      CLIENT_ADDRESS_V6="${PRIVATE_SUBNET_V6::-4}$((LASTIP6 + 1))"
      echo "# $NEW_CLIENT_NAME start
[Peer]
PublicKey = $CLIENT_PUBKEY
PresharedKey = $PRESHARED_KEY
AllowedIPs = $CLIENT_ADDRESS_V4/32,$CLIENT_ADDRESS_V6/128
# $NEW_CLIENT_NAME end" >>$WG_CONFIG
      echo "# $NEW_CLIENT_NAME
[Interface]
Address = $CLIENT_ADDRESS_V4/$PRIVATE_SUBNET_MASK_V4,$CLIENT_ADDRESS_V6/$PRIVATE_SUBNET_MASK_V6
DNS = $CLIENT_DNS
MTU = $MTU_CHOICE
PrivateKey = $CLIENT_PRIVKEY
[Peer]
AllowedIPs = $CLIENT_ALLOWED_IP
Endpoint = $SERVER_HOST$SERVER_PORT
PersistentKeepalive = $NAT_CHOICE
PresharedKey = $PRESHARED_KEY
PublicKey = $SERVER_PUBKEY" >"/etc/wireguard/clients"/"$NEW_CLIENT_NAME"-$WIREGUARD_PUB_NIC.conf
      qrencode -t ansiutf8 -l L <"/etc/wireguard/clients"/"$NEW_CLIENT_NAME"-$WIREGUARD_PUB_NIC.conf
      echo "Client config --> "/etc/wireguard/clients"/"$NEW_CLIENT_NAME"-$WIREGUARD_PUB_NIC.conf"
      # Restart WireGuard
      if pgrep systemd-journal; then
        systemctl restart wg-quick@$WIREGUARD_PUB_NIC
      else
        service wg-quick@$WIREGUARD_PUB_NIC restart
      fi
      ;;
    5)
      # Remove User
      echo "Which WireGuard User Do You Want To Remove?"
      cat $WG_CONFIG | grep start | awk '{ print $2 }'
      read -rp "Type in Client Name : " -e REMOVECLIENT
      read -rp "Are you sure you want to remove $REMOVECLIENT ? (y/n): " -n 1 -r
      if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo
        sed -i "/\# $REMOVECLIENT start/,/\# $REMOVECLIENT end/d" $WG_CONFIG
      fi
      exit
      if pgrep systemd-journal; then
        systemctl restart wg-quick@$WIREGUARD_PUB_NIC
      else
        service wg-quick@$WIREGUARD_PUB_NIC restart
      fi
      echo "Client named $REMOVECLIENT has been removed."
      ;;
    6)
      # Uninstall Wireguard and purging files
      read -rp "Do you really want to remove Wireguard? [y/n]:" -e -i n REMOVE_WIREGUARD
    if [ "$REMOVE_WIREGUARD" = "y" ]; then
      # Stop WireGuard
      wg-quick down $WIREGUARD_PUB_NIC
      if [ "$DISTRO" == "CentOS" ]; then
        yum remove wireguard qrencode haveged unbound unbound-host -y
      elif [ "$DISTRO" == "Debian" ]; then
        apt-get remove --purge wireguard qrencode haveged unbound unbound-host -y
      elif [ "$DISTRO" == "Ubuntu" ]; then
        apt-get remove --purge wireguard qrencode haveged unbound unbound-host -y
      elif [ "$DISTRO" == "Raspbian" ]; then
        apt-get remove --purge wireguard qrencode haveged unbound unbound-host dirmngr -y
      elif [ "$DISTRO" == "Arch" ]; then
        pacman -Rs wireguard qrencode haveged unbound unbound-host -y
      elif [ "$DISTRO" == "Fedora" ]; then
        dnf remove wireguard qrencode haveged unbound unbound-host -y
      elif [ "$DISTRO" == "Redhat" ]; then
        yum remove wireguard qrencode haveged unbound unbound-host -y
      fi
      # Remove Pi-Hole
      pihole uninstall
      # Remove Pi-Hole Files
      rm -rf /etc/.pihole
      rm -rf /etc/pihole
      rm -rf /opt/pihole
      rm -rf /var/www/html/admin
      # Removing Wireguard Files
      rm -rf /etc/wireguard
      # Removing Wireguard User Config Files
      rm -rf /etc/wireguard/clients
      # Removing Unbound Files
      rm -rf /etc/unbound
      # Removing Qrencode
      rm -rf /etc/qrencode
      # Removing system wireguard config
      rm -f /etc/sysctl.d/wireguard.conf
      # Removing wireguard config
      rm -f /etc/wireguard/$WIREGUARD_PUB_NIC.conf
      # Removing Unbound Config
      rm -f /etc/unbound/unbound.conf
      # Removing Haveged Config
      rm -f /etc/default/haveged
      # Allow the modification of the resolv file
      chattr -i /etc/resolv.conf
      # Disable previous DNS servers
      sed -i "s|nameserver|#nameserver|" /etc/resolv.conf
      sed -i "s|search|#search|" /etc/resolv.conf
      # Set localhost as the DNS resolver
      echo "nameserver 8.8.8.8" >> /etc/resolv.conf
      # Use -i to enable modifications
      chattr +i /etc/resolv.conf
    fi
      ;;
    7)
      exit
      ;;
    esac
  }

  # Running Questions Command
  wireguard-next-questions
fi
