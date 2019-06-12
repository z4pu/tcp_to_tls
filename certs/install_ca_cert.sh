#!/usr/bin/env bash
# Installs certauth.crt to the trusted certs folder for the distribution
# (CentOS or Debian/Ubuntu)
#
#
# Usage:
#     ./install_ca_cert.sh [options]
# Options:
#     -o <operating system>    # Operating system "debian" or "centos"
# certauth.crt  must be in the same directory as this script

if [ $# -eq 0 ]; then
    echo "No command specified" >&2
    exit 1
fi

while getopts ":o:" opt; do
  case $opt in
    o)
      OS=$OPTARG
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

if [ "$OS" != "debian" ] && [ "$OS" != "centos" ]; then
    echo "Invalid OS: $OS" >&2
    exit 1
fi

# Install the CA cert in the appropriate directory
if [ $OS = "debian" ]
  then
    if [ $EUID -ne 0 ]
      then
        sudo cp certauth.crt /usr/local/share/ca-certificates/$RANDOM.crt
        # update ca certificates
        # This adds appends the cert to /etc/ssl/certs/ca-certificates.crt
        sudo update-ca-certificates --fresh
      else
        cp certauth.crt /usr/local/share/ca-certificates/$RANDOM.crt
        update-ca-certificates --fresh
    fi
fi

if [ $OS = "centos" ]; then
  if [ $EUID -ne 0 ]; then
    sudo update-ca-trust force-enable
    # update ca certificates
    sudo cp certauth.crt /etc/pki/ca-trust/source/anchors/$RANDOM.crt
    sudo update-ca-trust extract
  else
    update-ca-trust force-enable
    cp certauth.crt /etc/pki/ca-trust/source/anchors/$RANDOM.crt
    update-ca-trust extract
  fi
fi
