#!/bin/bash
set -e

echo "=== WireGuard Manager Setup ==="

# Install dependencies
if command -v apt &> /dev/null; then
    echo "Installing WireGuard tools..."
    sudo apt update
    sudo apt install -y wireguard wireguard-tools iptables
elif command -v yum &> /dev/null; then
    echo "Installing WireGuard tools (yum)..."
    sudo yum install -y wireguard-tools iptables
elif command -v dnf &> /dev/null; then
    echo "Installing WireGuard tools (dnf)..."
    sudo dnf install -y wireguard-tools iptables
else
    echo "Please install wireguard-tools manually for your distribution"
fi

# Enable IP forwarding
echo "Enabling IP forwarding..."
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.d/99-wireguard.conf
sudo sysctl -p /etc/sysctl.d/99-wireguard.conf

echo ""
echo "=== Setup Complete ==="
echo "Run 'make build' to compile the application"
echo "Run './wg-manager' to start the server"
echo "Default password: admin"
