"""
network_core.py
================
Lógica de rede desacoplada da UI (antes embutida no app Flet `main.py`).

Responsabilidades:
- Detecção de interface / sub-rede / gateway
- Cache de fabricantes (OUI -> vendor) e atualização via IEEE
- Descoberta de dispositivos (ARP sweep com Scapy + complemento Nmap)
- Resolução de MAC / hostname
- Ataque/Restauração ARP (block/unblock) por dispositivo

Este módulo NÃO importa Flet e pode ser consumido por qualquer frontend
(API FastAPI, CLI, etc.).
"""

import socket
import threading
import time
import subprocess
import json
import os
import ipaddress
import re

import ifaddr
from scapy.all import ARP, Ether, srp, send, conf

# ---------------------------------------------------------------------------
# Configuração global
# ---------------------------------------------------------------------------
conf.verb = 0  # silencia o Scapy

VENDOR_CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mac_vendor_cache.json")
IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"

CURRENT_IFACE = None
CURRENT_SUBNET = None  # ipaddress.IPv4Network
NMAP_BIN = None
VENDOR_CACHE = {}


# ---------------------------------------------------------------------------
# Detecção de ambiente de rede
# ---------------------------------------------------------------------------
def get_local_ip() -> str:
    """IP local preferindo a rota real (UDP para 8.8.8.8)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def detect_active_interface_and_subnet():
    """Descobre (interface, gateway, sub-rede) usando ifaddr."""
    try:
        local_ip = get_local_ip()
        chosen_adapter = None
        chosen_ip = None
        prefix = None

        for adapter in ifaddr.get_adapters():
            for ip in adapter.ips:
                if isinstance(ip.ip, tuple):  # ignora IPv6
                    continue
                if ip.ip == local_ip:
                    chosen_adapter = adapter
                    chosen_ip = ip.ip
                    prefix = ip.network_prefix
                    break
            if chosen_adapter:
                break

        if chosen_adapter and chosen_ip and prefix is not None:
            subnet = ipaddress.ip_network(f"{chosen_ip}/{prefix}", strict=False)
            gw_ip = ".".join(chosen_ip.split(".")[:-1]) + ".1"
            iface_name = getattr(chosen_adapter, "nice_name", getattr(chosen_adapter, "name", None))
            return iface_name, gw_ip, subnet

        # Fallback: assume /24
        gw_ip = ".".join(local_ip.split(".")[:-1]) + ".1"
        try:
            subnet = ipaddress.ip_network(".".join(local_ip.split(".")[:-1]) + ".0/24", strict=False)
        except Exception:
            subnet = None
        iface_name = None
        for adapter in ifaddr.get_adapters():
            for ip in adapter.ips:
                if not isinstance(ip.ip, tuple) and ip.ip == local_ip:
                    iface_name = getattr(adapter, "nice_name", getattr(adapter, "name", None))
                    break
            if iface_name:
                break
        return iface_name, gw_ip, subnet
    except Exception:
        return None, None, None


def get_gateway_ip() -> str:
    """Heurística .1 baseada no IP local."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return ".".join(local_ip.split(".")[:-1]) + ".1"
    except Exception:
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            return ".".join(local_ip.split(".")[:-1]) + ".1"
        except Exception:
            return "192.168.1.1"


def resolve_nmap_binary():
    """Resolve o binário do nmap no PATH (opcional)."""
    for c in ["nmap"]:
        try:
            r = subprocess.run([c, "-V"], capture_output=True, text=True, timeout=3)
            if r.returncode == 0 or r.stdout or r.stderr:
                return c
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# Vendor cache (OUI -> fabricante)
# ---------------------------------------------------------------------------
def load_vendor_cache():
    global VENDOR_CACHE
    if os.path.exists(VENDOR_CACHE_FILE):
        try:
            with open(VENDOR_CACHE_FILE, "r", encoding="utf-8") as f:
                VENDOR_CACHE = json.load(f)
        except Exception:
            VENDOR_CACHE = {}
    else:
        VENDOR_CACHE = {}


def save_vendor_cache():
    try:
        with open(VENDOR_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(VENDOR_CACHE, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def update_vendor_cache_from_ieee() -> int:
    """Baixa a base OUI da IEEE e atualiza o cache. Retorna nº de entradas novas/alteradas."""
    import requests
    try:
        resp = requests.get(IEEE_OUI_URL, timeout=30)
        resp.raise_for_status()
        added = 0
        for line in resp.text.splitlines():
            if "(hex)" in line:
                parts = line.split("(hex)")
                if len(parts) > 1:
                    oui_mac = parts[0].strip().replace("-", ":").upper()
                    company = parts[1].strip()
                    if oui_mac and company and VENDOR_CACHE.get(oui_mac) != company:
                        VENDOR_CACHE[oui_mac] = company
                        added += 1
        save_vendor_cache()
        return added
    except Exception:
        return 0


def vendor_from_cache_only(mac: str) -> str:
    if not mac or len(mac) < 8:
        return "Desconhecido"
    oui = ":".join(mac.replace("-", ":").upper().split(":")[:3])
    return VENDOR_CACHE.get(oui, "Desconhecido")


# ---------------------------------------------------------------------------
# Descoberta / resolução
# ---------------------------------------------------------------------------
def robust_get_mac(ip: str, iface: str, retries=5, initial_timeout=1.0):
    """Resolve MAC por ARP com múltiplas tentativas."""
    if not iface:
        return None
    for i in range(retries):
        try:
            answered, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                timeout=initial_timeout + i * 0.3,
                retry=1,
                verbose=0,
                iface=iface,
            )
            for _, r in answered:
                return r[Ether].src
        except Exception:
            pass
        time.sleep(0.05)
    return None


def get_mac(ip: str):
    return robust_get_mac(ip, CURRENT_IFACE, retries=5, initial_timeout=0.8)


def get_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Desconhecido"


def arp_chunk_scan(ips, iface=None):
    """ARP em um lote de IPs -> [(ip, mac)]."""
    iface = iface or CURRENT_IFACE
    try:
        packets = [Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip) for ip in ips]
        answered, _ = srp(packets, timeout=0.3, iface=iface, verbose=0)
        return [(r.psrc, r.hwsrc) for _, r in answered]
    except Exception:
        return []


def init_environment():
    """Inicializa estado global (interface, sub-rede, nmap, cache). Idempotente."""
    global CURRENT_IFACE, CURRENT_SUBNET, NMAP_BIN
    iface, gw_ip, subnet = detect_active_interface_and_subnet()
    CURRENT_IFACE = iface
    CURRENT_SUBNET = subnet
    NMAP_BIN = resolve_nmap_binary()
    load_vendor_cache()
    return {
        "iface": iface,
        "gateway_ip": gw_ip or get_gateway_ip(),
        "local_ip": get_local_ip(),
        "subnet": str(subnet) if subnet else None,
        "nmap": NMAP_BIN,
    }
