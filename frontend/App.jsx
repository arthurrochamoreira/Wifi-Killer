import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import {
  Wifi,
  StopCircle,
  Download,
  PlusCircle,
  Search,
  Shield,
  ShieldOff,
  Router,
  Laptop,
  Ban,
  CheckCircle2,
  HelpCircle,
  X,
} from "lucide-react";

/**
 * Painel de Controle da Rede — frontend React + Tailwind.
 *
 * Refatoração da UI Flet (main.py) para web. Consome o backend FastAPI
 * (api.py) via REST + WebSocket. Arquivo único e autossuficiente.
 *
 * Defina a base da API (em dev, aponte para o backend uvicorn):
 *   const API = "http://localhost:8000";
 */
const API = (typeof window !== "undefined" && window.__API_BASE__) || "http://localhost:8000";
const WS_URL = API.replace(/^http/, "ws") + "/ws";

// ---------------------------------------------------------------------------
// Helpers de chamada à API
// ---------------------------------------------------------------------------
const api = {
  info: () => fetch(`${API}/api/info`).then((r) => r.json()),
  devices: () => fetch(`${API}/api/devices`).then((r) => r.json()),
  scanStart: () => fetch(`${API}/api/scan/start`, { method: "POST" }),
  scanStop: () => fetch(`${API}/api/scan/stop`, { method: "POST" }),
  block: (ip) => fetch(`${API}/api/devices/${ip}/block`, { method: "POST" }),
  unblock: (ip) => fetch(`${API}/api/devices/${ip}/unblock`, { method: "POST" }),
  blockAll: () => fetch(`${API}/api/block-all`, { method: "POST" }),
  unblockAll: () => fetch(`${API}/api/unblock-all`, { method: "POST" }),
  addIp: (ip) =>
    fetch(`${API}/api/devices`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip }),
    }).then((r) => r.json()),
  ouiUpdate: () => fetch(`${API}/api/oui/update`, { method: "POST" }).then((r) => r.json()),
};

// ---------------------------------------------------------------------------
// Estilo por status do dispositivo
// ---------------------------------------------------------------------------
const STATUS_STYLES = {
  "Gateway Padrão": { Icon: Router, color: "text-blue-400", bg: "bg-blue-800/60" },
  "Este Dispositivo": { Icon: Laptop, color: "text-violet-400", bg: "bg-indigo-700/60" },
  Bloqueado: { Icon: Ban, color: "text-red-400", bg: "bg-red-900/60" },
  Conectado: { Icon: HelpCircle, color: "text-green-400", bg: "bg-green-900/60" },
};

function StatusBadge({ status }) {
  if (status === "Conectado")
    return (
      <span className="flex items-center gap-1.5 text-xs text-green-400">
        <span className="h-2 w-2 rounded-full bg-green-400" /> Conectado
      </span>
    );
  if (status === "Bloqueado")
    return (
      <span className="flex items-center gap-1.5 text-xs text-red-400">
        <span className="h-2 w-2 rounded-full bg-red-400" /> Bloqueado
      </span>
    );
  return <span className="text-xs font-semibold text-violet-400">{status}</span>;
}

// ---------------------------------------------------------------------------
// Card de dispositivo
// ---------------------------------------------------------------------------
function DeviceCard({ device, onToggle, busy }) {
  const { ip, mac, hostname, vendor, status } = device;
  const style = STATUS_STYLES[status] || STATUS_STYLES.Conectado;
  const { Icon } = style;
  const isSpecial = status === "Gateway Padrão" || status === "Este Dispositivo";
  const isBlocked = status === "Bloqueado";

  return (
    <div
      className={`flex flex-col gap-3 rounded-xl p-3 sm:flex-row sm:items-center sm:justify-between ${
        status === "Este Dispositivo" ? "bg-violet-500/10" : "bg-white/[0.02] hover:bg-white/[0.05]"
      } transition-colors`}
    >
      <div className="flex items-center gap-3">
        <div className={`flex h-12 w-12 items-center justify-center rounded-full ${style.bg}`}>
          <Icon className={`h-6 w-6 ${style.color}`} />
        </div>
        <div className="leading-tight">
          <p className="text-[15px] font-bold text-gray-100">{ip}</p>
          <p className="text-xs text-gray-400">{hostname}</p>
          <p className="font-mono text-xs text-gray-500">{mac}</p>
          <p className="text-xs text-gray-500">{vendor}</p>
        </div>
      </div>

      <div className="flex items-center justify-end gap-3">
        <StatusBadge status={status} />
        {!isSpecial && (
          <button
            onClick={() => onToggle(device)}
            disabled={busy}
            className={`flex w-[120px] items-center justify-center gap-1.5 rounded-full px-3 py-2 text-sm font-medium text-white transition-colors disabled:opacity-50 ${
              isBlocked ? "bg-green-600 hover:bg-green-500" : "bg-gray-600 hover:bg-gray-500"
            }`}
          >
            {isBlocked ? <CheckCircle2 className="h-4 w-4" /> : <Ban className="h-4 w-4" />}
            {isBlocked ? "Liberar" : "Bloquear"}
          </button>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Modal "Adicionar IP"
// ---------------------------------------------------------------------------
function AddIpModal({ open, onClose, onConfirm }) {
  const [ip, setIp] = useState("");
  const [error, setError] = useState("");
  if (!open) return null;

  const confirm = async () => {
    const res = await onConfirm(ip.trim());
    if (res === true) {
      setIp("");
      setError("");
      onClose();
    } else {
      setError(res || "IP inválido");
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="w-full max-w-sm rounded-xl border border-gray-700 bg-gray-800 p-5 shadow-2xl">
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-gray-100">Adicionar dispositivo por IP</h3>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-200">
            <X className="h-5 w-5" />
          </button>
        </div>
        <input
          autoFocus
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && confirm()}
          placeholder="Ex.: 192.168.1.42"
          className="w-full rounded-lg border border-gray-600 bg-gray-900 px-3 py-2 text-gray-100 outline-none focus:border-blue-500"
        />
        <p className="mt-2 text-xs text-gray-400">
          Vamos tentar resolver MAC e hostname automaticamente.
        </p>
        {error && <p className="mt-2 text-xs text-red-400">{error}</p>}
        <div className="mt-4 flex justify-end gap-2">
          <button onClick={onClose} className="rounded-lg px-4 py-2 text-sm text-gray-300 hover:bg-white/5">
            Cancelar
          </button>
          <button onClick={confirm} className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500">
            Adicionar
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// App principal
// ---------------------------------------------------------------------------
export default function App() {
  const [devices, setDevices] = useState({}); // ip -> device
  const [info, setInfo] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState({ processed: 0, total: 0 });
  const [statusText, setStatusText] = useState("Pronto");
  const [search, setSearch] = useState("");
  const [modalOpen, setModalOpen] = useState(false);
  const [busy, setBusy] = useState({}); // ip -> bool
  const wsRef = useRef(null);

  const sortDevices = useCallback(
    (list) => {
      const gw = info?.gateway_ip;
      const local = info?.local_ip;
      return [...list].sort((a, b) => {
        const rank = (d) => (d.ip === gw ? 0 : d.ip === local ? 1 : 2);
        if (rank(a) !== rank(b)) return rank(a) - rank(b);
        const na = a.ip.split(".").map(Number);
        const nb = b.ip.split(".").map(Number);
        for (let i = 0; i < 4; i++) if (na[i] !== nb[i]) return na[i] - nb[i];
        return 0;
      });
    },
    [info]
  );

  // WebSocket para atualizações em tempo real
  useEffect(() => {
    api.info().then(setInfo);
    let ws;
    try {
      ws = new WebSocket(WS_URL);
      wsRef.current = ws;
      ws.onmessage = (ev) => {
        const msg = JSON.parse(ev.data);
        switch (msg.type) {
          case "snapshot":
          case "scan_end":
            setDevices(Object.fromEntries(msg.devices.map((d) => [d.ip, d])));
            if (msg.type === "scan_end") {
              setScanning(false);
              setStatusText("Pronto");
              setProgress({ processed: 0, total: 0 });
            }
            break;
          case "scan_start":
            setDevices({});
            setScanning(true);
            setStatusText("Escaneando...");
            break;
          case "device":
            setDevices((prev) => ({ ...prev, [msg.device.ip]: msg.device }));
            break;
          case "progress":
            setProgress({ processed: msg.processed, total: msg.total });
            setStatusText(`Escaneando… ${msg.found} dispositivos • ${msg.processed}/${msg.total} IPs`);
            break;
          default:
            break;
        }
      };
    } catch (e) {
      console.error("WS error", e);
    }
    return () => ws && ws.close();
  }, []);

  const filtered = useMemo(() => {
    const list = sortDevices(Object.values(devices));
    const term = search.toLowerCase();
    if (!term) return list;
    return list.filter(
      (d) =>
        d.ip.toLowerCase().includes(term) ||
        (d.mac || "").toLowerCase().includes(term) ||
        (d.hostname || "").toLowerCase().includes(term) ||
        (d.vendor || "").toLowerCase().includes(term)
    );
  }, [devices, search, sortDevices]);

  const toggleScan = async () => {
    if (scanning) {
      await api.scanStop();
      setScanning(false);
      setStatusText("Pronto");
    } else {
      setScanning(true);
      await api.scanStart();
    }
  };

  const toggleDevice = async (device) => {
    const ip = device.ip;
    setBusy((b) => ({ ...b, [ip]: true }));
    try {
      if (device.status === "Bloqueado") await api.unblock(ip);
      else await api.block(ip);
    } finally {
      setBusy((b) => ({ ...b, [ip]: false }));
    }
  };

  const addIp = async (ip) => {
    const res = await api.addIp(ip);
    return res.ok ? true : res.error || "IP inválido";
  };

  const updateOui = async () => {
    setStatusText("Baixando base OUI da IEEE...");
    const res = await api.ouiUpdate();
    setStatusText(`Base OUI atualizada (+${res.added} entradas).`);
  };

  const pct = progress.total ? Math.round((progress.processed / progress.total) * 100) : 0;

  return (
    <div className="min-h-screen bg-gray-900 font-sans text-gray-100">
      <div className="mx-auto max-w-3xl px-5 py-6">
        {/* Header */}
        <header className="mb-4">
          <h1 className="text-3xl font-bold">Painel de Controle da Rede</h1>
          <p className="text-gray-400">Gerencie dispositivos e proteja sua rede contra ARP Spoofing.</p>
          {info && (
            <p className="mt-1 text-xs text-gray-500">
              {info.iface || "interface ?"} • local {info.local_ip} • gateway {info.gateway_ip}
              {info.subnet ? ` • ${info.subnet}` : ""}
            </p>
          )}
        </header>

        {/* Busca + ações */}
        <div className="mb-4 space-y-3">
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Buscar por IP, MAC, nome, ou fabricante..."
              className="w-full rounded-full border border-gray-700 bg-gray-800 py-2.5 pl-9 pr-4 text-sm outline-none focus:border-blue-500"
            />
          </div>

          <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
            <button
              onClick={toggleScan}
              className={`flex items-center justify-center gap-2 rounded-full px-4 py-2.5 text-sm font-semibold text-white transition-colors ${
                scanning ? "bg-red-600 hover:bg-red-500" : "bg-blue-600 hover:bg-blue-500"
              }`}
            >
              {scanning ? <StopCircle className="h-5 w-5" /> : <Wifi className="h-5 w-5" />}
              {scanning ? "Parar Scan" : "Escanear Rede"}
            </button>
            <button
              onClick={updateOui}
              className="flex items-center justify-center gap-2 rounded-full bg-gray-700 px-4 py-2.5 text-sm font-semibold text-blue-400 transition-colors hover:bg-gray-600"
            >
              <Download className="h-5 w-5" /> Atualizar base OUI
            </button>
            <button
              onClick={() => setModalOpen(true)}
              className="flex items-center justify-center gap-2 rounded-full bg-gray-700 px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-gray-600"
            >
              <PlusCircle className="h-5 w-5" /> Adicionar IP
            </button>
          </div>
        </div>

        {/* Card de dispositivos */}
        <div className="rounded-xl border border-gray-700 bg-gray-800 shadow-lg shadow-black/20">
          <div className="flex items-center justify-between border-b border-gray-700 px-4 py-3">
            <h2 className="text-base font-semibold">Dispositivos Conectados</h2>
            <div className="flex gap-2">
              <button
                onClick={() => api.blockAll()}
                className="flex items-center gap-1.5 rounded-lg px-2 py-1 text-xs text-red-400 hover:bg-red-400/10"
              >
                <ShieldOff className="h-4 w-4" /> Bloquear Todos
              </button>
              <button
                onClick={() => api.unblockAll()}
                className="flex items-center gap-1.5 rounded-lg px-2 py-1 text-xs text-green-400 hover:bg-green-400/10"
              >
                <Shield className="h-4 w-4" /> Liberar Todos
              </button>
            </div>
          </div>

          {/* Barra de progresso */}
          <div className="px-4 pt-3">
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-gray-700">
              <div
                className={`h-full bg-blue-500 transition-all ${scanning && !progress.total ? "animate-pulse w-1/3" : ""}`}
                style={progress.total ? { width: `${pct}%` } : undefined}
              />
            </div>
            <p className="py-2 text-xs text-gray-400">{statusText}</p>
          </div>

          {/* Lista */}
          <div className="max-h-[60vh] space-y-1 overflow-y-auto px-2 pb-3">
            {filtered.length === 0 ? (
              <p className="py-10 text-center text-sm text-gray-500">
                Nenhum dispositivo. Clique em “Escanear Rede”.
              </p>
            ) : (
              filtered.map((d) => (
                <DeviceCard key={d.ip} device={d} onToggle={toggleDevice} busy={busy[d.ip]} />
              ))
            )}
          </div>
        </div>
      </div>

      <AddIpModal open={modalOpen} onClose={() => setModalOpen(false)} onConfirm={addIp} />
    </div>
  );
}
