# Painel de Controle da Rede

Ferramenta para escanear a rede local, identificar dispositivos e bloquear/liberar
o acesso à internet de cada um via **ARP Spoofing**.

A interface foi refatorada de **Flet (Python desktop)** para **React + Tailwind (web)**,
com a lógica de rede exposta por um backend **FastAPI**.

---

## Arquitetura

```
network_core.py   Lógica de rede (scan ARP, Nmap, OUI, ataque/restauração) — sem UI
api.py            Backend FastAPI: REST + WebSocket que expõe o network_core
frontend/
  App.jsx         Interface React + Tailwind (arquivo único)
  index.html      Carrega o App.jsx (Tailwind + React via CDN, p/ rodar sem build)
main.py           Versão Flet original (mantida como referência)
```

O frontend conversa com o backend por:
- **REST** (`/api/...`) para ações pontuais (scan start/stop, block, unblock, add IP, OUI)
- **WebSocket** (`/ws`) para receber dispositivos e progresso do scan em tempo real

---

## Pré-requisitos

- Python 3.10+
- `make`
- Privilégios de administrador (o Scapy precisa para enviar pacotes ARP)
- *(Opcional)* `nmap` no PATH — enriquece a descoberta de dispositivos

---

## Instalação

Cria o ambiente virtual e instala tudo do `requirements.txt`:

```bash
make install
```

---

## Subir o ambiente

**Tudo de uma vez** (backend + frontend):

```bash
make up
```

Depois abra **http://localhost:5500** no navegador.

Ou rode separadamente em dois terminais:

```bash
make backend    # FastAPI em http://localhost:8000 (pede senha de admin)
make frontend   # Frontend em http://localhost:5500
```

---

## Comandos disponíveis

| Comando         | Descrição                                                        |
|-----------------|------------------------------------------------------------------|
| `make install`  | Cria o venv e instala as dependências do `requirements.txt`      |
| `make up`       | Sobe backend **e** frontend juntos                               |
| `make backend`  | Sobe só o backend FastAPI (admin)                                |
| `make frontend` | Serve só o frontend                                              |
| `make run`      | Executa a versão Flet original (`main.py`)                       |
| `make clean`    | Remove o venv e caches                                           |
| `make help`     | Lista os comandos                                                |

---

## Configuração

- A porta do backend é `8000` e a do frontend `5500` (ajustáveis no `Makefile`).
- Se o backend não estiver em `localhost:8000`, edite `window.__API_BASE__`
  em `frontend/index.html`.

## Endpoints da API

| Método | Rota                          | Ação                                  |
|--------|-------------------------------|---------------------------------------|
| GET    | `/api/info`                   | Interface, IP local, gateway, sub-rede|
| GET    | `/api/devices`                | Lista atual de dispositivos           |
| POST   | `/api/scan/start`             | Inicia o scan                         |
| POST   | `/api/scan/stop`              | Para o scan                           |
| POST   | `/api/devices/{ip}/block`     | Bloqueia um dispositivo               |
| POST   | `/api/devices/{ip}/unblock`   | Libera um dispositivo                 |
| POST   | `/api/block-all`              | Bloqueia todos os conectados          |
| POST   | `/api/unblock-all`            | Libera todos                          |
| POST   | `/api/devices`                | Adiciona IP manualmente (`{"ip": ...}`)|
| POST   | `/api/oui/update`             | Atualiza a base OUI da IEEE           |
| WS     | `/ws`                         | Eventos de scan/dispositivos em tempo real |
