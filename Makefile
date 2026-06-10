# Define o interpretador Python e o nome do ambiente virtual
PYTHON = python3
VENV_NAME = venv
VENV_PYTHON = $(VENV_NAME)/bin/python
VENV_PIP = $(VENV_NAME)/bin/pip
SRC = main.py
HOST = 0.0.0.0
PORT = 8000
FRONT_PORT = 5500

.DEFAULT_GOAL := help

# --- Comandos Principais ---

## install: Cria o ambiente virtual e instala as dependencias (requirements.txt)
install: venv
	@echo "--> Instalando dependencias do requirements.txt..."
	$(VENV_PIP) install --upgrade pip
	$(VENV_PIP) install -r requirements.txt
	@echo "Dependencias instaladas com sucesso em '$(VENV_NAME)'."

## backend: Sobe o backend FastAPI (api.py) - requer permissoes de administrador
backend:
	@echo "--> Subindo backend FastAPI em http://$(HOST):$(PORT) (Scapy requer admin)..."
	@echo "--> Digite sua senha se solicitado."
	sudo $(VENV_PYTHON) -m uvicorn api:app --host $(HOST) --port $(PORT) --reload

## frontend: Serve o frontend React (frontend/) em http://localhost:$(FRONT_PORT)
frontend:
	@echo "--> Servindo frontend em http://localhost:$(FRONT_PORT) ..."
	cd frontend && $(VENV_PYTHON) -m http.server $(FRONT_PORT)

## up: Sobe backend e frontend juntos (Ctrl+C encerra ambos)
up:
	@echo "--> Subindo ambiente completo (backend + frontend)..."
	@trap 'kill 0' INT TERM EXIT; \
	sudo $(VENV_PYTHON) -m uvicorn api:app --host $(HOST) --port $(PORT) & \
	(cd frontend && $(VENV_PYTHON) -m http.server $(FRONT_PORT)) & \
	wait

## run: Executa a versao Flet original (main.py) com permissoes de administrador
run:
	@echo "--> Executando a aplicacao Flet... (Requer permissoes de administrador)"
	@echo "--> Por favor, digite sua senha se solicitado."
	sudo $(VENV_PYTHON) $(SRC)

## clean: Remove o ambiente virtual e arquivos de cache
clean:
	@echo "--> Limpando o projeto..."
	rm -rf $(VENV_NAME)
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -exec rm -rf {} +
	@echo "Limpeza concluida."

## help: Mostra esta mensagem de ajuda
help:
	@echo "Comandos disponiveis:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //' | awk 'BEGIN {FS = ": "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

# --- Tarefas Internas ---

venv:
	@if [ ! -d "$(VENV_NAME)" ]; then \
		echo "--> Criando ambiente virtual..."; \
		$(PYTHON) -m venv $(VENV_NAME); \
	fi

.PHONY: install backend frontend up run clean help venv
