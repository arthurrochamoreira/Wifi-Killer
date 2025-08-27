# Define o interpretador Python e o nome do ambiente virtual
PYTHON = python3
VENV_NAME = venv
VENV_PYTHON = $(VENV_NAME)/bin/python
VENV_PIP = $(VENV_NAME)/bin/pip
SRC = main.py

# O comando padrão, executado quando você digita apenas "make"
.DEFAULT_GOAL := help

# --- Comandos Principais ---

## install: Cria o ambiente virtual e instala as dependências
install: venv
	@echo "--> Instalando dependências..."
	$(VENV_PIP) install --upgrade pip
	$(VENV_PIP) install scapy
	@echo "✅ Dependências instaladas com sucesso em '$(VENV_NAME)'."

## run: Executa a aplicação com permissões de administrador
run:
	@echo "--> Executando a aplicação... (Requer permissões de administrador)"
	@echo "--> Por favor, digite sua senha se solicitado."
	sudo $(VENV_PYTHON) $(SRC)

## clean: Remove o ambiente virtual e arquivos de cache
clean:
	@echo "--> Limpando o projeto..."
	rm -rf $(VENV_NAME)
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -exec rm -rf {} +
	@echo "🧹 Limpeza concluída."

## help: Mostra esta mensagem de ajuda
help:
	@echo "Comandos disponíveis:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

# --- Tarefas Internas ---

# Cria o ambiente virtual se ele não existir
venv:
	@if [ ! -d "$(VENV_NAME)" ]; then \
		echo "--> Criando ambiente virtual..."; \
		$(PYTHON) -m venv $(VENV_NAME); \
	fi

# Define os alvos que não são arquivos
.PHONY: install run clean help venv