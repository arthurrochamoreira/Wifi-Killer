[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/PBVutFEA)
# Prova II

A prova usa a mesma base de repositório que a lista de exercícios. Você
**pode e deve** usar os arquivos do repositório pessoal como base para começar a
resolução da prova. O modo mais prático de começar é clonar este repositório e
copiar os arquivos importantes na pasta lox ("ast.py", "transformer.py",
"grammar.lark" e "runtime.py").

Os exercícios ficam em uma pasta separada chamada `/prova/`. A prova consiste em
4 questões e uma questão de desafio.

Algumas questões possuem duas ou mais versões. Você pode escolher qualquer uma
das alternativas para implementar, mas somente a maior nota de cada questão será
considerada.

A tabela abaixo mostra o valor de cada uma das quesões em suas diferentes 
variantes:

    +---------+-------+-------+-------+
    | Questão |   A   |   B   |   C   |
    +---------+-------+-------+-------+
    |   Q1    |  6pt  |   -   |   -   |
    +---------+-------+-------+-------+
    |   Q2    |  5pt  |  6pt  |   -   |
    +---------+-------+-------+-------+
    |   Q3    |  6pt  |   -   |   -   |
    +---------+-------+-------+-------+
    |   Q4    |  7pt  |  7pt  |  7pt  |
    +---------+-------+-------+-------+

A questão desafio vale 10pts e pode substituir qualquer uma das outras questões
da prova.


## Regras

Você pode fazer a prova no computador do laboratório ou no computador pessoal e
durante a prova pode acessar alguns sites:

* O livro https://craftinginterpreters.com/contents.html
* O seu repositório do trabalho no Github classroom.
* O seu repositório da prova no Github classroom.
* O repositório do Github da turma.
* https://docs.astral.sh/uv/ para baixar o UV, se necessário

A utilização de qualquer outro site é proibida. Em particular a utilização de
modelos de linguagem como ChatGPT, DeepSeek, Gemini, Grok, etc está
EXPRESSAMENTE PROIBIDA! A utilização de qualquer um desses modelos durante a
prova implica na anulação da mesma.

Além disso, a utilização de qualquer sistema de mensageria (WhatsApp, Telegram,
Gmail, Instagram, TikTok etc) tanto no celular quanto no computador também
implica na anulação da prova. Desligue as notificações do celular durante a
prova e se precisar atender o celular em alguma emergência, fale antes com o
professor.


## Rodando testes

A prova usa o `uv` para gerenciar a versão do Python e executar os comandos. 
Assim como na lista, os testes automatizados são executados pelo pyteset. 
Os comandos abaixo podem ser úteis:

    # Roda os testes
    uv run pytest 
    uv run pytest --maxfail=1       # para no 1o erro
    uv run pytest tests/test_q1.py  # seleciona uma questão
    uv run pytest -l                # mostra variáveis locais no traceback
    uv run pytest --tb=no           # relatório curto, também aceita short, line

    # Executa o lox
    uv run lox --help
    uv run lox some_file.lox

Importante! A questão 1 possui um teste separado. Execute o teste com o comando

    # Executa a questão 1
    uv run prova/q1_regex.py


## Entrega

A prova será entregue subindo um commit para a branch master. Você pode usar
comandos do git, mas conhecendo a rede da UnB, é melhor se planejar para subir 
os arquivos manualmente pela interface do Github.

Você não precisa subir todos os arquivos, mas somente aqueles que foram
modificados na prova. A lista provavelmente será essa:

* lox/ast.py
* lox/grammar.lark
* lox/transformer.py
* lox/runtime.py
* prova/q1_regex.py
* prova/q2b_strings.py

