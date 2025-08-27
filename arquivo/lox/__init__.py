"""
ATENÇÃO: EVITE MODIFICAR ESTE ARQUIVO!

Carrega os nomes principais do módulo lox.
"""

from .ast import Expr, Stmt, Value
from .ctx import Ctx
from .errors import SemanticError
from .node import Node
from .parser import lex, parse, parse_cst, parse_expr

__all__ = [
    "Ctx",
    "eval",
    "Expr",
    "lex",
    "Node",
    "parse_cst",
    "parse",
    "parse_expr",
    "Stmt",
    "SemanticError",
]


def eval(
    src: str | Node,
    env: Ctx | dict[str, Value] | None = None,
    skip_validation: bool = False,
) -> Value:
    """
    Avalia o código fonte e retorna o valur resultante.

    Args:
        src:
            Código fonte em formato de string ou um nó AST.
        env:
            Ambiente onde as variáveis serão avaliadas. Se omitido, um novo
            ambiente vazio será criado. Aceita um dicionário mapeando nomes de
            variáveis para seus valores ou uma instância de `Ctx`.
        skip_validation:
            Se `True`, ignora a validação do código fonte antes da avaliação.
    """
    if env is None:
        env = Ctx.from_dict({})
    elif not isinstance(env, Ctx):
        env = Ctx.from_dict(env)

    if isinstance(src, Node):
        ast = src
    else:
        ast = parse(src)

    if not skip_validation:
        ast.validate_tree()

    try:
        return ast.eval(env)
    except Exception as e:
        print(f"Programa terminou com um erro: {e}")
        print("Variáveis:", env)
        raise
