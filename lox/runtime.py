import builtins
from dataclasses import dataclass
from operator import eq, ge, gt, le, lt, ne, neg, not_, add as _add, sub as _sub, mul as _mul, truediv as _truediv
from typing import TYPE_CHECKING

from .ctx import Ctx

if TYPE_CHECKING:
    from .ast import Stmt, Value

__all__ = [
    "add",
    "eq",
    "ge",
    "gt",
    "le",
    "lt",
    "mul",
    "ne",
    "neg",
    "not_",
    "print",
    "show",
    "sub",
    "truthy",
    "truediv",
]


class LoxInstance:
    """
    Classe base para todos os objetos Lox.
    """


@dataclass
class LoxFunction:
    """Representa uma função do Lox."""

    name: str
    params: list[str]
    body: list["Stmt"]
    ctx: Ctx

    def call(self, args: list["Value"]):
        env = dict(zip(self.params, args, strict=True))
        self.ctx.push(env)
        try:
            for stmt in self.body:
                stmt.eval(self.ctx)
        except LoxReturn as e:
            return e.value
        finally:
            self.ctx.pop()

    def __call__(self, *args):
        return self.call(list(args))
class LoxReturn(Exception):
    """
    Exceção para retornar de uma função Lox.
    """

    def __init__(self, value):
        self.value = value
        super().__init__()


class LoxError(Exception):
    """
    Exceção para erros de execução Lox.
    """


nan = float("nan")
inf = float("inf")

def _op_result(x, y, result):
    """Converte o resultado para int se ambos os operandos forem inteiros."""
    if isinstance(x, int) and isinstance(y, int):
        return int(result)
    return result


def add(x: "Value", y: "Value") -> "Value":
    return _op_result(x, y, _add(x, y))


def sub(x: "Value", y: "Value") -> "Value":
    return _op_result(x, y, _sub(x, y))


def mul(x: "Value", y: "Value") -> "Value":
    return _op_result(x, y, _mul(x, y))


def truediv(x: "Value", y: "Value") -> "Value":
    return _op_result(x, y, _truediv(x, y))



def print(value: "Value"):
    """
    Imprime um valor lox.
    """
    builtins.print(show(value))


def show(value: "Value") -> str:
    """
    Converte valor lox para string.
    """
    return str(value)


def show_repr(value: "Value") -> str:
    """
    Mostra um valor lox, mas coloca aspas em strings.
    """
    if isinstance(value, str):
        return f'"{value}"'
    return show(value)


def truthy(value: "Value") -> bool:
    """
    Converte valor lox para booleano segundo a semântica do lox.
    """
    if value is None or value is False:
        return False
    return True
