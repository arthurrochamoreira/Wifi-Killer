import builtins
from dataclasses import dataclass, field
from types import BuiltinFunctionType, FunctionType
from typing import TYPE_CHECKING, Optional

from .ctx import Ctx

if TYPE_CHECKING:
    from .ast import Stmt, Value

__all__ = [
    "print",
    "show",
    "truthy",
]

number = (float, int)


@dataclass(frozen=True)
class LoxClass:
    """
    Classe base para todos os tipos de classe Lox.
    """

    name: str
    methods: dict[str, "LoxFunction"]
    base: Optional["LoxClass"] = None

    def __repr__(self):
        return self.name

    def __str__(self):
        return self.name

    def __call__(self, *args):
        instance = LoxInstance(self)
        try:
            init = self.get_method("init")
        except LoxError:
            if args:
                raise TypeError(f"Class {self} não aceita argumentos no construtor")
        else:
            init = init.bind(instance)
            init(*args)
        return instance

    def get_method(self, name: str) -> "LoxFunction":
        """
        Retorna um método da classe ou superclasse.
        """
        try:
            return self.methods[name]
        except KeyError:
            if self.base is None:
                raise LoxError(f"Method '{name}' not found in class '{self.name}'")
            return self.base.get_method(name)


@dataclass
class LoxInstance:
    """
    Classe base para todos os objetos Lox.
    """

    __lox_class: LoxClass = field()

    def __getattr__(self, name: str) -> "Value":
        method = self.__lox_class.get_method(name)
        return method.bind(self)

    def __repr__(self):
        return f"{self.__lox_class.name} instance"

    def init(self, *args):
        """
        Inicializa a instância com os argumentos fornecidos.
        """
        init_method = self.__lox_class.get_method("init")
        init_method.bind(self)(*args)
        return self


@dataclass(frozen=True)
class LoxFunction:
    """
    Classe base para todas as funções Lox.
    """

    name: str
    args: list[str]
    body: list["Stmt"]
    ctx: Ctx

    def __call__(self, *args):
        env = dict(zip(self.args, args, strict=True))
        env = self.ctx.push(env)
        try:
            for stmt in self.body:
                stmt.eval(env)
        except LoxReturn as e:
            return e.value

    def __str__(self):
        return f"<fn {self.name}>"

    def __eq__(self, other):
        return self is other

    def bind(self, instance: LoxInstance):
        """
        Vincula a função a uma instância, permitindo acesso ao 'this'.
        """
        return LoxFunction(
            self.name,
            self.args,
            self.body,
            self.ctx.push({"this": instance}),
        )


@dataclass(frozen=True)
class LoxCommand:
    """
    Classe base para todas as funções Lox.
    """

    name: str
    args: list[str]
    body: list["Stmt"]
    ctx: Ctx

    def __call__(self, ctx, *args):
        env = dict(zip(self.args, args, strict=True))
        env["!"] = ctx
        env = self.ctx.push(env)

        try:
            for stmt in self.body:
                stmt.eval(env)
        except LoxReturn as e:
            return e.value

    def __str__(self):
        return f"<fn {self.name}>"

    def __eq__(self, other):
        return self is other

    def bind(self, instance: LoxInstance):
        """
        Vincula a função a uma instância, permitindo acesso ao 'this'.
        """
        return LoxFunction(
            self.name,
            self.args,
            self.body,
            self.ctx.push({"this": instance}),
        )


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


def print(value: "Value"):
    """
    Imprime um valor lox.
    """
    builtins.print(show(value))


def show(value: "Value") -> str:
    """
    Converte valor lox para string.
    """
    if isinstance(value, bool):
        return str(value).lower()
    if value is None:
        return "nil"
    if isinstance(value, float):
        return str(value).removesuffix(".0").lower()
    if isinstance(value, (FunctionType, BuiltinFunctionType)):
        return "<native fn>"
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


def eq(a, b):
    return type(a) is type(b) and a == b


def ne(a, b):
    return not eq(a, b)


def lt(a, b):
    if isinstance(a, float) and isinstance(b, float):
        return a < b
    raise LoxError(f"Comparação entre {type(a).__name__} e {type(b).__name__}")


def gt(a, b):
    return lt(b, a)


def le(a, b):
    return lt(a, b) or eq(a, b)


def ge(a, b):
    return le(b, a)


def add(a, b):
    if isinstance(a, number) and isinstance(b, number):
        return a + b
    if isinstance(a, str) and isinstance(b, str):
        return a + b
    raise LoxError(f"Soma entre {type(a).__name__} e {type(b).__name__}")


def sub(a, b):
    if isinstance(a, number) and isinstance(b, number):
        return a - b
    raise LoxError(f"Soma entre {type(a).__name__} e {type(b).__name__}")


def mul(a, b):
    if isinstance(a, number) and isinstance(b, number):
        return a * b
    raise LoxError(f"Multiplicação entre {type(a).__name__} e {type(b).__name__}")


def truediv(a, b):
    if isinstance(a, int) and isinstance(b, int):
        return a // b
    if isinstance(a, number) and isinstance(b, number):
        if b == 0:
            return float("nan")
        return a / b
    raise LoxError(f"Divisão entre {type(a).__name__} e {type(b).__name__}")


def neg(a):
    if isinstance(a, number):
        return -a
    raise LoxError(f"Negação de {type(a).__name__}")


def not_(a):
    return not truthy(a)
