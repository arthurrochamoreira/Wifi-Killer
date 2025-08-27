import math
import time
from dataclasses import field
from typing import TYPE_CHECKING, Iterator, Optional, TypeVar

from lox.ast import dataclass

if TYPE_CHECKING:
    from .ast import Value

T = TypeVar("T")
ScopeDict = dict[str, "Value"]


class _Builtins(dict):
    BUILTINS: dict[str, "Value"] = {
        "sqrt": math.sqrt,
        "clock": time.time,
        "max": max,
    }

    def __init__(self):
        super().__init__(self.BUILTINS)

    def __repr__(self) -> str:
        return "BUILTINS"

    def __str__(self) -> str:
        return self.__repr__()


BUILTINS = _Builtins()


@dataclass
class Ctx:
    """
    Contexto de execução. Por enquanto é só um dicionário que armazena nomes
    das variáveis e seus respectivos valores.
    """

    scope: ScopeDict = field(default_factory=dict)
    parent: Optional["Ctx"] = field(default_factory=lambda: Ctx(BUILTINS, None))

    @classmethod
    def from_dict(cls, env: ScopeDict) -> "Ctx":
        """
        Cria um novo contexto a partir de um dicionário.
        """
        return cls(env, Ctx(BUILTINS, None))

    def __getitem__(self, name: str) -> "Value":
        """
        Obtém o valor de uma variável pelo nome.
        """
        if name in self.scope:
            return self.scope[name]
        elif self.parent is not None:
            return self.parent[name]
        raise KeyError(f"Variable '{name}' not found in context.")

    def __setitem__(self, name: str, value: "Value") -> None:
        """
        Define o valor de uma variável pelo nome.
        """
        if name in self.scope:
            self.scope[name] = value
        elif self.parent is not None:
            self.parent[name] = value
        else:
            raise KeyError(f"Variable '{name}' not found in context.")

    def __contains__(self, name: str) -> bool:
        """
        Verifica se uma variável existe no contexto.
        """
        return name in self.scope or (self.parent is not None and name in self.parent)

    def var_def(self, name: str, value: "Value") -> None:
        """
        Define uma variável no contexto atual.
        """
        if name in self.scope and not self.is_global():
            raise KeyError(f"Variable '{name}' already defined in the current scope.")
        self.scope[name] = value

    def assign(self, key: str, value: "Value"):
        """Encontra a ocorrência mais próxima de ``key`` e atualiza seu valor."""
        ctx: Optional[Ctx] = self
        while ctx is not None:
            if key in ctx.scope:
                ctx.scope[key] = value
                return
            ctx = ctx.parent
        raise KeyError(f"Variable '{key}' not found in context.")

    def to_dict(self) -> ScopeDict:
        """
        Converte o contexto para um dicionário.
        """
        if self.parent is None:
            return self.scope.copy()
        return {**self.parent.to_dict(), **self.scope}

    def iter_scopes(self, reverse: bool = False) -> Iterator[ScopeDict]:
        """
        Itera sobre os ambientes do contexto, começando pelo mais interno.
        """
        if reverse:
            if self.parent is not None:
                yield from self.parent.iter_scopes(reverse=True)
            yield self.scope
        else:
            yield self.scope
            if self.parent is not None:
                yield from self.parent.iter_scopes()

    def pretty(self) -> str:
        """
        Representação do contexto como string.
        """

        lines: list[str] = []
        for i, scope in enumerate(self.iter_scopes(reverse=True)):
            lines.append(pretty_scope(scope, i))
        return "\n".join(reversed(lines))

    def pop(self) -> ScopeDict:
        """
        Remove o escopo mais interno e retorna o contexto atualizado.
        """
        if self.parent is None:
            raise RuntimeError("Cannot pop the global scope.")

        scope = self.scope
        self.scope = self.parent.scope
        self.parent = self.parent.parent
        return scope

    def push(self, tos: ScopeDict):
        """Adiciona um dicionário ao topo da pilha."""
        self.parent = Ctx(self.scope, self.parent)
        self.scope = tos

    def is_global(self) -> bool:
        """
        Verifica se o contexto atual é o escopo global.
        """
        if self.parent is None:
            return False
        return self.parent.parent is None


def pretty_scope(env: ScopeDict, index: int) -> str:
    """
    Representa um escopo como string.
    """
    if not env:
        return f"{index:>2}: <empty>"
    items = (f"{k} = {v}" for k, v in sorted(env.items()))
    data = "; ".join(items)
    return f"{index:>2}: {data}"
