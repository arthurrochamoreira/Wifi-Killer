from abc import ABC
from dataclasses import dataclass
from typing import Callable
from .ctx import Ctx
from .runtime import LoxFunction, LoxReturn, truthy
from .runtime import LoxFunction, LoxCommand, LoxReturn, truthy

# Declaramos nossa classe base num módulo separado para esconder um pouco de
# Python relativamente avançado de quem não se interessar pelo assunto.
#
# A classe Node implementa um método `pretty` que imprime as árvores de forma
# legível. Também possui funcionalidades para navegar na árvore usando cursores
# e métodos de visitação.
from .node import Node


#
# TIPOS BÁSICOS
#

# Tipos de valores que podem aparecer durante a execução do programa
Value = bool | str | float | None


class Expr(Node, ABC):
    """
    Classe base para expressões.

    Expressões são nós que podem ser avaliados para produzir um valor.
    Também podem ser atribuídos a variáveis, passados como argumentos para
    funções, etc.
    """


class Stmt(Node, ABC):
    """
    Classe base para comandos.

    Comandos são associdos a construtos sintáticos que alteram o fluxo de
    execução do código ou declaram elementos como classes, funções, etc.
    """


@dataclass
class Program(Node):
    """
    Representa um programa.

    Um programa é uma lista de comandos.
    """

    stmts: list[Stmt]

    def eval(self, ctx: Ctx):
        for stmt in self.stmts:
            stmt.eval(ctx)


#
# EXPRESSÕES
#
@dataclass
class BinOp(Expr):
    """
    Uma operação infixa com dois operandos.

    Ex.: x + y, 2 * x, 3.14 > 3 and 3.14 < 4
    """

    left: Expr
    right: Expr
    op: Callable[[Value, Value], Value]

    def eval(self, ctx: Ctx):
        left_value = self.left.eval(ctx)
        right_value = self.right.eval(ctx)
        return self.op(left_value, right_value)


@dataclass
class Var(Expr):
    """
    Uma variável no código

    Ex.: x, y, z
    """

    name: str

    def eval(self, ctx: Ctx):
        try:
            return ctx[self.name]
        except KeyError:
            raise NameError(f"variável {self.name} não existe!")
        
@dataclass
class VarBang(Expr):
    """Variável acessada em contexto dinâmico"""

    name: str

    def eval(self, ctx: Ctx):
        key = self.name
        if "!" in ctx and key in ctx["!"]:
            return ctx["!"][key]
        try:
            return ctx[key]
        except KeyError:
            raise NameError(f"variável {self.name} não existe!")


@dataclass
class Literal(Expr):
    """
    Representa valores literais no código, ex.: strings, booleanos,
    números, etc.

    Ex.: "Hello, world!", 42, 3.14, true, nil
    """

    value: Value

    def eval(self, ctx: Ctx):
        return self.value


@dataclass
class And(Expr):
    """Operador lógico 'and' com curto-circuito."""

    left: Expr
    right: Expr

    def eval(self, ctx: Ctx):
        left_value = self.left.eval(ctx)
        if not truthy(left_value):
            return left_value
        return self.right.eval(ctx)

@dataclass
class Or(Expr):
    """Operador lógico 'or' com curto-circuito."""

    left: Expr
    right: Expr

    def eval(self, ctx: Ctx):
        left_value = self.left.eval(ctx)
        if truthy(left_value):
            return left_value
        return self.right.eval(ctx)


@dataclass
class Call(Expr):
    """
    Uma chamada de função.

    Ex.: fat(42)
    """

    callee: Expr
    params: list[Expr]

    def eval(self, ctx: Ctx):
        func = self.callee.eval(ctx)
        args = [p.eval(ctx) for p in self.params]
        if callable(func):
            if isinstance(func, LoxCommand):
                return func(ctx, *args)
            return func(*args)
        raise TypeError(f"{func!r} não é chamável")

@dataclass
class This(Expr):
    """
    Acesso ao `this`.

    Ex.: this
    """

@dataclass
class Super(Expr):
    """
    Acesso a method ou atributo da superclasse.

    Ex.: super.x
    """


@dataclass
class Assign(Expr):
    """
    Atribuição de variável.

    Ex.: x = 42
    """
    name: str
    value: Expr

    def eval(self, ctx: Ctx):
        result = self.value.eval(ctx)
        if self.name[:1] in "ijklmn":
            result = int(result)
        ctx.assign(self.name, result)
        return result


@dataclass
class Getattr(Expr):
    """
    Acesso a atributo de um objeto.

    Ex.: x.y
    """

    obj: Expr
    attr: str

    def eval(self, ctx: Ctx):
        value = self.obj.eval(ctx)
        return getattr(value, self.attr)

@dataclass
class Setattr(Expr):
    obj: Expr
    attr: str
    value: Expr

    def eval(self, ctx: Ctx):
        obj_value = self.obj.eval(ctx)
        result = self.value.eval(ctx)
        if self.attr[:1] in "ijklmn":
            result = int(result)
        setattr(obj_value, self.attr, result)
        return result


#
# COMANDOS
#
@dataclass
class Print(Stmt):
    """
    Representa uma instrução de impressão.

    Ex.: print "Hello, world!";
    """
    expr: Expr
    
    def eval(self, ctx: Ctx):
        value = self.expr.eval(ctx)
        print(value)


@dataclass
class Return(Stmt):
    value: Expr | None = None

    def eval(self, ctx: Ctx):
        result = None if self.value is None else self.value.eval(ctx)
        raise LoxReturn(result)

@dataclass
class VarDef(Stmt):
    name: str
    value: Expr

    def eval(self, ctx: Ctx):
        result = self.value.eval(ctx)
        if self.name[:1] in "ijklmn":
            result = int(result)
        ctx.var_def(self.name, result)

@dataclass
class If(Stmt):
    cond: Expr
    then_branch: Stmt
    else_branch: Stmt | None = None

    def eval(self, ctx: Ctx):
        if truthy(self.cond.eval(ctx)):
            self.then_branch.eval(ctx)
        elif self.else_branch is not None:
            self.else_branch.eval(ctx)
@dataclass
class While(Stmt):
    cond: Expr
    body: Stmt

    def eval(self, ctx: Ctx):
        while truthy(self.cond.eval(ctx)):
            self.body.eval(ctx)


@dataclass
class Block(Node):
    stmts: list[Stmt]

    def eval(self, ctx: Ctx):
        ctx.push({})
        try:
            for stmt in self.stmts:
                stmt.eval(ctx)
        finally:
            ctx.pop()

@dataclass
class BlockExpr(Expr):
    decls: list[Stmt]
    value: Expr

    def eval(self, ctx: Ctx):
        ctx.push({})
        try:
            for decl in self.decls:
                decl.eval(ctx)
            return self.value.eval(ctx)
        finally:
            ctx.pop()



@dataclass
class Function(Stmt):
    name: str
    params: list[str]
    body: Block

    def eval(self, ctx: Ctx):
        func = LoxFunction(
            name=self.name,
            params=self.params,
            body=self.body.stmts,
            ctx=ctx,
        )
        ctx.var_def(self.name, func)
        return func
    
@dataclass
class Command(Stmt):
    """Declaração de comando (função com escopo dinâmico)."""

    name: str
    params: list[str]
    body: Block

    def eval(self, ctx: Ctx):
        func = LoxCommand(
            name=self.name,
            params=self.params,
            body=self.body.stmts,
            ctx=ctx,
        )
        ctx.var_def(self.name, func)
        return func
@dataclass
class Class(Stmt):
    """
    Representa uma classe.

    Ex.: class B < A { ... }
    """

@dataclass
class UnaryOp(Expr):
    op: Callable[[Value], Value]
    operand: Expr

    def eval(self, ctx: Ctx):
        return self.op(self.operand.eval(ctx))
