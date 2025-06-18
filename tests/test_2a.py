from lox import *
from lox import testing
from lox.ast import *


class TestTypeHints(testing.ExerciseTester):
    is_expr = False
    src1 = "var x: number = 42;"
    src2 = "fun f(x: number, s: string) -> Object? { return s; }"
    src3 = "fun f(x, y: number) { return x + y; }"
    tks1 = "x 42"
    tks2 = "f x s"
    tks3 = "f x y"
    ast_class1 = VarDef
    ast_class2 = Function
    ast_class3 = Function

    def eval_env(self, n):
        return ({}, n)

    def verify_eval_result(self, n, stdout, ctx):
        if n == 1:
            assert ctx["x"] == 42
        elif n == 2:
            f = ctx["f"]
            assert f(1, "test") == "test"
        elif n == 3:
            f = ctx["f"]
            assert f(1, 2) == 3
