from types import SimpleNamespace

import pytest

from lox import *
from lox import testing
from lox.ast import *

src_a = """
var i = "40";
var iAlt = "2";
print i + iAlt;  // saída: 42
"""

src_b = """
var n = 30;
var m = 7;
var div = n / m;  // div vai guardar um inteiro!
var resto = n - m * div;

print resto; // saída: 2
"""


class TestImplicitInts(testing.ExerciseTester):
    is_expr = False
    src1 = "var i = 3.25;"
    src2 = "n = 1.5;"
    src3 = 'obj.n = "42";'
    tks1 = "i 3.25"
    tks2 = "n 1.5"
    tks3 = "obj n 42"
    ast_class1 = VarDef
    ast_class2 = Assign
    ast_class3 = Setattr

    def eval_env(self, n):
        obj = Obj()
        return ({"n": 0, "obj": obj}, n)

    def verify_eval_result(self, n, stdout, ctx):
        if n == 1:
            assert ctx["i"] == 3
        elif n == 2:
            assert ctx["n"] == 1
        elif n == 3:
            obj = ctx["obj"]
            assert obj.n == 42

    @pytest.mark.parametrize(
        "op, result",
        [("+", "13\n"), ("-", "7\n"), ("*", "30\n"), ("/", "3\n")],
    )
    def test_operações_com_inteiros(self, op, result):
        src = f"""
var n = 10;
var m = 3;
print n {op} m;
        """
        try:
            self.verify(src, ctx := {}, result)
        finally:
            print("\nContexto (saída):")
            print(ctx)

    def test_exemplo_coerção_de_strings(self):
        try:
            self.verify(src_a, ctx := {}, "42\n")
        finally:
            print("\nContexto (saída):")
            print(ctx)

    def test_exemplo_divisão_inteira(self):
        try:
            self.verify(src_b, ctx := {}, "2\n")
        finally:
            print("\nContexto (saída):")
            print(ctx)


class Obj(SimpleNamespace): ...
