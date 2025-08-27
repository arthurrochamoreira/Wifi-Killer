from lox import *
from lox import testing
from lox.ast import *

SRC = "var func = fun(x, y) { return x + y; };"


class TestLambdas(testing.ExerciseTester):
    is_expr = True
    src1 = "fun(x, y) { return x + y; }"
    src2 = "(fun(x) { return x + 1; })(41)"
    src3 = '(fun(x) { print x; })("ok")'
    tks1 = "x y"
    tks2 = "x 1 41"
    tks3 = "x ok"
    ast_class1 = Node
    ast_class2 = Call
    ast_class3 = Call
    test_eval = False

    def test_verifica_exemplo1(self):
        def check(fun, stdout, ctx):
            assert callable(fun)
            assert fun(1, 2) == 3

        self.verify(self.src1, {}, expect_verifier=check)

    def test_verifica_exemplo2(self):
        self.verify(self.src2, {}, 42.0)

    def test_verifica_exemplo3(self):
        self.verify(self.src3, {}, expect_stdout="ok\n")

    def test_verifica_exemplo_do_enunciado(self):
        def check(_, stdout, ctx):
            fun = ctx["func"]
            assert callable(fun)
            assert fun(1, 2) == 3
            assert fun(2, 3) == 5

        self.verify(SRC, {}, expect_verifier=check, parse="stmt")
