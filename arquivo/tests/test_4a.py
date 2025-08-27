from lox import *
from lox import testing
from lox.ast import *


class TestDoWhile(testing.ExerciseTester):
    is_expr = False
    src1 = "do { i = i + 1; print i; } while (i <= 5);"
    src2 = "do i = i + 1; while (i <= 5) ;"
    src3 = "do do i = i + 1; while (i <= 5) ; while (i <= 5);"
    tks1 = "i 5"
    tks2 = "i 5"
    tks3 = "i 5"
    ast_class1 = Stmt
    ast_class2 = Stmt
    ast_class3 = Stmt
    test_eval = False

    def eval_env(self, n):
        return ({"i": 0}, n)

    def verify_eval_result(self, n, stdout, ctx):
        if n == 1:
            assert stdout == "1\n2\n3\n4\n5\n"
        elif n == 2:
            i = ctx["i"]
            assert i == 6
        elif n == 3:
            i = ctx["i"]
            assert i == 6

    def test_zero_funciona_como_true_na_condição(self):
        src = """
var a = 0;
var cond = 0;
do {
    a = a + 1;
    print a;
    if (a >= 3) {
        cond = false;
    }
} while (cond);
"""
        self.verify(src, {}, expect_stdout="1\n2\n3\n")

    def test_do_while_aninhados(self):
        src = """
do {
    do {
        print "inner";
    } while (false);
    print "outer";
} while (false);
"""
        self.verify(src, {}, expect_stdout="inner\nouter\n")
