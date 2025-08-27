from lox import *
from lox import testing
from lox.ast import *

src = """
var soma = {
    var x = 1;
    var y = 2;
    x + y
};
print soma;  // saída: 3
"""


class TestBlocks(testing.ExerciseTester):
    is_expr = True
    src1 = "{ var x = 1; var y = 2; x + y }"
    src2 = "{1 + 2}"
    src3 = "f({ var x = 1; var y = 2; x + y })"
    tks1 = "x y"
    tks2 = "1 2"
    tks3 = "f x y"
    ast_class1 = Node
    ast_class2 = Node
    ast_class3 = Call

    def eval_env(self, n):
        ctx = {"f": lambda x: x}
        return (ctx, 3)

    def test_expressão_de_bloco_isola_as_varáveis(self):
        def check(result, stdout, _):
            assert stdout == "3\n"
            assert "x" not in ctx
            assert "y" not in ctx

        ctx = {}
        self.verify(src, {}, expect_verifier=check, parse="stmt")
