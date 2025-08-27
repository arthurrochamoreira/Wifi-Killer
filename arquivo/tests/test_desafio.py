import io
from contextlib import redirect_stdout

import pytest

from lox import *
from lox import testing
from lox.ast import *

SRC = """
fun show!(x) {
    print x;
}

fun show_person!(name, age) {
    show!("nome: ");
    show!(name);
    show!("idade: ");
    show!(age);
}

{
    fun show!(x) {}
    show_person!("João", 18);  // Nada acontece
}

show_person!("Maria", 20);     // Mostra maria
"""

SRC2 = """

fun show!(x) {
    print x;
}

fun show_pair!(x, y) {
    show!(x);
    show!(y);
}

{
    // Capturamos os prints para testar o programa
    var printed = "";
    
    fun show!(x) {
        printed = printed + x + ";";
    }
    
    show_pair!("foo", "bar");
    print printed == "foo;bar;"; // verdadeiro!
}

{
    // Usamos o efeito colateral de print
    show_pair!("foo", "bar");
}
"""


class TestBangCall(testing.ExerciseTester):
    is_expr = False
    src1 = 'fun show!(x) { print x; }\nshow!("hello world!");'
    src2 = "fun add!(x, y) { print x + y; }\nadd!(x, y);"
    src3 = "var x = cmd!;"
    tks1 = "show! x hello world"
    tks2 = "add! x y"
    tks3 = "x cmd!"
    test_ast = False
    fuzzy_output = True

    def eval_env(self, n):
        if n == 1:
            ctx = {}
            out = "hello world!\n"
        elif n == 2:
            ctx = {"x": "foo", "y": "bar"}
            out = "foobar\n"
        else:  # n == 3
            ctx = {"cmd!": eff, "x": 1.0}
            out = {"cmd!": eff}
        return (ctx, out)

    def test_comando_espera_o_contexto_como_primeiro_argumento(self):
        program = self.parse(self.src1)
        program.eval(ctx := Ctx.from_dict(env := {}))
        show = env["show!"]

        with redirect_stdout(io.StringIO()) as stdout:
            show(ctx, "hello world!")
        assert stdout.getvalue() == "hello world!\n"

        with pytest.raises(Exception):
            show("não passou o contexto como primeiro argumento")

    def test_exemplo_no_enunciado_da_questão(self):
        ctx = {}
        src = SRC
        out = "nome: \nMaria\nidade: \n20\n"
        self.verify(src, ctx, out)

    def test_exemplo_de_captura_de_print(self):
        ctx = {}
        src = SRC2
        out = "true\nfoo\nbar\n"
        self.verify(src, ctx, out)


def eff(ctx, *args):
    return str(args)
