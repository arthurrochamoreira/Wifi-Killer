# Strings
#
# A declaração de strings em Lox possui a seguinte gramática:
#
# ```lark
# string    : QUOTE NON_QUOTE* QUOTE
#
# QUOTE     : /"/
# NON_QUOTE : /[^"]/
# ```
# Isso permite criar strings como `"foo"`, `"foo bar"`, `""` entre outras.
# Implemente suporte para substituição de variáveis para que strings da forma
# `"foo: ${x}"` na realidade substituam o valor de uma variável x na posição em
# que ela aparece na string.
#
# Dois cifrões seguidos são usados como sequência de escape, ou seja, a
# string `"foo: $${x}"` deve ser interpretada como `"foo: ${x}"`, sem realizar a
# substituição de variável.
#
# Use as mesmas regras do Lox para a definição de variáveis.
from lark import Lark, Transformer, v_args

# Modifique a gramática abaixo para que ela reconheça strings com variáveis
grammar = r"""
string    : QUOTE NON_QUOTE* QUOTE

QUOTE     : /"/
NON_QUOTE : /[^"]/
"""


# Modifique o Transformer para que ele avalie a string de entrada e faça a
# substituição de variáveis
@v_args(inline=True)
class StringTransformer(Transformer):
    def __init__(self, vars=None):
        if vars is None:
            vars = {}
        self.vars = vars
        super().__init__()

    def string(self, *args):
        return "..."  # implemente o transformer aqui!


# Não modifique essa função!
def parse(st: str, vars: dict, show_tree=False):
    """
    Lê string com substituição de variáveis e retorna o resultado da substituição.
    """
    lark = Lark(grammar, start="string", parser="lalr")
    tree = lark.parse(st)
    if show_tree:
        print(tree.pretty())
        return
    transformer = StringTransformer(vars)
    return transformer.transform(tree)


# O comando abaixo permite interagir com os casos de teste
#
#   $ uv run prova/q2b_strings.py
#
# Depois execute os testes com
#
#   $ uv run pytest tests/test_q2b.py
#
if __name__ == "__main__":
    # Mude para True se quiser ver a árvore sintática
    show_tree = False
    kwargs = {"show_tree": show_tree}

    # "foo x bar"
    print(parse('"foo ${x} bar"', {"x": "x"}, **kwargs))

    # "valor: R$10,00"
    # print(parse('"valor: R$$10,00"', {}, **kwargs))

    # "foo ${x} bar"
    # print(parse('"foo $${x} bar"', {"x": "42"}, **kwargs))

    # "$var = ok"
    # print(parse('"$$var = ${var}"', {"var": "ok", **kwargs}))

    # "1 + 2 = 3"
    # ctx = {"x": "1", "y": "2", "_result": "3"}
    # print(parse('"${x} + ${y} = ${_result}"', ctx, **kwargs))
