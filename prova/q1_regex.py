from lox.tools.q1_regex import grade_all

# Nessa questão, criaremos expressões regulares que reconhecem números romanos.
# Apesar de parecer simple a primeira vista, existem vários casos especiais que
# devem ser levados em consideração para evitar que se aceite números inválidos.
#

# [Q1a; 1pts]
# Vamos começar, criando uma regra que reconhece os números de I a IX.
#
# A regra abaixo reconhece números romanos de I a IX usando um método de
# "força bruta". Refatore para que a expressão fique mais compacta e aceite a
# string vazia.
#
# Vamos considerar por enquanto que a string vazia corresponde ao zero, ainda
# que esse número não exista no sistema de numeração romano.
Q1a: str = r"(I|II|III|IV|V|VI|VII|VIII|IX)?"

# [Q1b; 1pts]
# Modifique a expressão anterior para que a string vazia seja rejeitada. Note
# como a resposta ficou mais complicada!
Q1b: str = r"..."

# [Q1c; 0.5pts]
# Podemos simplificar a expressão anterior utilizando o operador de lookahead.
# Basta adicionar o lookahead positivo `(?=.)` antes da expressão em Q1a
# para garantir que a string possua pelo menos um caractere.
Q1c: str = r"(?=.)..."

# [Q1c; 0.5pts]
# Podemos facilmente criar uma expressão que lida com as dezenas simplesmente
# trocando I por X, V por L e X por C na expressão Q1a. Crie uma expressão deste
# tipo para reconhecer dezenas exatas entre X e XC.
Q1d: str = r"..."

# [Q1c; 0.5pt]
# Agora, faça a mesma coisa para as centenas, trocando X por C, L por D e C por M.
Q1e: str = r"..."

# [Q1f; 2.5pts]
# Finalmente, podemos juntar as expressões anteriores para reconhecer números
# romanos de I a MMMCMXCIX. Note que a ordem das expressões é importante, pois
# a expressão deve reconhecer os milhares, centenas, dezenas e unidades, nesta
# ordem.
#
# Lembre-se de incluir o lookahead positivo `(?=.)` para garantir que a string
# possua pelo menos um caractere.
Q1f: str = r"..."


# O comando abaixo executa a correção automática
#
#   $ uv run prova/q1_regex.py
#
grade_all(globals())