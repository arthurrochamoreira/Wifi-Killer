# Inteiros

Lox não possui suporte para inteiros. Poderíamos implementar o suporte do modo
tradicional e discriminar números com parte decimal (que seriam entendidos como
floats) e números sem parte decimal (que seriam entendidos como inteiros). Ao
invés disso, vamos tomar como inspiração um linguagem de programação veterana, o
FORTRAN.

Nas primeiras versões do FORTRAN o tipo das variáveis era dado de forma
implícita: todas variáveis cujo nome comece com i, j, k, l, m e n é tratada como
inteira e todas as outras são consideradas implicitamente floats (ou reais, na
nomeclatura do FORTRAN). Versões posteriores da linguagem também adicionaram
suporte a números complexos, mas não vamos entrar nesses detalhes.

Vamos suportar essa (des?)funcionalidade em Lox. Modifique o seu interpretador
para que toda declaração de variável, toda atribuição e toda modificação de
atributo com variáveis e atributos que comecem com uma das letras citadas acima
provoquem uma conversão automática para int.

Depois dessa alteração, podemos escrever códigos como:

```lox
var i = "40";
var iAlt = "2";
print i + iAlt;  // saída: 42
```

Modifique as operações matemáticas para que operações com inteiros sempre 
retornem inteiros.

```lox
var n = 30;
var m = 7;
var div = n / m;  // div vai guardar um inteiro!
var resto = n - m * div;

print resto; // saída: 2
```

Letras maiúsculas não compartilham esse comportamento:

```lox
var I = 1.5;
print I; // saída: 1.5
```

Implemente a funcionalidade modificando o método eval das classes Assign, VarDef
e Setattr até passar em todos os testes.
