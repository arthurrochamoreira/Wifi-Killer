# Blocos como expressões

Em Lox, blocos são comandos e portanto não podem aparecer em locais onde se 
espera uma expressão. Algumas linguagens orientadas a expressões permitem tratar 
blocos como expressões. Um exemplo disso é o Rust, onde uma declaração como a 
abaixo é válida:

```lox
var soma = {
    var x = 1;
    var y = 2;
    x + y
};
print soma;  // saída: 3
```

(no Rust trocaríamos var, por let, mas a estrutura é a mesma)

O valor do bloco é dado pelo valor da última expressão.

Implemente suporte a blocos de expressão na sua gramática. Os blocos de
expressão são formados por uma sequência de zero ou mais declarações e terminam
em uma única expressão.

O bloco deve avaliar todas as declarações como um bloco normal e retornar o
valor da expressão final como sendo o valor do bloco. Coloque as expressões de
bloco como a construção com maior nível de precedência junto com expressões
entre parênteses.