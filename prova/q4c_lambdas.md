# Funções anônimas

Em Lox, funções são declarações e não podem aparecer um um lugar que espera uma
expressão. No entanto, podemos modifcar a gramática muito levemente para aceitar
funções anônimas usando a sintaxe:

```lox
var func = fun(x, y) { return x + y; };
```

Note que a implementação foca basicamente na sintaxe já que o comportamento 
das funções normais e funções anônimas é o mesmo.

A declaração de função em Lox já é responsável por duas operações idependentes:
construir um objeto função e associá-lo a uma variável com o nome da função.
Funções anônimas simplesmente pulam a segunda parte!

Podemos utilizar a mesma classe LoxFunction para representar funções anônimas e
funções regulares. O Python, por exemplo, usa esta estratégia para implementar
os lambdas e funções criadas com `def`. Como o objeto que representa funções
possui um atributo que guarda o nome da mesma, precisamos atribuir um nome
genérico às funções anônimas. Python, por exemplo, usa "lambda". Podemos 
seguir o exemplo e salvar as funções anônimas como se chamassem "fun".

Implemente o suporte a funções anônimas (ou lambdas, como às vezes são chamadas
em programação funcional). 
