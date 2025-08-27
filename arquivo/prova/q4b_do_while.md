# do while

C possui o comando "do { ... } while (cond)", que funciona basicamente como o
while, mas confere a condição após a excução do bloco de comandos e não antes.
Isso pode ser considerado um açucar sintático já que é sempre possível
reescrever o do/while usando blocos de comando e o próprio while.

Implemente o suporte à sintaxe do/while em Lox. 

```lox
var i = 0;

do {
    // No do/while, sempre executamos pelo menos uma vez o corpo
    i = i + 1;
    print i;
} while (i <= 5);
```

Para seguir a consistência com o while, aceitamos blocos com um único comando

```lox
var i = 0;

do i = i + 1; while (i <= 5);
```

Decida a estratégia de implementação: se é criar um nó especializado `DoWhile`
na árvore sintática ou se deve converter do/while em comandos mais básicos como
blocos + while. Ambos funcionam bem. Escolha a estratégia e termine a
implementação até passar nos testes!