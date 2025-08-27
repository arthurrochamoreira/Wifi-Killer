# Declaração de tipos

Lox, assim como Python, é uma linguagem dinamicamente tipada. Isso significa que
os tipos são determinados em tempo de execução e não durante a compilação ou
análise semântica. 

Mesmo linguagens dinamicamente tipadas podem se beneficiar de declarações de
tipos como forma de documentação ou de apoio a ferramentas de análise estática.
Vamos criar suporte a declarações opcionais de tipos na linguagem. Note que
essas declarações não influenciam a execução do programa em absolutamente nada e
são apenas uma extensão sintática à linguagem para expressar tipos de uma forma
mais conveniente que comentários.

Os tipos podem aparecer tanto em declarações de variáveis quanto em funções:

```lox
// Declaração de tipo de uma variável
var x: number = 42;

// Declaração de tipo de uma função
fun f(st: string?, n: number) -> string {
    return "some result"
}
```

Implemente suporte a declaração de tipos nestes dois casos. Algumas observações 
importantes:

* A declaração de tipos é sempre opcional.
* Os tipos são sempre da forma "identificador" ou "identificador?" a segunda
  forma denota um tipo "anulável", ou seja, que aceita `nil` como valor.
* Os tipos não influenciam em nada na execução do programa.
* É possível fazer declarações parciais, por exemplo declarando os tipos de
  alguns argumentos de uma função, mas não de outros (inclusive o retorno).