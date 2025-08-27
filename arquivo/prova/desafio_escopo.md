# Escopo dinâmico

Lox, assim como quase todas linguagens de programação, possui escopo léxico.
Isso significa que a resolução de variáveis em uma função é feita de acordo com
a posição da mesma no momento onde a função é declarada e não no momento onde
ela é chamada.

Para entender a diferença:

```lox 
var z = 10;

fun f(x, y) {
    return x + y + z;
}

fun g(x) {
    var z = 2;
    var y = z * x;
    return f(x, y)
}

print g(1);
```

O comando `g(1, 2)` imprimiria 23 usando a regra de escopo léxico já que a
declaração de `z` dentro de `g` não altera a resolução de `z` no corpo de `f`.
Em uma linguagem com escopo dinâmico, o resultado seria `5`, já que `f` daria
preferência para o `z` no escopo atual de execução e não no escopo aonde `f` foi
definida.

É lógico que uma linguagem com escopo puramente dinâmico seria bastante difícil
de utilizar, já que os conflitos de nome causariam vários conflitos e bugs
imprevisíveis. No entanto, formas controladas de escopo dinâmico podem ser
úteis.

Vamos introduzir uma nova sintaxe à linguagem para chamar funções com escopo
flexível: `func!(arg1, arg2, arg3)`. Note o símbolo `!` no final do nome. Vamos
chamar estas funções de comandos e elas terão um tratamento especial em Lox.

## Sintaxe

Vamos tratar a `!` como parte do nome do comando. Para isso, criamos mais um
símbolo terminal na gramática:

```lark
VAR_BANG.2 = VAR "!"
```

Depois crie suporte na sua gramática variáveis de comando e declarações de
comando:

```lark
command  : "fun" VAR_BANG "(" args ")" block

atom     : NUMBER | STRING | ... | VAR | VAR_BANG
```

## Semântica

Modifique a classe `lox.ast.Call` para lidar com comandos de forma explícita. O
comando é uma função ordinária que recebe o contexto explicitamente como
primeiro argumento. Isso permite a resolução de algumas variáveis num escopo
dinânmico.

```python
class Call(Expr):
    ...
    def eval(self, ctx: Ctx):
        func = ...
        args = ... 
        
        # Verificamos se `func` é um comando
        if isinstance(func, LoxCommand):
            return func(ctx, *args) # comandos recebem o contexto explicitamente
                                    # como primeiro argumento
        else:
            return func(*args)
```

A implementação de LoxCommand é muito semelhante à LoxFunction. Você pode
inclusive copiar e colar a classe e fazer as alterações necesssárias. Lembre-se
que LoxCommand recebe um argumento a mais (o contexto) e deve salvá-lo dentro
sob uma chave especial que, por convenção, chamamos de "!".


```python
class LoxCommand:
    ...
    def __call__(self, ctx, *args):
        ctx = ...               # cria contexto
        ctx.var_def("!", ctx)   # salvamos o contexto na variável especial `!`
        ...                     # termina a execução da função...
```

Finalmente, implementamos o método eval para as váráveis `VarBang` para dar
prioridade para buscar o valor dentro de `!` e não do contexto atual

```python
@dataclass
class VarBang(Expr):
    ...

    def eval(self, ctx: Ctx):
        key = ... # nome da variável
        
        # Busca em "!" antes, caso ele exista e caso a variável esteja definida 
        # no contexto dinâmico
        if "!" in ctx and key in ctx["!"]:
            return ctx["!"][key]
        return ctx[key]
```

Implemente o suporte para essa funcionalidade modificando a gramática, a classe
LoxTransformer e modificando as classes e métodos mostrados acima.

Mostramos abaixo um exemplo de uso de escopo dinâmico para controlar efeitos no 
código.

```lox
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

show_person!("Maria", 20);  // Mostra maria
```