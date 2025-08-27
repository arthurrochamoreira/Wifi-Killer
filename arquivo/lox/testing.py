"""
ATENÇÃO: EVITE MODIFICAR ESTE ARQUIVO!

Funções que auxiliam na criação de testes e execução de exemplos.
"""

import builtins
import contextlib
import io
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Iterable

import pytest
from lark import Tree, UnexpectedCharacters, UnexpectedToken

try:
    from rich import print
except ImportError:
    pass

from . import Node, parse, parse_cst, parse_expr
from . import eval as lox_eval
from . import parse as parse_stmt
from .ast import Literal, Program
from .ctx import Ctx
from .errors import SemanticError

BASE_DIR = Path(__file__).parent.parent
EXERCISES = BASE_DIR / "exercicios"
EXAMPLES = BASE_DIR / "exemplos"
EXERCISES_ALT = BASE_DIR / "exercícios"
LEX_REGEX = re.compile(
    r"""
    (?://\ *expect:\ (?P<EXPECT>[^\n]*))
    | (?://\ *expect\ runtime\ error:\ (?P<RUNTIME_ERROR>[^\n]*))
    | (?://[^\n]*Error\ at\ '(?P<ERROR_AT>[^'\n]*)'[^\n]*)
    | (?://[^\n]*Error\ at\ end:(?P<ERROR_EOF>[^\n]*))
    | (?://[^\n]*Error:(?P<ERROR>[^\n]*))
    | (?P<COMMENT>//[^\n])
    | (?P<IGNORE>[^"/]+|"[^"]*"|//[^\n]*)
    """,
    re.VERBOSE,
)
NOT_GIVEN = NotImplemented


@dataclass(frozen=True)
class Error:
    token: str | None = None
    line: int | None = None
    runtime: bool = False


@dataclass(frozen=True)
class Example:
    """
    Valores esperados dos exercícios.
    """

    src: str
    path: Path = Path("<string>")
    error: Error | None = None
    outputs: list[str] = field(default_factory=list)
    fuzzy: bool = False

    def __post_init__(self):
        for m in LEX_REGEX.finditer(self.src):
            if m.lastgroup == "IGNORE":
                continue
            elif m.lastgroup == "EXPECT":
                self.outputs.append(m.group("EXPECT"))
            elif m.lastgroup == "ERROR_AT":
                super().__setattr__("error", Error(token=m.group("ERROR_AT")))
                break
            elif m.lastgroup == "ERROR_EOF":
                super().__setattr__("error", Error(token=""))
                break
            elif m.lastgroup == "RUNTIME_ERROR":
                super().__setattr__("error", Error(token="", runtime=True))
                break
            elif m.lastgroup == "ERROR":
                super().__setattr__("error", Error())
                break

    @property
    def has_valid_syntax(self) -> bool:
        """
        Verifica se o exemplo possui uma sintaxe válida.
        """
        return self.error is None or self.error.runtime

    @property
    def expect_runtime_error(self) -> bool:
        """
        Verifica se o exemplo possui um erro de execução esperado.
        """
        return self.error is not None and self.error.runtime

    def eval(self) -> tuple[Ctx, str, str | None]:
        """
        Executa o exemplo.
        """
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout) as stdout:
            ctx = Ctx.from_dict({})
            try:
                lox_eval(self.src, ctx)
            except Exception as e:
                if self.error is not None and self.error.runtime:
                    return ctx, "", str(e)
                raise
        return ctx, stdout.getvalue(), None

    def test_example(self):
        """
        Executa o exemplo e verifica a saída padrão e erros.
        """

        try:
            if self.has_valid_syntax:
                self.check_fully_converted()
                ctx, stdout, err = self.eval()
                stdout = stdout.rstrip("\n")
                expect = "\n".join(self.outputs)

                if not self.expect_runtime_error and self.fuzzy:
                    assert fuzzy(expect) == stdout
                elif not self.expect_runtime_error:
                    assert expect == stdout
                else:
                    assert err is not None
            else:
                try:
                    parse(self.src)
                except UnexpectedToken as e:
                    assert (self.error.token == str(e.token)) or (  # type: ignore
                        self.error.token == str(e.token_history[-1])  # type: ignore
                    )
                except UnexpectedCharacters:
                    assert self.error.token is None
                except SemanticError as e:
                    assert self.error.token == str(e.token)
                else:
                    raise AssertionError(
                        "Esperava erro de sintaxe, mas isso não ocorreu."
                    )
        except:
            print("Erro ao executar o exemplo abaixo:")
            builtins.print(f"[{self.path.absolute()}]")
            print("\n    ".join(["", *self.src.splitlines(), ""]))
            print("Erros esperados:", self.error or "nenhum")
            raise

    def check_fully_converted(self):
        """
        Verifica se o exemplo foi totalmente convertido de CST para AST.
        """
        ast = parse(self.src)
        assert isinstance(ast, Node)

        def assert_not_lark(obj):
            if isinstance(obj, Tree):
                print(f"Esperava uma AST, mas encontrei um nó Lark do tipo {obj.data}:")
                print(obj.pretty())
                raise ValueError("árvore inválida")

        ast.visit({object: assert_not_lark})


class ExampleTester:
    module: str
    exclude: set[str] | None = None
    examples: Iterable[str] | None = None
    fuzzy_output: bool = False

    def __init_subclass__(cls, **kwargs):
        name = cls.__name__

        if not hasattr(cls, "module"):
            raise RuntimeError(f"Classe {name} deve definir o atributo 'module'")
        if cls.exclude is not None:
            examples = [*load_examples(cls.module, exclude=cls.exclude)]
        elif cls.examples is not None:
            examples = [*load_examples(cls.module, only=cls.examples)]
        else:
            examples = [*load_examples(cls.module)]

        names = [p.name.removesuffix(".lox") for p in examples]

        @pytest.mark.parametrize("path", examples, ids=names)
        def test_expected(self, path: Path):
            ex = Example(
                path.read_text(encoding="utf-8"),
                path=path,
                fuzzy=cls.fuzzy_output,
            )
            ex.test_example()

        test_name = "test_exemplo_válido"
        test_expected.__name__ = test_name
        test_expected.__qualname__ = f"{name}.{test_name}"
        setattr(cls, test_name, test_expected)

        super().__init_subclass__(**kwargs)


class ExerciseTester:
    try:
        import pytest_jsonreport as _  # type: ignore[import]
    except ImportError:

        @pytest.fixture
        def json_metadata(self):
            return {}

    is_expr = True
    src1: str
    src2: str
    src3: str
    n_sources: int
    ast_class1: type[Node] = property(lambda self: self.ast_class)  # type: ignore
    ast_class2: type[Node] = property(lambda self: self.ast_class)  # type: ignore
    ast_class3: type[Node] = property(lambda self: self.ast_class)  # type: ignore
    fuzzy_output: bool = False
    test_ast = True
    test_cst = True
    test_eval = True
    grades = {
        "cst": None,
        "ast": None,
        "eval": None,
    }

    @property
    def ast_class(self) -> type[Node]:
        msg = "Defina o atributo 'ast_class' ou 'ast_class(1|2|3)' com a classe esperada nos exemplos."
        raise NotImplementedError(msg)

    @pytest.fixture
    def grade(self, json_metadata):
        def grade(**kwargs):
            [(name, value)] = kwargs.items()
            name = name.removesuffix("_or")
            value = self.grades.get(name, value) or value
            json_metadata["grade"] = value
            return value

        return grade

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        if hasattr(cls, "src3"):
            cls.n_sources = 3
        elif hasattr(cls, "src2"):
            cls.n_sources = 2
        else:
            cls.n_sources = 1

        src_indexes = [*range(1, cls.n_sources + 1)]

        # Criamos testes com o número correto de parametrizações
        # Isso evita um número excessivo de testes pulados
        @pytest.mark.parametrize("n", src_indexes)
        def test_exemplo_produz_cst_válida(self: "ExerciseTester", n: int, grade):
            self._verify_cst(n, grade)

        @pytest.mark.parametrize("n", src_indexes)
        def test_exemplo_produz_ast_válida(self: "ExerciseTester", n: int, grade):
            self._verify_ast(n, grade)

        @pytest.mark.parametrize("n", src_indexes)
        def test_função_eval(self: "ExerciseTester", n: int, grade):
            self._verify_eval(n, grade)

        @pytest.mark.parametrize("n", src_indexes)
        def test_função_eval_alt(self: "ExerciseTester", n: int, grade):
            self._verify_eval(n, grade, alt=True)

        if cls.test_cst:
            cls.test_exemplo_produz_cst_válida = test_exemplo_produz_cst_válida
        if cls.test_ast:
            cls.test_exemplo_produz_ast_válida = test_exemplo_produz_ast_válida
        if cls.test_eval:
            cls.test_função_eval = test_função_eval

        if hasattr(cls, "eval_env_alt"):
            cls.test_função_eval_alt = test_função_eval_alt

    def parse_cst(self, src: str) -> Tree:
        if not src:
            return Tree("empty", [])
        return parse_cst(src, expr=self.is_expr)

    def parse(self, src: str, parse="auto") -> Node:
        if parse == "expr" or parse == "auto" and self.is_expr:
            if src:
                return parse_expr(src)
            return Literal(None)
        else:
            return parse_stmt(src)

    def src(self, i: int):
        """
        Retorna o código fonte do exemplo i.
        """
        try:
            return getattr(self, f"src{i}")
        except AttributeError:
            pytest.skip(f"Exemplo {i} não definido")

    def cst(self, i: int | str) -> Tree:
        """
        Árvore Lark para o exemplo i.
        """
        return self._prop("cst", i, self.parse_cst)

    def ast(self, i: int | str) -> Node:
        """
        AST para o exemplo i.
        """
        return self._prop("ast", i, self.parse)

    def tks(self, i: int) -> list[str]:
        """
        Tokens que devem aparecer na CST do exemplo i.
        """
        data = getattr(self, f"tks{i}", [])
        if isinstance(data, str):
            return data.split()
        return data

    def cls(self, i: int) -> type[Node]:
        """
        Retorna a classe AST esperada para o exemplo i.
        """
        return getattr(self, f"ast_class{i}")

    def eval_env(self, i: int) -> tuple[dict[str, Any], Any]:
        """
        Retorna o ambiente de avaliação ctx e o resultado esperado result para o exemplo i.
        """
        try:
            return getattr(self, f"eval_env{i}")()
        except AttributeError:
            pytest.skip(f"Ambiente de avaliação para exemplo {i} não definido")

    def assert_stdout_eq(self, stdout: str, expect: str):
        """
        Verifica se a saída padrão é igual à esperada.
        """
        if self.fuzzy_output:
            assert fuzzy(expect) == stdout
        else:
            assert stdout == expect

    def _verify_cst(self, n: int, grade=lambda **kwargs: None):
        grade(cst_or=1.0)

        cst = self.cst(n)
        msg = f"Exemplo {n} deve produzir uma CST, mas produziu: {cst}"
        assert isinstance(cst, Tree), msg

        pretty = cst.pretty()
        for tk in self.tks(n):
            assert tk in pretty, f"Token '{tk}' não encontrado na CST: {pretty}"

    def _verify_ast(self, n: int | str, grade=lambda **kwargs: None):
        grade(ast_or=1.0)

        ast = self.ast(n)
        if not self.is_expr and isinstance(ast, Program):
            assert len(ast.stmts) == 1, "Programa deveria ter apenas um comando"
            ast = ast.stmts[0]

        if isinstance(ast, Tree):
            msg = f"Exemplo {n} deve produzir um(a) AST, mas produziu uma CST:\n\n"
            msg += f"{ast.pretty()}\nImplemente a conversão de CST para AST implementando o método {ast.data} no LoxTransformer."
            raise TypeError(msg)

        if isinstance(n, int):
            cls = self.cls(n)
            msg = f"Exemplo {n} deve produzir um(a) {cls.__name__}, mas produziu: {type(ast).__name__}"
            assert isinstance(ast, cls), msg
        else:
            cls = self.cls(1)

        for bad in ast.lark_descendents():
            if isinstance(bad, Tree):
                elem = f"não-terminal {bad.data}"
            else:
                elem = f"terminal {bad.type}"
            msg = f"Você esqueceu de transformar um {elem} em {cls.__name__}?"
            assert False, msg

    def _verify_eval(self, n, grade, alt=False):
        grade(eval_or=1.0)

        src = self.src(n)
        print(f"Testando: {src=}")

        if alt:
            ctx, expect = self.eval_env_alt(n)
        elif alt:
            pytest.skip(f"Exemplo {n} não possui ambiente de avaliação alternativo")
        else:
            ctx, expect = self.eval_env(n)

        try:
            verifier = getattr(self, "verify_eval_result")
        except AttributeError:
            self.verify(self.ast(n), ctx, expect)
        else:
            self.verify(self.ast(n), ctx, expect_verifier=verifier)

    def _eval_in_context(
        self, ast: Node | str, env: Ctx | dict, parse="auto"
    ) -> tuple[Any, str]:
        """
        Avalia e retorna uma tupla (resultado, stdout).
        """
        if isinstance(ast, str):
            print("Código Lox:")
            print(indent(ast))

            ast = self.parse(ast, parse=parse)

        if isinstance(env, Ctx):
            ctx = env
        else:
            ctx = Ctx.from_dict(env)

        with contextlib.redirect_stdout(io.StringIO()) as fd:
            result = ast.eval(ctx)
            stdout = fd.getvalue()

        return result, stdout

    def verify(
        self,
        ast: Node | str,
        ctx: Ctx | dict,
        expect: Any = NOT_GIVEN,
        parse="auto",
        **kwargs,
    ):
        """
        Verifica a execução do código Lox e compara o resultado com o esperado.

        Args:
            ast (Node | str):
                O código Lox a ser avaliado, que pode ser uma árvore AST, uma
                string ou um exemplo identificado por um número.
            ctx (Ctx | dict):
                O contexto onde o código será avaliado, que pode ser um objeto
                Ctx ou um dicionário representando o ambiente.
            expect (Any, optional):
                O resultado esperado da avaliação. Pode ser um valor,
                um dicionário representando o contexto esperado, uma string
                representando a saída padrão.

                Se não for fornecido, deve ser passado exatamente um argumento
                nomeado começando com "expect_<method>" com os seguintes
                métodos:
                    value: compara a saída com um valor.
                    ctx: compara o contexto com um dicionário.
                    stdout: compara a saída padrão com uma string.
                    verifier: chama uma função de verificação com os resultados.
                        a função deve aceitar três argumentos:
                        o resultado, a saída padrão e o contexto.

                    none: não verifica nada.
                    raises: espera que uma exceção seja levantada.

        Examples:
            >>> self.verify_execution(
            ...     "print x;",
            ...     {"x": 42},
            ...     expect_stdout="42\n"
            ... )
        """
        print("Avaliando com o contexto:", ctx, "")

        if expect is NOT_GIVEN and len(kwargs) != 1:
            msg = "aceita exatamente 1 argumento nomeado (expect_value, expect_ctx, expect_stdout, expect_verifier, expect_raises)"
            raise TypeError(msg)
        elif expect is NOT_GIVEN:
            [(method, expect)] = kwargs.items()
            assert method.startswith("expect_")
            method = method.removeprefix("expect_")
        else:
            if self.is_expr:
                method = "value"
            elif isinstance(expect, str):
                method = "stdout"
            elif isinstance(expect, dict):
                method = "ctx"
            else:
                method = "unknown"

        if not isinstance(ctx, Ctx):
            ctx = Ctx.from_dict(ctx)

        if method == "raises":
            print(f"Espera-se exceção:\n    {expect}\n")
            try:
                result, stdout = self._eval_in_context(ast, ctx)
            except expect:
                return
            except Exception:
                raise
            else:
                print("Resultado:", result)
                print("Código executado, mas deveria ter levantado erro.")
                return

        result, stdout = self._eval_in_context(ast, ctx, parse=parse)

        match method:
            # Em expressões, o resultado é o valor da expressão.
            case "value":
                print(f"Resultado: {result}")
                assert result == expect, f"Esperava encontrar {expect}"

            # Em comandos, o resultado é None e o que importa é o conteúdo do contexto
            # ou a saída padrão.
            case "ctx":
                print("Contexto esperado:", expect)
                print("Contexto obtido:", ctx)

                for key, value in expect.items():
                    msg = f"Esperava encontrar variável '{key}' no contexto, não encontrei"
                    assert key in ctx, msg
                    assert ctx[key] == value

            # Comparamos a saída padrão com o esperado.
            case "stdout":
                print("\nSaída esperada:")
                print(indent(expect))
                print("\nSaída obtida:")
                print(indent(stdout))
                if self.fuzzy_output:
                    assert fuzzy(expect) == stdout
                else:
                    assert stdout == expect

            case "none":
                pass

            case "verifier":
                if not callable(expect):
                    raise TypeError(
                        f"expect_verifier deve ser uma função, mas encontrei {type(expect).__name__}"
                    )
                expect(result, stdout, ctx)

            case _:
                raise TypeError(
                    f"Tipo de resultado inesperado: {type(expect).__name__} (esperado str ou dict)"
                )

    def _prop(self, attr: str, i: int | str, factory: Callable):
        """
        Implementação de .ast() e .cst()
        """
        try:
            return getattr(self, f"{attr}{i}")
        except AttributeError:
            pass

        if isinstance(i, str):
            src = i
        else:
            src = self.src(i)

        print("\nCódigo Lox:")
        print(indent(src))
        obj = factory(src)
        setattr(self, f"{attr}{i}", obj)

        print("\nÁrvore:")
        try:
            print(indent(obj.pretty()))
        except Exception:
            print("    <Erro ao imprimir árvore>")

        return obj

    if TYPE_CHECKING:
        # Sobrescrita opcional
        def verify_eval_result(self, result: Any, stdout: str, ctx: Ctx | dict): ...


class fuzzy(str):
    def __new__(cls, value: str):
        return str.__new__(cls, value.lower())

    def __eq__(self, value) -> bool:
        if not isinstance(value, str):
            return False

        value = value.lower()
        if "\n" in self:
            this = [fuzzy(s) for s in self.splitlines()]
            other = value.splitlines()
            return this == other
        if (
            super().__eq__(value)
            or super().__eq__(value.replace("none", "nil"))
            or super().__eq__(value.removesuffix(".0"))
        ):
            return True
        return False


def load_examples(
    module: str,
    exclude: set[str] = set(),
    only: Iterable[str] | None = None,
):
    """
    Carrega exemplos de código.
    """
    base = EXAMPLES / module
    if only is not None:
        for name in only:
            path = base / f"{name}.lox"
            if path.exists():
                yield path
            else:
                path = path.relative_to(EXAMPLES)
                raise FileNotFoundError(f"Exemplo {path} não encontrado")
        return

    for path in sorted(base.iterdir()):
        name = path.name.removesuffix(".lox")
        if name not in exclude and not path.is_dir():
            yield path


@lru_cache(maxsize=512)
def load_example(place: Path) -> Example:
    return Example(place.read_text(encoding="utf-8"), path=place)


@lru_cache(maxsize=512)
def normalize(name: Path) -> str:
    """
    Normaliza o nome do arquivo.
    """
    return str(name).removeprefix(str(EXAMPLES) + os.path.sep).removesuffix(".lox")


def indent(st: str) -> str:
    """
    Indenta o texto com 4 espaços.
    """
    return "\n".join(" " * 4 + line if line else line for line in st.splitlines())
