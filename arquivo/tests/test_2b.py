from pathlib import Path
from types import SimpleNamespace

BASE = Path(__file__).parent.parent / "prova"


class TestStringSubs:
    def parse(self, src: str, ctx: dict) -> str:
        print("Código:")
        print(f"    {src}\n")
        print("Variáveis:")
        print("    ", ctx)
        mod = self.mod()
        return mod.parse(src, ctx)

    def mod(self):
        path = BASE / "q2b_strings.py"
        src = path.read_text(encoding="utf-8")
        code = compile(src, path, "exec")
        exec(code, ns := {})
        return SimpleNamespace(parse=ns["parse"])

    def test_string_sem_substituição(self):
        ctx = {}
        parse = self.parse
        result = parse('"foo bar"', ctx)
        assert result == "foo bar"

    def test_string_com_substituição_simples(self):
        parse = self.parse
        assert parse('"foo ${x} bar"', {"x": "x"}) == "foo x bar"
        assert parse('"foo ${x} bar"', {"x": "42"}) == "foo 42 bar"

    def test_sequência_de_escape(self):
        parse = self.parse
        assert parse('"valor: R$$10,00"', {}) == "valor: R$10,00"
        assert parse('"foo $${x} bar"', {"x": "42"}) == "foo ${x} bar"

    def test_string_com_várias_substituições(self):
        parse = self.parse
        ctx = {"x": "1", "y": "2", "_result": "3"}
        assert parse('"${x} + ${y} = ${_result}"', ctx) == "1 + 2 = 3"
        assert parse('"$$var = ${var}"', {"var": "ok"}) == "$var = ok"
