import re
from dataclasses import dataclass, field
from typing import Iterable

from rich import print

from .romans import invalid_numbers, to_roman

INTERACTIVE = True
GRADES: dict[str, float] = {
    "Q1a": 1,
    "Q1b": 1,
    "Q1c": 0.5,
    "Q1d": 0.5,
    "Q1e": 0.5,
    "Q1f": 2.5,
}

Grade = float | int


@dataclass
class Report:
    grades: dict[str, Grade] = field(default_factory=dict)
    errors: dict[str, list[str]] = field(default_factory=dict)

    @property
    def total(self):
        return sum(self.grades.values())

    def __add__(self, other: "Report") -> "Report":
        if not isinstance(other, Report):
            raise TypeError(f"Cannot add {type(other)} to Report")
        return self.combine(other)

    def combine(self, other: "Report") -> "Report":
        return Report(
            grades={**self.grades, **other.grades},
            errors={**self.errors, **other.errors},
        )

    def show(self):
        if not self.errors:
            print(f"[green]Tudo certo! ({self.total}/25)[/]")
            return

        print("[bold red]Erros encontrados:[/]")
        for key, error in self.errors.items():
            print(f"\n[bold yellow]{key} (0/{GRADES[key]}):[/]")
            for msg in error:
                print(f"  - {msg}")

        print(f"\n[bold yellow]Pontuação total:[/] {self.total}/25")


def cfg(interactive: bool = True):
    """
    Configura o ambiente de correção
    """
    global INTERACTIVE

    INTERACTIVE = interactive


def grade_all(ns: dict[str, str]) -> Report:
    """
    Corrige a questão 1
    """
    small_regex = 13
    large_regex = 20
    report = Report()
    report += grade(
        regex=ns[q := "Q1a"],
        name=q,
        good=range(1, 9),
        bad=(bad_units := "IIII IVI IIV VV X XI".split()),
        max_size=small_regex,
        empty=True,
    )
    report += grade(
        regex=ns[q := "Q1b"],
        name=q,
        good=range(1, 9),
        bad=bad_units,
        max_size=large_regex,
    )
    report += grade(
        regex=ns[q := "Q1c"],
        name=q,
        good=range(1, 9),
        bad=bad_units,
        max_size=small_regex + 7,
        lookahead=True,
    )
    report += grade(
        regex=ns[q := "Q1d"],
        name=q,
        good=range(10, 100, 10),
        bad="XXXX XLX XXL LL C CX".split(),
        empty=True,
        max_size=small_regex,
    )
    report += grade(
        regex=ns[q := "Q1e"],
        name=q,
        good=range(100, 1000, 100),
        bad="CCCC CDC CCD DD M MC".split(),
        empty=True,
        max_size=small_regex,
    )
    report += grade(
        regex=ns[q := "Q1f"],
        name=q,
        good=range(1, 4000),
        bad="IIII IVI IIV VV XXXX XLX XXL LL CCCC CDC CCD DD CCCC CDC CCD DD".split()
        + invalid_numbers(),
        empty=False,
        lookahead=True,
        max_size=1000,
    )
    if INTERACTIVE:
        report.show()
    return report


def grade(
    regex: str,
    name: str,
    good: Iterable[int],
    bad: list[str],
    max_size: int,
    empty: bool = False,
    lookahead: bool = False,
) -> Report:
    errors: list[str] = []
    grade = GRADES[name]

    try:
        match = re.compile(regex).fullmatch
    except re.error as e:
        errors = [f"Expressão regular inválida {regex!r}: {e}"]
        return Report(grades={name: 0}, errors={name: errors})

    # Valida as corretas
    n_errors = 0
    for example in map(to_roman, good):
        if not match(str(example)):
            n_errors += 1
            if n_errors < 4:
                msg = f"Recusou exemplo válido: [green4 bold]{example}[/]"
                errors.append(msg)
            grade = 0
    if n_errors >= 4:
        errors.append(f"[grey37]... e mais {n_errors - 3} exemplos válidos![/]")

    # Invalida as incorretas
    n_errors = 0
    for example in bad:
        if match(example):
            n_errors += 1
            if n_errors < 4:
                msg = f"Aceitou exemplo inválido: [magenta bold]{example}[/]"
                errors.append(msg)
            grade = 0
    if n_errors >= 4:
        errors.append(f"[grey37]... e mais {n_errors - 3} exemplos inválidos![/]")

    # Verifica o tamanho máximo
    if len(regex) > max_size:
        msg = f"Regex muito longa, tamanho = [bold]{len(regex)}[/b] > {max_size}"
        errors.append(msg)
        grade = 0

    # Verifica se a string vazia é aceita
    if not empty and match(""):
        errors.append("Deveria recusar a string vazia!")
        grade = 0
    elif empty and not match(""):
        errors.append("Deveria aceitar a string vazia!")
        grade = 0

    # Verifica o lookahead
    if not lookahead and "(?=" in regex:
        errors.append("Não pode usar lookahead neste exemplo!")
        grade = 0

    return Report(
        grades={name: grade},
        errors={name: errors} if errors else {},
    )
