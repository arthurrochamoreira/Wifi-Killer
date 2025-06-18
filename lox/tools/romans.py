import random
from string import ascii_uppercase

LETTERS = ascii_uppercase + 20 * "IVXLCDM"
ROMANS: dict[str, int] = {}


def to_roman(n: int) -> str:
    """
    Converte um número inteiro para o formato romano.
    """
    if n < 1 or n > 3999:
        raise ValueError("Número fora do intervalo permitido (1-3999).")

    roman_numerals = [
        (1000, "M"),
        (900, "CM"),
        (500, "D"),
        (400, "CD"),
        (100, "C"),
        (90, "XC"),
        (50, "L"),
        (40, "XL"),
        (10, "X"),
        (9, "IX"),
        (5, "V"),
        (4, "IV"),
        (1, "I"),
    ]

    result = []
    for value, numeral in roman_numerals:
        while n >= value:
            result.append(numeral)
            n -= value

    return "".join(result)


def is_roman(roman: str) -> bool:
    """
    Verifica se a string é um número romano válido.
    """
    return roman in ROMANS


def from_roman(roman: str) -> int:
    """
    Converte um número romano para o formato inteiro.
    """
    try:
        return ROMANS[roman]
    except KeyError:
        raise ValueError(f"Número romano inválido: {roman}")


def assert_invalid(func, value):
    try:
        result = func(value)
    except ValueError:
        return
    msg = f"Esperava erro, obteve: {func.__name__}({value!r}) = {result!r}"
    raise AssertionError(msg)


def invalid_numbers(size=200) -> list[str]:
    """
    Gera uma lista de strings com números romanos inválidos.
    """

    def char():
        return random.choice(LETTERS)

    def num():
        n = random.randint(1, 20)
        return "".join(char() for _ in range(n))

    bad_examples: list[str] = []
    while len(bad_examples) < size:
        if not is_roman(st := num()):
            bad_examples.append(st)
    return bad_examples


ROMANS.update((to_roman(n), n) for n in range(1, 4000))


if __name__ == "__main__":
    for i in range(1, 4000):
        roman = to_roman(i)
        assert from_roman(roman) == i, f"{roman} ({i}) != {from_roman(roman)}"

    assert_invalid(from_roman, "IVI")
    assert_invalid(from_roman, "VX")
    assert_invalid(from_roman, "")
