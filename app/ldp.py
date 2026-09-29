import math
import random
import string

PRINTABLE = string.ascii_letters + string.digits + string.punctuation

def k_rr(text: str, epsilon: float, seed: int | None = None) -> str:
    """Educational character-level k-RR implementation inspired by the paper.

    Characters are kept with probability 1-gamma; otherwise replaced by a
    uniformly random different printable ASCII character.
    """
    rng = random.Random(seed)
    k = len(PRINTABLE)
    gamma = (k - 1) / ((k - 1) + math.exp(epsilon))

    result = []
    for ch in text:
        if ch == " " or ch == "\n" or ch == "\t" or ch not in PRINTABLE:
            result.append(ch)
            continue
        if rng.random() < gamma:
            choices = [c for c in PRINTABLE if c != ch]
            result.append(rng.choice(choices))
        else:
            result.append(ch)
    return "".join(result)
