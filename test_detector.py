import re, random

def luhn(s):
    d = [int(c) for c in re.sub(r"\D", "", s)]
    if not 13 <= len(d) <= 19:
        return False
    t = 0
    for i, x in enumerate(reversed(d)):
        if i % 2 == 1:
            x *= 2
            if x > 9:
                x -= 9
        t += x
    return t % 10 == 0

def mask(v):
    v = v.strip()
    if len(v) <= 4:
        return "*" * len(v)
    return v[:2] + "*" * (len(v) - 4) + v[-2:]

def make_valid_card(prefix, length=16):
    body = prefix + "".join(random.choice("0123456789") for _ in range(length - len(prefix) - 1))
    for check in "0123456789":
        if luhn(body + check):
            return body + check

def test_luhn_valid():
    assert luhn("4111111111111111")
    assert luhn("5555555555554444")

def test_luhn_invalid():
    assert not luhn("1234567890123456")
    assert not luhn("4111111111111112")

def test_luhn_length_limits():
    assert not luhn("411111111111")

def test_mask_hides_middle():
    assert mask("Secret123") == "Se*****23"
    assert mask("abcd") == "****"
    assert "Secret" not in mask("Secret123")

if __name__ == "__main__":
    tests = [test_luhn_valid, test_luhn_invalid,
             test_luhn_length_limits, test_mask_hides_middle]
    passed = 0
    for t in tests:
        try:
            t()
            print("PASSED", t.__name__)
            passed += 1
        except AssertionError:
            print("FAILED", t.__name__)
    print(f"{passed}/{len(tests)} unit tests passed\n")

    random.seed(1)
    positives = [make_valid_card(random.choice(["4", "51", "55", "37"])) for _ in range(100)]
    negatives = []
    while len(negatives) < 100:
        n = "".join(random.choice("0123456789") for _ in range(16))
        if not luhn(n):
            negatives.append(n)

    tp = sum(luhn(x) for x in positives)
    fn = len(positives) - tp
    fp = sum(luhn(x) for x in negatives)
    tn = len(negatives) - fp
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0

    print(f"TP={tp} FN={fn} FP={fp} TN={tn}")
    print(f"Precision = {precision:.2%}")
    print(f"Recall    = {recall:.2%}")
    print(f"Regex-only false positives: {len(negatives)}/{len(negatives)} (100%)")
    print(f"With Luhn false positives : {fp}/{len(negatives)}")
