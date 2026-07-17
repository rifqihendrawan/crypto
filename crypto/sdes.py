"""
Simplified DES (S-DES) implementation with full step-by-step tracing.
Reference: Stallings, "Cryptography and Network Security" - S-DES appendix.
"""

P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8 = [6, 3, 7, 4, 8, 5, 10, 9]
IP = [2, 6, 3, 1, 4, 8, 5, 7]
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]
EP = [4, 1, 2, 3, 2, 3, 4, 1]
P4 = [2, 4, 3, 1]

S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2],
]
S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3],
]


def permute(bits, table):
    """table is 1-indexed positions into bits"""
    return ''.join(bits[i - 1] for i in table)


def lshift(bits, n):
    n = n % len(bits)
    return bits[n:] + bits[:n]


def xor(a, b):
    return ''.join('1' if x != y else '0' for x, y in zip(a, b))


def sbox_lookup(bits4, sbox):
    """bits4: 4-bit string. row = bit0,bit3 ; col = bit1,bit2 (S-DES convention)"""
    row = int(bits4[0] + bits4[3], 2)
    col = int(bits4[1] + bits4[2], 2)
    val = sbox[row][col]
    return format(val, '02b'), row, col, val


def generate_keys(key10, steps):
    steps.append({"title": "Kunci Awal (10-bit)", "type": "bits",
                  "content": [{"label": "Key", "value": key10}]})

    p10 = permute(key10, P10)
    steps.append({"title": "Permutasi P10", "type": "bits",
                  "content": [{"label": "P10(Key)", "value": p10}]})

    l0, r0 = p10[:5], p10[5:]
    steps.append({"title": "Pembagian 5-bit Kiri/Kanan", "type": "bits",
                  "content": [{"label": "L0 (kiri)", "value": l0},
                              {"label": "R0 (kanan)", "value": r0}]})

    l1, r1 = lshift(l0, 1), lshift(r0, 1)
    steps.append({"title": "Left Shift 1 (LS-1)", "type": "bits",
                  "content": [{"label": "L1 = LS-1(L0)", "value": l1},
                              {"label": "R1 = LS-1(R0)", "value": r1}]})

    k1 = permute(l1 + r1, P8)
    steps.append({"title": "Permutasi P8 -> K1", "type": "bits",
                  "content": [{"label": "L1||R1", "value": l1 + r1},
                              {"label": "K1 = P8(L1||R1)", "value": k1}]})

    l2, r2 = lshift(l1, 2), lshift(r1, 2)
    steps.append({"title": "Left Shift 2 (LS-2)", "type": "bits",
                  "content": [{"label": "L2 = LS-2(L1)", "value": l2},
                              {"label": "R2 = LS-2(R1)", "value": r2}]})

    k2 = permute(l2 + r2, P8)
    steps.append({"title": "Permutasi P8 -> K2", "type": "bits",
                  "content": [{"label": "L2||R2", "value": l2 + r2},
                              {"label": "K2 = P8(L2||R2)", "value": k2}]})

    return k1, k2


def fk(bits8, key8, steps, round_label):
    l, r = bits8[:4], bits8[4:]
    ep = permute(r, EP)
    xored = xor(ep, key8)
    steps.append({"title": f"{round_label}: Expansion/Permutation (E/P) & XOR K", "type": "bits",
                  "content": [{"label": "R (4-bit)", "value": r},
                              {"label": "E/P(R) (8-bit)", "value": ep},
                              {"label": "Kunci Ronde", "value": key8},
                              {"label": "E/P(R) XOR K", "value": xored}]})

    left4, right4 = xored[:4], xored[4:]
    s0_out, r0, c0, v0 = sbox_lookup(left4, S0)
    s1_out, r1_, c1, v1 = sbox_lookup(right4, S1)
    steps.append({"title": f"{round_label}: Substitusi S-Box", "type": "table",
                  "content": {
                      "headers": ["S-Box", "Input 4-bit", "Baris", "Kolom", "Nilai", "Output 2-bit"],
                      "rows": [
                          ["S0", left4, str(r0), str(c0), str(v0), s0_out],
                          ["S1", right4, str(r1_), str(c1), str(v1), s1_out],
                      ]}})

    p4_in = s0_out + s1_out
    p4_out = permute(p4_in, P4)
    steps.append({"title": f"{round_label}: Permutasi P4", "type": "bits",
                  "content": [{"label": "S0||S1", "value": p4_in},
                              {"label": "P4(S0||S1)", "value": p4_out}]})

    new_l = xor(p4_out, l)
    steps.append({"title": f"{round_label}: XOR dengan L", "type": "bits",
                  "content": [{"label": "P4 output", "value": p4_out},
                              {"label": "L", "value": l},
                              {"label": "L' = P4 XOR L", "value": new_l}]})

    return new_l + r


def run_sdes(plaintext8, key10, mode, steps):
    """mode: 'encrypt' or 'decrypt'. Returns 8-bit result string."""
    steps.append({"title": "Diketahui", "type": "bits",
                  "content": [
                      {"label": "Plaintext" if mode == "encrypt" else "Ciphertext", "value": plaintext8},
                      {"label": "Key (10-bit)", "value": key10}]})

    k1, k2 = generate_keys(key10, steps)

    first_key, second_key = (k1, k2) if mode == "encrypt" else (k2, k1)

    ip = permute(plaintext8, IP)
    steps.append({"title": "Initial Permutation (IP)", "type": "bits",
                  "content": [{"label": "Input", "value": plaintext8},
                              {"label": "IP(input)", "value": ip}]})

    after_f1 = fk(ip, first_key, steps, "Round Function 1")

    swapped = after_f1[4:] + after_f1[:4]
    steps.append({"title": "Swap (SW)", "type": "bits",
                  "content": [{"label": "Sebelum swap", "value": after_f1},
                              {"label": "Setelah swap", "value": swapped}]})

    after_f2 = fk(swapped, second_key, steps, "Round Function 2")

    result = permute(after_f2, IP_INV)
    steps.append({"title": "Final Permutation (IP-1)", "type": "bits",
                  "content": [{"label": "Input", "value": after_f2},
                              {"label": "IP-1(input)", "value": result}]})

    steps.append({"title": "Hasil Akhir", "type": "bits",
                  "content": [{"label": "Ciphertext" if mode == "encrypt" else "Plaintext", "value": result}]})

    return result, {"k1": k1, "k2": k2}
