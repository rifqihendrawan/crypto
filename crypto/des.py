"""
Data Encryption Standard (DES) implementation with full step-by-step tracing.
Standard textbook tables (FIPS 46-3).
"""

IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

IP_INV = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25]

E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

SBOX = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
]


def permute(bits, table):
    return ''.join(bits[i - 1] for i in table)


def lshift(bits, n):
    n = n % len(bits)
    return bits[n:] + bits[:n]


def xor(a, b):
    return ''.join('1' if x != y else '0' for x, y in zip(a, b))


def hex_to_bin(h, bitlen):
    return format(int(h, 16), '0{}b'.format(bitlen))


def bin_to_hex(b):
    return format(int(b, 2), '0{}X'.format(len(b) // 4))


def generate_subkeys(key64, steps):
    steps.append({"title": "Kunci Awal (64-bit)", "type": "bits",
                  "content": [{"label": "Key", "value": key64}]})

    pc1 = permute(key64, PC1)
    c, d = pc1[:28], pc1[28:]
    steps.append({"title": "Permutasi Choice 1 (PC-1)", "type": "bits",
                  "content": [{"label": "PC-1(Key) 56-bit", "value": pc1},
                              {"label": "C0 (28-bit)", "value": c},
                              {"label": "D0 (28-bit)", "value": d}]})

    subkeys = []
    rows = []
    for i in range(1, 17):
        c = lshift(c, SHIFT_SCHEDULE[i - 1])
        d = lshift(d, SHIFT_SCHEDULE[i - 1])
        k = permute(c + d, PC2)
        subkeys.append(k)
        rows.append([f"K{i}", str(SHIFT_SCHEDULE[i - 1]), c, d, k])

    steps.append({"title": "Left Shift & Permutasi Choice 2 (PC-2) tiap Ronde", "type": "table",
                  "content": {"headers": ["Subkey", "Left Shift", "Ci (28-bit)", "Di (28-bit)", "Ki (48-bit)"],
                              "rows": rows}})
    return subkeys


def feistel_round(l, r, subkey, round_num, steps, is_last):
    ep = permute(r, E)
    xored = xor(ep, subkey)
    steps.append({"title": f"Ronde {round_num}: Expansion (E) & XOR K{round_num}", "type": "bits",
                  "content": [{"label": "R (32-bit)", "value": r},
                              {"label": "E(R) (48-bit)", "value": ep},
                              {"label": f"K{round_num}", "value": subkey},
                              {"label": "E(R) XOR K", "value": xored}]})

    sbox_rows = []
    sbox_out = ""
    for i in range(8):
        block6 = xored[i * 6:(i + 1) * 6]
        row = int(block6[0] + block6[5], 2)
        col = int(block6[1:5], 2)
        val = SBOX[i][row][col]
        val4 = format(val, '04b')
        sbox_out += val4
        sbox_rows.append([f"S{i+1}", block6, str(row), str(col), str(val), val4])

    steps.append({"title": f"Ronde {round_num}: Substitusi 8 S-Box", "type": "table",
                  "content": {"headers": ["S-Box", "Input 6-bit", "Baris", "Kolom", "Nilai", "Output 4-bit"],
                              "rows": sbox_rows}})

    p_out = permute(sbox_out, P)
    steps.append({"title": f"Ronde {round_num}: Permutasi P", "type": "bits",
                  "content": [{"label": "Gabungan S-Box (32-bit)", "value": sbox_out},
                              {"label": "P(output)", "value": p_out}]})

    new_r = xor(p_out, l)
    steps.append({"title": f"Ronde {round_num}: XOR dengan L & Swap", "type": "bits",
                  "content": [{"label": "L (lama)", "value": l},
                              {"label": "P output", "value": p_out},
                              {"label": "L XOR P = R (baru)", "value": new_r},
                              {"label": "R (lama) = L (baru)" + ("" if not is_last else " [ronde 16: tanpa swap]"),
                               "value": r}]})

    if is_last:
        return r, new_r  # no swap on round 16 -> combine as L16=old R, R16=new_r... per spec L16R16 (preswap) used directly
    else:
        return r, new_r  # new L = old R, new R = new_r (this already represents the swap)


def run_des(text64, key64, mode, steps):
    steps.append({"title": "Diketahui", "type": "bits",
                  "content": [
                      {"label": "Plaintext" if mode == "encrypt" else "Ciphertext", "value": text64},
                      {"label": "Key (64-bit)", "value": key64}]})

    subkeys = generate_subkeys(key64, steps)
    if mode == "decrypt":
        subkeys = list(reversed(subkeys))

    ip = permute(text64, IP)
    l, r = ip[:32], ip[32:]
    steps.append({"title": "Initial Permutation (IP)", "type": "bits",
                  "content": [{"label": "Input", "value": text64},
                              {"label": "IP(input)", "value": ip},
                              {"label": "L0", "value": l},
                              {"label": "R0", "value": r}]})

    for i in range(16):
        is_last = (i == 15)
        l, r = feistel_round(l, r, subkeys[i], i + 1, steps, is_last)

    # After round 16 there is no swap: preswap L16R16 = R15||(L15 xor f) ; but our loop already
    # produced l,r as (old_r, new_r) each round which effectively performs the swap each time.
    # To get the correct "no swap after round 16" result we must undo the last swap.
    l16r16 = r + l  # undo swap of final round -> R16 || L16 becomes L16||R16 = r + l
    steps.append({"title": "Gabungan Akhir (Tanpa Swap Ronde 16)", "type": "bits",
                  "content": [{"label": "L16", "value": l},
                              {"label": "R16", "value": r},
                              {"label": "L16 || R16", "value": l16r16}]})

    result = permute(l16r16, IP_INV)
    steps.append({"title": "Final Permutation (IP-1)", "type": "bits",
                  "content": [{"label": "Input", "value": l16r16},
                              {"label": "IP-1(input)", "value": result}]})

    steps.append({"title": "Hasil Akhir", "type": "bits",
                  "content": [{"label": "Ciphertext" if mode == "encrypt" else "Plaintext", "value": result}]})

    return result
