"""
Simplified AES (S-AES) implementation with full step-by-step tracing.
Reference: Musa, Schaefer, Wedig - "A Simplified AES Algorithm ..." (2003)
"""

SBOX = [0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7]
INV_SBOX = [0] * 16
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

RCON1 = 0x80
RCON2 = 0x30


def sub_nib_byte(byte):
    hi = SBOX[(byte >> 4) & 0xF]
    lo = SBOX[byte & 0xF]
    return (hi << 4) | lo


def inv_sub_nib_byte(byte):
    hi = INV_SBOX[(byte >> 4) & 0xF]
    lo = INV_SBOX[byte & 0xF]
    return (hi << 4) | lo


def rot_nib(byte):
    hi = (byte >> 4) & 0xF
    lo = byte & 0xF
    return (lo << 4) | hi


def gmul4(a, b):
    """GF(2^4) multiplication mod x^4+x+1 (0b10011)"""
    p = 0
    for _ in range(4):
        if b & 1:
            p ^= a
        hi = a & 0x8
        a = (a << 1) & 0xF
        if hi:
            a ^= 0x3  # x^4 = x+1 -> reduce with 0b0011 after masking top bit
        b >>= 1
    return p & 0xF


def key_expansion(key16, steps):
    w0 = (key16 >> 8) & 0xFF
    w1 = key16 & 0xFF

    def g(w):
        rotated = rot_nib(w)
        subbed = sub_nib_byte(rotated)
        return subbed

    g1 = g(w1)
    w2 = w0 ^ g1 ^ RCON1
    w3 = w2 ^ w1
    g3 = g(w3)
    w4 = w2 ^ g3 ^ RCON2
    w5 = w4 ^ w3

    def hx(v):
        return format(v, '02X')

    steps.append({"title": "Key Expansion", "type": "table",
                  "content": {"headers": ["Langkah", "Nilai (hex)"], "rows": [
                      ["w0", hx(w0)],
                      ["w1", hx(w1)],
                      ["RotNib(w1)", hx(rot_nib(w1))],
                      ["SubNib(RotNib(w1)) = g(w1)", hx(g1)],
                      ["RCON1", hx(RCON1)],
                      ["w2 = w0 XOR g(w1) XOR RCON1", hx(w2)],
                      ["w3 = w2 XOR w1", hx(w3)],
                      ["RotNib(w3)", hx(rot_nib(w3))],
                      ["SubNib(RotNib(w3)) = g(w3)", hx(g3)],
                      ["RCON2", hx(RCON2)],
                      ["w4 = w2 XOR g(w3) XOR RCON2", hx(w4)],
                      ["w5 = w4 XOR w3", hx(w5)],
                  ]}})

    k0 = (w0 << 8) | w1
    k1 = (w2 << 8) | w3
    k2 = (w4 << 8) | w5
    steps.append({"title": "Round Keys", "type": "keyvalue",
                  "content": [{"label": "K0 = w0||w1", "value": format(k0, '04X')},
                              {"label": "K1 = w2||w3", "value": format(k1, '04X')},
                              {"label": "K2 = w4||w5", "value": format(k2, '04X')}]})
    return k0, k1, k2


def to_state(val16):
    """16-bit int -> nibbles n0 n1 n2 n3 -> state [[n0,n2],[n1,n3]]"""
    n0 = (val16 >> 12) & 0xF
    n1 = (val16 >> 8) & 0xF
    n2 = (val16 >> 4) & 0xF
    n3 = val16 & 0xF
    return [[n0, n2], [n1, n3]]


def from_state(state):
    n0, n2 = state[0]
    n1, n3 = state[1]
    return (n0 << 12) | (n1 << 8) | (n2 << 4) | n3


def state_hex(state):
    return [[format(v, '01X') for v in row] for row in state]


def nib_sub(state, inverse=False):
    tbl = INV_SBOX if inverse else SBOX
    return [[tbl[v] for v in row] for row in state]


def shift_rows(state):
    # swap the two nibbles in row 1 (index 1)
    return [state[0][:], [state[1][1], state[1][0]]]


def mix_columns(state):
    s = state
    new = [[0, 0], [0, 0]]
    for c in range(2):
        s0, s1 = s[0][c], s[1][c]
        new[0][c] = gmul4(1, s0) ^ gmul4(4, s1)
        new[1][c] = gmul4(4, s0) ^ gmul4(1, s1)
    return new


def inv_mix_columns(state):
    s = state
    new = [[0, 0], [0, 0]]
    for c in range(2):
        s0, s1 = s[0][c], s[1][c]
        new[0][c] = gmul4(9, s0) ^ gmul4(2, s1)
        new[1][c] = gmul4(2, s0) ^ gmul4(9, s1)
    return new


def add_round_key(state, key16):
    ks = to_state(key16)
    return [[state[r][c] ^ ks[r][c] for c in range(2)] for r in range(2)]


def add_step(steps, title, state):
    steps.append({"title": title, "type": "matrix", "content": state_hex(state)})


def run_saes(text_hex4, key_hex4, mode, steps):
    steps.append({"title": "Diketahui", "type": "keyvalue",
                  "content": [
                      {"label": "Plaintext" if mode == "encrypt" else "Ciphertext", "value": text_hex4},
                      {"label": "Key (16-bit)", "value": key_hex4}]})

    text_val = int(text_hex4, 16)
    key_val = int(key_hex4, 16)

    k0, k1, k2 = key_expansion(key_val, steps)

    state = to_state(text_val)
    add_step(steps, "State Awal", state)

    if mode == "encrypt":
        state = add_round_key(state, k0)
        add_step(steps, "Initial Round: AddRoundKey (State XOR K0)", state)

        state = nib_sub(state)
        add_step(steps, "Ronde 1: Nibble Substitution", state)
        state = shift_rows(state)
        add_step(steps, "Ronde 1: Shift Rows", state)
        state = mix_columns(state)
        add_step(steps, "Ronde 1: Mix Columns", state)
        state = add_round_key(state, k1)
        add_step(steps, "Ronde 1: Add Round Key (K1)", state)

        state = nib_sub(state)
        add_step(steps, "Ronde 2: Nibble Substitution", state)
        state = shift_rows(state)
        add_step(steps, "Ronde 2: Shift Rows", state)
        state = add_round_key(state, k2)
        add_step(steps, "Ronde 2: Add Round Key (K2, tanpa Mix Columns)", state)

    else:
        state = add_round_key(state, k2)
        add_step(steps, "Initial Round: AddRoundKey (State XOR K2)", state)

        state = shift_rows(state)
        add_step(steps, "Ronde 1: Inverse Shift Rows", state)
        state = nib_sub(state, inverse=True)
        add_step(steps, "Ronde 1: Inverse Nibble Substitution", state)
        state = add_round_key(state, k1)
        add_step(steps, "Ronde 1: Add Round Key (K1)", state)
        state = inv_mix_columns(state)
        add_step(steps, "Ronde 1: Inverse Mix Columns", state)

        state = shift_rows(state)
        add_step(steps, "Ronde 2: Inverse Shift Rows", state)
        state = nib_sub(state, inverse=True)
        add_step(steps, "Ronde 2: Inverse Nibble Substitution", state)
        state = add_round_key(state, k0)
        add_step(steps, "Ronde 2: Add Round Key (K0, hasil akhir)", state)

    result_val = from_state(state)
    result_hex = format(result_val, '04X')
    steps.append({"title": "Hasil Akhir", "type": "keyvalue",
                  "content": [{"label": "Ciphertext" if mode == "encrypt" else "Plaintext", "value": result_hex}]})
    return result_hex
