"""
AES-128 implementation with full step-by-step tracing.
Standard FIPS-197 tables and GF(2^8) arithmetic.
"""

SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def bytes_to_state(b):
    """16 bytes -> 4x4 state, column-major"""
    return [[b[r + 4 * c] for c in range(4)] for r in range(4)]


def state_to_bytes(s):
    return [s[r][c] for c in range(4) for r in range(4)]


def state_hex(s):
    return [[format(v, '02X') for v in row] for row in s]


def sub_word(word):
    return [SBOX[b] for b in word]


def rot_word(word):
    return word[1:] + word[:1]


def key_expansion(key_bytes, steps):
    Nk, Nr = 4, 10
    w = [list(key_bytes[4 * i:4 * i + 4]) for i in range(Nk)]

    rows = []
    for i in range(Nk, 4 * (Nr + 1)):
        temp = list(w[i - 1])
        note = ""
        if i % Nk == 0:
            rotated = rot_word(temp)
            subbed = sub_word(rotated)
            rcon_word = [RCON[i // Nk - 1], 0, 0, 0]
            temp = [subbed[j] ^ rcon_word[j] for j in range(4)]
            note = (f"RotWord({''.join(format(x,'02X') for x in w[i-1])})="
                    f"{''.join(format(x,'02X') for x in rotated)}, "
                    f"SubWord={''.join(format(x,'02X') for x in subbed)}, "
                    f"XOR Rcon[{i//Nk}]={''.join(format(x,'02X') for x in rcon_word)}")
        new_word = [w[i - Nk][j] ^ temp[j] for j in range(4)]
        w.append(new_word)
        rows.append([f"w{i}", ''.join(format(x, '02X') for x in new_word), note])

    steps.append({"title": "Key Expansion (w4 .. w43)", "type": "table",
                  "content": {"headers": ["Word", "Nilai (hex)", "Catatan"], "rows": rows}})

    round_keys = []
    for r in range(Nr + 1):
        words = w[4 * r:4 * r + 4]
        rk_state = [[words[c][row] for c in range(4)] for row in range(4)]
        round_keys.append(rk_state)
    return round_keys


def sub_bytes(state):
    return [[SBOX[v] for v in row] for row in state]


def inv_sub_bytes(state):
    return [[INV_SBOX[v] for v in row] for row in state]


def shift_rows(state):
    return [state[r][r:] + state[r][:r] for r in range(4)]


def inv_shift_rows(state):
    return [state[r][-r:] + state[r][:-r] if r != 0 else state[r][:] for r in range(4)]


def mix_columns(state):
    new_state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new_state[0][c] = gmul(col[0], 2) ^ gmul(col[1], 3) ^ col[2] ^ col[3]
        new_state[1][c] = col[0] ^ gmul(col[1], 2) ^ gmul(col[2], 3) ^ col[3]
        new_state[2][c] = col[0] ^ col[1] ^ gmul(col[2], 2) ^ gmul(col[3], 3)
        new_state[3][c] = gmul(col[0], 3) ^ col[1] ^ col[2] ^ gmul(col[3], 2)
    return new_state


def inv_mix_columns(state):
    new_state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new_state[0][c] = gmul(col[0], 14) ^ gmul(col[1], 11) ^ gmul(col[2], 13) ^ gmul(col[3], 9)
        new_state[1][c] = gmul(col[0], 9) ^ gmul(col[1], 14) ^ gmul(col[2], 11) ^ gmul(col[3], 13)
        new_state[2][c] = gmul(col[0], 13) ^ gmul(col[1], 9) ^ gmul(col[2], 14) ^ gmul(col[3], 11)
        new_state[3][c] = gmul(col[0], 11) ^ gmul(col[1], 13) ^ gmul(col[2], 9) ^ gmul(col[3], 14)
    return new_state


def add_round_key(state, rk):
    return [[state[r][c] ^ rk[r][c] for c in range(4)] for r in range(4)]


def add_step(steps, title, state):
    steps.append({"title": title, "type": "matrix", "content": state_hex(state)})


def run_aes(text_hex32, key_hex32, mode, steps):
    steps.append({"title": "Diketahui", "type": "keyvalue",
                  "content": [
                      {"label": "Plaintext" if mode == "encrypt" else "Ciphertext", "value": text_hex32},
                      {"label": "Key (128-bit)", "value": key_hex32}]})

    key_bytes = [int(key_hex32[i:i + 2], 16) for i in range(0, 32, 2)]
    text_bytes = [int(text_hex32[i:i + 2], 16) for i in range(0, 32, 2)]

    round_keys = key_expansion(key_bytes, steps)

    state = bytes_to_state(text_bytes)
    add_step(steps, "State Awal (Plaintext/Ciphertext)", state)
    add_step(steps, "Round Key 0", round_keys[0])

    if mode == "encrypt":
        state = add_round_key(state, round_keys[0])
        add_step(steps, "Initial Round: AddRoundKey (State XOR RK0)", state)

        for rnd in range(1, 10):
            state = sub_bytes(state)
            add_step(steps, f"Ronde {rnd}: SubBytes", state)
            state = shift_rows(state)
            add_step(steps, f"Ronde {rnd}: ShiftRows", state)
            state = mix_columns(state)
            add_step(steps, f"Ronde {rnd}: MixColumns", state)
            state = add_round_key(state, round_keys[rnd])
            add_step(steps, f"Ronde {rnd}: AddRoundKey (RK{rnd})", state)

        state = sub_bytes(state)
        add_step(steps, "Ronde 10: SubBytes", state)
        state = shift_rows(state)
        add_step(steps, "Ronde 10: ShiftRows", state)
        state = add_round_key(state, round_keys[10])
        add_step(steps, "Ronde 10: AddRoundKey (RK10, tanpa MixColumns)", state)

    else:
        state = add_round_key(state, round_keys[10])
        add_step(steps, "Initial Round: AddRoundKey (State XOR RK10)", state)

        for rnd in range(9, 0, -1):
            state = inv_shift_rows(state)
            add_step(steps, f"Ronde {10-rnd}: InvShiftRows", state)
            state = inv_sub_bytes(state)
            add_step(steps, f"Ronde {10-rnd}: InvSubBytes", state)
            state = add_round_key(state, round_keys[rnd])
            add_step(steps, f"Ronde {10-rnd}: AddRoundKey (RK{rnd})", state)
            state = inv_mix_columns(state)
            add_step(steps, f"Ronde {10-rnd}: InvMixColumns", state)

        state = inv_shift_rows(state)
        add_step(steps, "Ronde 10: InvShiftRows", state)
        state = inv_sub_bytes(state)
        add_step(steps, "Ronde 10: InvSubBytes", state)
        state = add_round_key(state, round_keys[0])
        add_step(steps, "Ronde 10: AddRoundKey (RK0, hasil akhir)", state)

    result_bytes = state_to_bytes(state)
    result_hex = ''.join(format(b, '02X') for b in result_bytes)
    steps.append({"title": "Hasil Akhir", "type": "keyvalue",
                  "content": [{"label": "Ciphertext" if mode == "encrypt" else "Plaintext", "value": result_hex}]})
    return result_hex
