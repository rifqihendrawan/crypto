from flask import Flask, render_template, request, jsonify
import re

from crypto import sdes, des, aes, saes

app = Flask(__name__)

MODULES = {
    "des": {
        "name": "DES",
        "full_name": "Data Encryption Standard",
        "block_bits": 64,
        "key_bits": 64,
        "input_format": "hex",
        "endpoint": "/api/des",
        "example_text": "0123456789ABCDEF",
        "example_key": "133457799BBCDFF1",
        "desc": "Algoritma blok cipher 64-bit klasik dengan struktur Feistel 16 ronde.",
    },
    "sdes": {
        "name": "S-DES",
        "full_name": "Simplified Data Encryption Standard",
        "block_bits": 8,
        "key_bits": 10,
        "input_format": "bin",
        "endpoint": "/api/sdes",
        "example_text": "10111101",
        "example_key": "0000000010",
        "desc": "Versi sederhana DES untuk pembelajaran: 8-bit blok, 10-bit kunci, 2 ronde.",
    },
    "aes": {
        "name": "AES-128",
        "full_name": "Advanced Encryption Standard",
        "block_bits": 128,
        "key_bits": 128,
        "input_format": "hex",
        "endpoint": "/api/aes",
        "example_text": "00112233445566778899AABBCCDDEEFF",
        "example_key": "000102030405060708090A0B0C0D0E0F",
        "desc": "Standar enkripsi modern berbasis substitusi-permutasi, state 4x4 byte, 10 ronde.",
    },
    "saes": {
        "name": "S-AES",
        "full_name": "Simplified AES",
        "block_bits": 16,
        "key_bits": 16,
        "input_format": "hex",
        "endpoint": "/api/saes",
        "example_text": "6F6B",
        "example_key": "A73B",
        "desc": "Versi sederhana AES untuk pembelajaran: 16-bit blok, state 2x2 nibble, 2 ronde.",
    },
}


@app.route("/")
def index():
    return render_template("index.html", modules=MODULES)


@app.route("/module/<key>")
def module_page(key):
    if key not in MODULES:
        return "Modul tidak ditemukan", 404
    return render_template("module.html", mod=MODULES[key], mod_key=key)


def error_response(msg):
    return jsonify({"error": msg}), 400


def clean_bin(s, expected_len, field_name):
    s = re.sub(r"\s+", "", s or "")
    if not re.fullmatch(r"[01]+", s):
        raise ValueError(f"{field_name} harus berupa biner (hanya 0 dan 1).")
    if len(s) != expected_len:
        raise ValueError(f"{field_name} harus tepat {expected_len} bit (saat ini {len(s)} bit).")
    return s


def clean_hex(s, expected_bits, field_name):
    s = re.sub(r"\s+", "", s or "").upper()
    s = s.replace("0X", "")
    if not re.fullmatch(r"[0-9A-F]+", s):
        raise ValueError(f"{field_name} harus berupa heksadesimal.")
    expected_hexlen = expected_bits // 4
    if len(s) != expected_hexlen:
        raise ValueError(f"{field_name} harus tepat {expected_hexlen} digit hex ({expected_bits} bit).")
    return s


def hex_to_bin_str(h):
    return bin(int(h, 16))[2:].zfill(len(h) * 4)


@app.route("/api/sdes", methods=["POST"])
def api_sdes():
    data = request.get_json(force=True)
    mode = data.get("mode", "encrypt")
    try:
        text = clean_bin(data.get("text"), 8, "Plaintext/Ciphertext")
        key = clean_bin(data.get("key"), 10, "Key")
    except ValueError as e:
        return error_response(str(e))

    steps = []
    result, _ = sdes.run_sdes(text, key, mode, steps)
    return jsonify({"result": result, "result_format": "bin", "steps": steps})


@app.route("/api/des", methods=["POST"])
def api_des():
    data = request.get_json(force=True)
    mode = data.get("mode", "encrypt")
    try:
        text_hex = clean_hex(data.get("text"), 64, "Plaintext/Ciphertext")
        key_hex = clean_hex(data.get("key"), 64, "Key")
    except ValueError as e:
        return error_response(str(e))

    text_bin = hex_to_bin_str(text_hex)
    key_bin = hex_to_bin_str(key_hex)

    steps = []
    result_bin = des.run_des(text_bin, key_bin, mode, steps)
    result_hex = des.bin_to_hex(result_bin)
    return jsonify({"result": result_hex, "result_format": "hex", "steps": steps})


@app.route("/api/aes", methods=["POST"])
def api_aes():
    data = request.get_json(force=True)
    mode = data.get("mode", "encrypt")
    try:
        text_hex = clean_hex(data.get("text"), 128, "Plaintext/Ciphertext")
        key_hex = clean_hex(data.get("key"), 128, "Key")
    except ValueError as e:
        return error_response(str(e))

    steps = []
    result = aes.run_aes(text_hex, key_hex, mode, steps)
    return jsonify({"result": result, "result_format": "hex", "steps": steps})


@app.route("/api/saes", methods=["POST"])
def api_saes():
    data = request.get_json(force=True)
    mode = data.get("mode", "encrypt")
    try:
        text_hex = clean_hex(data.get("text"), 16, "Plaintext/Ciphertext")
        key_hex = clean_hex(data.get("key"), 16, "Key")
    except ValueError as e:
        return error_response(str(e))

    steps = []
    result = saes.run_saes(text_hex, key_hex, mode, steps)
    return jsonify({"result": result, "result_format": "hex", "steps": steps})


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
