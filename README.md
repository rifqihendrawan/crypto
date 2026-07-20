# Cipher Bench — Web Simulasi Algoritma Kriptografi Simetris
### (Versi siap deploy ke Vercel + domain .my.id)

Aplikasi web simulasi step-by-step untuk empat algoritma block cipher simetris:
**DES**, **S-DES**, **AES-128**, dan **S-AES**. Dibangun untuk UAS Mata Kuliah Kriptografi.

## Fitur

- Landing page dengan navigasi ke 4 modul algoritma.
- Setiap modul menampilkan:
  - Form input plaintext/ciphertext dan key sesuai panjang bit algoritma.
  - Pilihan mode Enkripsi / Dekripsi.
  - Tombol Submit, Reset, dan Isi Contoh.
  - Kotak hasil (bit/nibble/byte per kotak).
  - Bagian "Tampilkan Solusi Penyelesaian" yang merinci **seluruh tahapan** perhitungan:
    key generation, permutasi, substitusi S-Box, XOR, round function, dsb.
- Seluruh algoritma diimplementasikan dari nol (tanpa library kripto pihak ketiga) dan
  telah diverifikasi terhadap test vector standar:
  - DES: test vector Stallings (`key=133457799BBCDFF1`, `plaintext=0123456789ABCDEF` → `ciphertext=85E813540F0AB405`)
  - AES-128: test vector resmi FIPS-197
  - S-AES: test vector dari paper Musa/Schaefer/Wedig
  - S-DES: diverifikasi round-trip (encrypt → decrypt kembali ke plaintext semula)

## Struktur Proyek

```
cryptoapp-vercel/
├── app.py                  # Flask app: routing halaman + API endpoint tiap algoritma
├── vercel.json              # Konfigurasi deployment Vercel
├── .vercelignore
├── requirements.txt
├── crypto/
│   ├── sdes.py               # Simplified DES
│   ├── des.py                # DES (64-bit, 16 ronde Feistel)
│   ├── aes.py                 # AES-128
│   └── saes.py                # Simplified AES
├── templates/
│   ├── base.html              # Layout dasar (header, nav, footer)
│   ├── index.html             # Landing page
│   └── module.html            # Template generik untuk 4 modul (parameterized)
└── static/
    ├── css/style.css          # Desain (tema "Cipher Bench")
    └── js/main.js               # Rendering step generik + logic form
```

## 1. Menjalankan Secara Lokal (sebelum deploy)

**Mac/Linux:**
```bash
cd cryptoapp-vercel
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

**Windows (Git Bash):**
```bash
cd cryptoapp-vercel
python -m venv venv
source venv/Scripts/activate
pip install -r requirements.txt
python app.py
```

Buka `http://127.0.0.1:5000` di browser untuk memastikan semua modul berjalan normal
sebelum lanjut ke tahap deploy.

## 2. Push ke GitHub

```bash
git init
git add .
git commit -m "Cipher Bench - siap deploy ke Vercel"
git branch -M main
git remote add origin https://github.com/USERNAME/REPO.git
git push -u origin main
```

## 3. Deploy ke Vercel

Cara termudah: install Vercel CLI dan deploy langsung dari folder ini.

```bash
npm install -g vercel
vercel login
vercel --prod
```

Ikuti prompt yang muncul (pilih scope akun, konfirmasi nama project, dsb). Setelah selesai,
Vercel akan memberi URL seperti `https://nama-project.vercel.app` — coba buka untuk pastikan
semua modul (DES, S-DES, AES, S-AES) berjalan seperti versi lokal.

**Alternatif tanpa CLI:** buka https://vercel.com → New Project → Import dari repository
GitHub yang sudah di-push tadi → Deploy (Vercel otomatis mendeteksi `app.py` sebagai
entrypoint Flask, tidak perlu konfigurasi tambahan selain `vercel.json` yang sudah disertakan).

## 4. Menghubungkan Domain .my.id

1. Daftar domain gratis `.my.id` melalui penyedia domain gratis .my.id (mis. PANDI atau
   penyedia domain gratis yang bekerja sama dengan PANDI untuk pelajar/mahasiswa).
2. Di dashboard Vercel: buka project → **Settings → Domains** → masukkan domain
   `namamu.my.id` → Add.
3. Vercel akan menampilkan instruksi DNS (biasanya berupa **CNAME record** yang mengarah ke
   `cname.vercel-dns.com`, atau **A record** ke IP yang diberikan Vercel).
4. Masuk ke panel DNS penyedia domain `.my.id` kamu, tambahkan record sesuai instruksi
   tersebut.
5. Tunggu propagasi DNS (biasanya beberapa menit hingga beberapa jam), lalu domain
   `.my.id` akan otomatis mengarah ke aplikasi Cipher Bench di Vercel dengan HTTPS aktif.

## Catatan Teknis Deployment

- Aplikasi ini **stateless** (tidak ada database/penyimpanan), sehingga cocok untuk
  arsitektur serverless seperti Vercel — tidak ada isu terkait cold start kehilangan data.
- `vercel.json` menetapkan `maxDuration: 10` detik untuk function `app.py`, lebih dari cukup
  karena perhitungan kriptografi (bahkan 16 ronde DES atau 10 ronde AES) berjalan dalam
  hitungan milidetik.
- Baris `app.run(...)` di akhir `app.py` **tidak dipakai** saat berjalan di Vercel (Vercel
  langsung mengimpor objek `app`), baris tersebut hanya dipakai untuk menjalankan server
  lokal biasa.

## Cara Kerja Tiap Modul (Ringkas)

| Modul | Blok | Kunci | Format Input |
|-------|------|-------|--------------|
| DES   | 64-bit | 64-bit | Hex (16 digit) |
| S-DES | 8-bit  | 10-bit | Biner |
| AES-128 | 128-bit | 128-bit | Hex (32 digit) |
| S-AES | 16-bit | 16-bit | Hex (4 digit) |

Backend menghitung seluruh tahapan algoritma dan mengembalikan JSON berisi daftar `steps`
(setiap step punya `title`, `type`, dan `content`). Frontend (`main.js`) merender setiap
`step` secara generik ke dalam kartu — baik berupa deretan kotak bit, tabel S-Box, maupun
matriks state (untuk AES/S-AES) — sehingga tampilan konsisten di keempat modul.

## Catatan Akademik

Seluruh tabel algoritma (PC-1/PC-2, S-Box DES, S-Box AES/Rijndael, S-Box S-DES/S-AES, dsb.)
mengikuti spesifikasi standar publik (FIPS 46-3, FIPS 197, dan paper S-DES/S-AES Schaefer et al.),
sehingga hasil aplikasi dapat langsung dibandingkan dengan perhitungan manual pada laporan.
# cryptobench
# cryptobench
