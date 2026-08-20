# ChunkCrypt - Intermittent Encryption Demo

> Implementasi enkripsi intermittent, teknik yang sering ditemukan di malware sample untuk evasi deteksi static analysis.

## Deskripsi

**ChunkCrypt** adalah proof-of-concept yang mendemonstrasikan metode **intermittent encryption** (partial file encryption) menggunakan stream cipher **Salsa20**. Tool ini dirancang sebagai educational resource untuk malware analysis dan security research.

### Apa itu Intermittent Encryption?

Enkripsi intermittent adalah teknik enkripsi yang hanya mengenkripsi bagian tertentu dari file, bukan keseluruhan. Teknik ini:

- ✅ Mengurangi overhead enkripsi (lebih cepat)
- ✅ Menghindari perubahan magic bytes yang terdeteksi
- ✅ Membuat file tetap partially readable
- ✅ Meningkatkan evasion terhadap static analysis

Teknik ini banyak ditemukan di malware ransomware modern seperti **LockBit**, **Conti**, dan variantnya.

---

## Arsitektur

### Komponen Utama

```
Program.cs
├── EncryptProcess()      → Enkripsi intermittent + footer
├── DecryptProcess()      → Dekripsi + validasi marker
└── CalculateEntropy()    → Analisis entropy score

Algo.cs
├── Salsa20               → Stream cipher core
├── CustomRandom          → LCG deterministic RNG
├── AdvancedLogic
│   ├── GetDeterministicSeed()  → Reproducible seed
│   └── GetAdaptiveParams()     → File-type adaptive chunking
└── Key derivation (RFC2898)
```

---

## Algoritma Teknis

### 1. Salsa20 Stream Cipher

Implementasi native Salsa20 dengan:
- **Key size**: 256-bit (32 bytes)
- **IV size**: 8 bytes (nonce)
- **Block size**: 64 bytes
- **Rounds**: 20 (standar)

```csharp
// Setiap chunk dienkripsi dengan instance Salsa20 baru
using (Algo.Salsa20 salsa = new Algo.Salsa20()) {
    encrypted = salsa.Encrypt(buffer, key, iv);
}
```

### 2. Key Derivation

Menggunakan **RFC2898 (PBKDF2)** dengan:
- Algorithm: SHA256
- Iterations: 100
- Salt: 8 random bytes
- Output: 256-bit key

```csharp
var rfcdb = new Rfc2898DeriveBytes(password, salt, 100, HashAlgorithmName.SHA256);
byte[] key = rfcdb.GetBytes(32);
```

### 3. Deterministic Seeding

Seed untuk chunk jump dihitung dari:
- Derived key
- Original filename
- File size

```
seed = SHA256(Base64(key) + filename + filesize)
```

Ini memastikan jump pattern reproducible jika input sama.

### 4. Adaptive Chunking

Parameter chunk size dan jump distance di-adapt berdasarkan file type:

| File Type | Chunk Size | Min Jump | Max Jump | Use Case |
|-----------|-----------|----------|----------|----------|
| `.vmdk/.iso/.vhd` | 1MB | 10MB | 50MB | Virtual disk images |
| `.db/.sqlite/.mdf` | 4KB | 100KB | 1MB | Database files |
| `.txt/.log/.csv` | 512B | 2KB | 8KB | Text files |
| `.jpg/.png/.bmp` | 4KB | 32KB | 128KB | Image files |
| `.mp4/.avi/.mkv` | 256KB | 1MB | 5MB | Video files |
| `.pdf/.docx/.xlsx` | 8KB | 32KB | 128KB | Documents |

**Logika**:
- File kecil (<1MB): Full encryption
- File besar: Intermittent dengan adaptive gaps

---

## Entropy Analysis

Tool menghitung Shannon entropy dari file terenkripsi:

```
Entropy = -Σ(p_i * log2(p_i))
```

- **Plaintext entropy**: ~4.5-6.0 (bergantung format)
- **Target encrypted entropy**: 5.0-6.5 (random-like)
- **Full encryption entropy**: ~7.9 (maximum randomness)

Entropy score membantu verify bahwa output terenkripsi memiliki karakteristik random-like.

---

## Usage

### Prerequisites

```
.NET 8
```

### Kompilasi

```bash
dotnet publish -c Release -r YourOs-Arch64 *ex linux-arm64
```

### Enkripsi File

```bash
./ChunkCrypt enc <filename>
```

**Output**:

<img width="1080" height="422" alt="Screenshot_20260820-163408" src="https://github.com/user-attachments/assets/8a7ababe-4dbb-489d-b34d-a5487f51796c" />

File original diganti dengan `filename.LOCKED`

### Dekripsi File

```bash
./ChunkCrypt dec dummy_teks.txt.LOCKED
```

**Input prompt**:
```
[?] Input Key  : [paste KEY from encryption]
[?] Input Salt : [paste SALT from encryption]
```

File di-restore ke nama original.

<img width="1080" height="337" alt="Screenshot_20260820-163453" src="https://github.com/user-attachments/assets/2aec8533-5477-43ef-8e16-e9b51c73482a" />

---

## Technical Details

### Memory-Mapped File I/O

Untuk efisiensi memory pada file besar:

```csharp
using (var mmf = MemoryMappedFile.CreateFromFile(file, FileMode.Open)) {
    using (var accessor = mmf.CreateViewAccessor()) {
        accessor.ReadArray(pos, buffer, 0, bytesToRead);
        // ... process ...
        accessor.WriteArray(pos, encrypted, 0, encrypted.Length);
        accessor.Flush();
    }
}
```

### Footer Marker

Setiap file terenkripsi memiliki footer:
```
[encrypted_data][IV(8 bytes)][marker("[no-mode]")]
```

Marker untuk:
- Validasi bahwa file terenkripsi dengan ChunkCrypt
- Menyimpan IV untuk decryption

### Custom Linear Congruential Generator (LCG)

Untuk deterministic jump pattern:

```
seed' = (1103515245 * seed + 12345) mod 2^31
result = (seed' mod range) + min
```

---

## Coverage Statistics

Tool melaporkan:
- **Encrypted Chunks**: Jumlah chunk yang berhasil dienkripsi
- **Coverage %**: Persentase file yang terenkripsi (partial untuk intermittent)
- **Entropy Score**: Shannon entropy dari ciphertext

**Contoh output**:
```
Coverage: 34.56%  → Hanya 34.56% dari file yang dienkripsi
Entropy : 6.42    → Close to target (5.0-6.5)
```

---

## Educational Value

### Untuk Malware Analysis:

1. **Memahami Evasion**: Lihat bagaimana intermittent encryption menghindari full-file detection
2. **Reverse Engineering**: Study kode Salsa20 dan parameter derivation
3. **Behavioral Analysis**: Monitor jump patterns dan entropy changes
4. **Detection Evasion**: Contoh teknik yang dipakai oleh ransomware modern

### Untuk Security Research:

- Reference implementasi stream cipher
- Understanding deterministic cryptographic seeding
- File type adaptive encryption strategies
- Entropy analysis untuk ciphertext quality

---

## ⚠️ Disclaimer

**EDUCATIONAL USE ONLY**
Pengguna bertanggung jawab atas penggunaan kode ini. Unauthorized encryption atau usage pada sistem lain adalah illegal.

---

## 🎬 Demo Video

Video lengkap demonstrasi tool ini:

[![Watch Demo](https://img.shields.io/badge/Watch%20Demo-YouTube-red?style=for-the-badge&logo=youtube)](https://youtu.be/Gyy9IY70Zr0)

---

## Reference

### Cryptography Standards:
- [RFC 7539 - Salsa20 and Poly1305](https://tools.ietf.org/html/rfc7539)
- [RFC 2898 - PBKDF2](https://tools.ietf.org/html/rfc2898)
- [Shannon Entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory))

### Malware Reference:
- LockBit Ransomware Analysis
- Conti Ransomware Techniques
- Partial Encryption Strategies in Modern Malware

---

## License

Educational/Research Purpose Only

---

**Last Updated**: 2025  
**Language**: C# (.NET 8)  
**Architecture**: x64
