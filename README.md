🦀 **mass-scan**  
*Pemindai massal XSS · SQLi · Nuclei super-cepat berbasis Rust*

---

### 📋 Deskripsi  
**mass-scan** adalah CLI berkecepatan tinggi yang menjalankan **tiga mesin scanner sekaligus**:  
1. **XSS** via *dalfox*  
2. **SQL-injection** via *sqlmap*  
3. **Vulnerabilitas umum** via *nuclei*

Cukup sisipkan token **`FUZZ`** di URL → alat otomatis mengganti token dengan payload yang sesuai, lalu men-scan secara paralel.

---

### 🎯 Manfaat  
| Manfaat | Penjelasan |
|---------|------------|
| **hemat waktu** | satu perintah → tiga laporan sekaligus |
| **presisi tinggi** | POC diverifikasi langsung oleh *dalfox* & *sqlmap* |
| **skalabel** | bisa memproses ribuan URL sekaligus via file atau stdin |
| **aman & cepat** | ditulis dalam Rust + paralel Rayon |

---

### 🔧 Fitur Detail  
| Fitur | Detail Teknis |
|-------|---------------|
| **Rust + Rayon** | thread-pool otomatis, zero-cost abstraction, aman memori |
| **FUZZ Replace** | `FUZZ` → payload XSS (`<script>alert(1)</script>`) atau wildcard `*` (SQLi) |
| **Mode Selektif** | flag `-x`, `-s`, `-n` (bisa kombinasi) |
| **Input Fleksibel** | single URL (`-u`), file list, atau pipe stdin |
| **Output Terstruktur** | folder `hasil-scan/` berisi `.txt` & JSON yang siap dibaca tools lain |
| **Live CLI** | keluaran real-time dari *dalfox*, *sqlmap*, *nuclei* tetap ditampilkan |
| **Zero Config** | cukup punya 3 binary eksternal; tidak perlu edit file `.toml`/env |

---

### 🛠️ Cara Pasang (Kali / Ubuntu / Debian)  
1. **Instal scanner eksternal**
   ```bash
   # dalfox
   go install -v github.com/hahwul/dalfox/v2@latest
   sudo cp ~/go/bin/dalfox /usr/local/bin/

   # nuclei
   go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
   sudo cp ~/go/bin/nuclei /usr/local/bin/

   # sqlmap
   sudo apt update && sudo apt install sqlmap -y
   ```

2. **Clone & build mass-scan**
   ```bash
   git clone https://github.com/0xZer0r/mass-scan.git
   cd mass-scan
   cargo build --release
   sudo cp target/release/mass-scan /usr/local/bin/
   ```

3. **Verifikasi**
   ```bash
   mass-scan --version
   # mass-scan 0.1.0
   ```

---

### 🚀 Cara Pakai  
| Skenario | Perintah |
|----------|----------|
| **scan semua (stdin)** | `cat urls.txt | mass-scan` |
| **XSS only** | `mass-scan -x targets.txt` |
| **SQLi only** | `mass-scan -s -u 'https://site.com?p=FUZZ'` |
| **Nuclei only** | `mass-scan -n file.txt` |
| **kombinasi** | `mass-scan -x -n file.txt` |

*Semua hasil tersimpan di folder `hasil-scan/`.*

---

### 📊 Contoh Hasil  
**Perintah:**
```bash
echo 'https://buggy.site/search?q=FUZZ' | mass-scan
```

**Terminal (live):**
```
[+] XSS selesai → hasil-scan/hasil-xss.txt
[+] SQLi selesai → hasil-scan/hasil-sqli.txt
[+] Nuclei selesai → hasil-scan/hasil-nuclei.txt
[+] Selesai! Cek hasil-scan
```

**Isi folder:**
```
hasil-scan/
├── hasil-xss.txt          → POC XSS, curl, CVE
├── hasil-sqli.txt         → DBMS, DB name, user, password, tabel, CVE
├── hasil-nuclei.txt       → template-id, severity, CVE, description
└── *.json (raw)           → versi JSON untuk otomasi
```

**Cuplikan hasil-xss.txt:**
```
🔍 Finding #1
   URL      : https://demo.testfire.net/search?q=<script>alert(1)</script>
   Payload  : <script>alert(1)</script>
   Evidence : <script>alert(1)</script>
   Severity : high
   Extra    : {
     "dalfox_poc": "<script>alert(1)</script>",
     "curl_poc": "curl -X GET 'https://demo.testfire.net?q=%3Cscript%3E...'",
     "cve": []
   }
```

**Cuplikan hasil-sqli.txt:**
```
🔍 Finding #1
   URL      : https://demo.testfire.net/search?q=1' OR 1=1-- -
   Payload  : 1' OR 1=1-- -
   Evidence : MySQL error 1064: syntax
   Severity : high
   Extra    : {
     "dbms": "MySQL",
     "db_name": "acme_portal",
     "user": "acme_user@localhost",
     "password": "P@ssw0rd123",
     "tables": ["users", "orders", "admin"],
     "cve": ["CVE-2023-1234"]
   }
```

**Cuplikan hasil-nuclei.txt:**
```
🔍 Finding #1
   URL      : https://demo.testfire.net/search?q=test
   Payload  : apache-log4j-rce
   Evidence : log4j
   Severity : critical
   Extra    : {
     "template_id": "apache-log4j-rce",
     "name": "Apache Log4j RCE",
     "description": "Apache Log4j <= 2.14.1 RCE vulnerability",
     "cve": ["CVE-2021-44228"]
   }
```

---

### ⚠️ Catuan Penggunaan  
- Pastikan setiap URL mengandung **teks persis `FUZZ`** (case-sensitive).  
- Folder `target/` otomatis diabaikan (hasil build Rust).  
- Untuk push ke GitHub, gunakan **Personal Access Token** atau **SSH key** (password biasa tidak lagi diterima).  

---

### 🤝 Kontribusi  
Pull-requests & issues dipersilakan.  
Label `good-first-issue` tersedia untuk pemula Rust.

---

### 📜 Credit & License  
- **0xZer0r** – penulis kode Rust © 2025  
- **hahwul** – Dalfox  
- **projectdiscovery** – Nuclei  
- **sqlmap project** – SQLMap  

**License:** MIT © 2025 0xZer0r
