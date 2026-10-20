# Kontrol P1

Tanggal: 20 Oktober 2026. Repo publik nusacred-lab, lisensi Apache-2.0.
Default branch `main` mewajibkan PR serta checks `security` dan `dependency-review`
dari GitHub Actions app 15368. Branch harus mutakhir, force push/deletion dilarang,
aturan berlaku untuk admin, dan percakapan review harus diselesaikan.

Actions memakai SHA penuh, runner sementara dan token default read-only; workflow
tidak boleh menyetujui PR. Hanya action milik GitHub yang diizinkan. Secret scanning,
push protection, vulnerability alerts dan private vulnerability reporting aktif.
Fitur non-provider pattern tidak aktif menurut pembacaan balik; Gitleaks menambah
pemindaian pola umum pada seluruh riwayat Git. Dependency review PR bukan pengganti
SCA hasil resolusi serta scan image.

Hanya ada satu maintainer (`abeinoe`). PR dan CI diwajibkan, tetapi jumlah approval
manusia disetel nol; CODEOWNERS tidak diklaim sebagai review dua orang atau kontrol
review independen yang sudah berlaku. Commit fondasi pertama dipush sebelum proteksi
untuk menyediakan workflow awal; perubahan selanjutnya mengikuti PR.

Bukti uji negatif: https://github.com/nusacred-lab/bukti-kompetensi/pull/1
File penanda tidak berbahaya membuat check security gagal; percobaan merge admin
benar-benar ditolak dengan pesan `Required status check "security" is failing.`
PR uji kemudian ditutup tanpa merge. Tidak ada CVE atau secret sengaja dipublikasikan.

G1 proyek belum lulus. Build fork, penguncian/verifikasi dependency serta scan
baseline dan image target dilacak di repo waltid-identity; fondasi repo ini tidak
menyatakan aplikasi atau deployment telah tersedia.
