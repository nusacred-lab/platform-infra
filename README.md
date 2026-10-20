# Platform Infra — Bukti Kompetensi

Repo infrastruktur dan kontrol rilis demo data sintetis nusacred-lab.
Target operasi: satu VM Linux x86_64 dengan Docker Compose, HTTPS, jaringan privat,
Keycloak/PostgreSQL, backend aplikasi, issuer/wallet/verifier dan SMTP privat.
Build/CI berjalan di luar VM; backup terenkripsi di luar VM, restore dan rollback
harus terbukti sebelum demo dibuka. Provider, region dan tujuan backup belum dipilih.

Status P1: fondasi repo dan CI. Belum ada konfigurasi produksi siap deploy.
Jangan memakai Compose harness Python sebagai deployment publik.
Simpan hanya template non-secret. Database, key, keystore, token, runtime dan backup
berada di penyimpanan privat. Tidak ada akses deploy/publish dari workflow PR.

Pemeriksaan lokal: `python3 ci/check_policy.py`. CI memindai seluruh riwayat Git
dan perubahan dependency. Lihat SECURITY-PROJECT.md untuk batas kontrol/review.
Kode proyek: Apache-2.0 (LICENSE).
