# PerfGuard

Alat diagnosa dan peredam CPU/RAM 100% untuk Windows. Portabel: PowerShell
murni, tanpa instalasi, tanpa dependensi, tanpa perubahan registry.

## Pakai di device lain

1. Salin **seluruh folder** `PerfGuard` ke device target (USB, network share, apa saja).
2. Dobel-klik **`Start.cmd`**.
3. Pilih menu. Mulai dari `1 Status`, lalu `2 Watch`.

Tidak perlu install apa pun. `Start.cmd` otomatis membersihkan Mark-of-the-Web
(penanda "file dari luar" yang bikin PowerShell menolak menjalankan skrip dari
USB), dan menjalankan skrip dengan `-ExecutionPolicy Bypass` sehingga kebijakan
eksekusi mesin target tidak perlu diubah.

Bisa juga dari command line:

```
PerfGuard.cmd optimize | ceiling | guard | status | watch | report | export | relieve | auto | restore | tune | profile | help
```

Opsi: `-CpuThreshold <n>` `-RamThreshold <n>` `-Seconds <n>` `-Ceiling <n>` `-Target <n>`
`-PurgeAt <n>` `-PurgeTo <n>` `-Purge` `-Aggressive` `-Apply` `-Gentle` `-DryRun`

### Alur yang disarankan untuk mendiagnosa PC orang lain

| Langkah | Perintah | Kenapa |
|---|---|---|
| 1 | `Status` | Lihat kondisi sesaat dan header kompatibilitas mesin |
| 2 | `Watch`, biarkan 1-2 jam saat PC dipakai normal | **Tidak mengubah apa pun.** Hanya mencatat siapa yang memuncak |
| 3 | `Report` | Baru di sini pelakunya kelihatan, bukan hasil tebakan |
| 4 | `Export` | Simpan laporan HTML + TXT untuk tiket atau atasan |
| 5 | `Guard` kalau keluhannya ngelag/freeze, `Relieve`/`Auto` kalau CPU penuh | Setelah tahu penyebabnya |
| 6 | `Tune` | Audit penyebab lag di level sistem |
| 7 | `Restore` sebelum menyerahkan PC kembali | Kembalikan semua ke normal |

## Satu tombol: mode Optimize

`PerfGuard.cmd optimize` menjalankan seluruh urutan tanpa perlu memilih apa-apa:

1. Profil ulang mesin
2. Audit sistem + terapkan perbaikan aman (power plan, efek visual)
3. Lepas memori dari proses dorman
4. **Cetak apa yang tidak bisa diperbaiki software** — sebelum plafon mulai jalan,
   supaya tidak ada yang membaca "plafon berjalan" sebagai "mesin sudah beres"
5. Jaga plafon CPU/RAM sampai ditutup dengan Ctrl+C

## Plafon 80% (mode Ceiling)

Menahan CPU dan RAM **maksimal 80%**, dengan target turun ke 75%.
Diatur lewat `CeilingCpu` / `CeilingRam` (80) dan `CeilingTargetLow` (75),
atau saat dijalankan dengan `-Ceiling <n>` dan `-Target <n>`.

Tangga eskalasinya ditambatkan ke target, bukan disebar 20 poin ke bawah.
Kalau tidak, dengan band sempit 75-80 level pertama akan aktif di 60% -- yang
di mesin yang memang idle di angka 70-an berarti menahan proses sepanjang waktu:

| Level | Ambang | Tindakan |
|---|---|---|
| L1 | ≥ 65% | EcoQoS + prioritas rendah, lepas memori proses dorman |
| L2 | ≥ 72% | Batasi proses rakus ke separuh core |
| L3 | ≥ 76% | Tangguhkan software tray |
| L4 | ≥ 79% | Tangguhkan proses background aplikasi berat (`-Gentle` mematikan level ini) |

Penangguhan di level N dilepas begitu tekanan turun ke N−2, jadi aplikasi
dikembalikan segera saat ada kelonggaran -- tidak menunggu sampai level 0 yang
di mesin sempit mungkin tak pernah tercapai.

**Semua dikembalikan otomatis** begitu tekanan reda selama 2 sampel berturut-turut,
dan saat mode ditutup.

### Pagar pengaman yang dipasang setelah pengujian

Tiga hal yang ditemukan saat menguji dan sekarang dijaga ketat:

- **Proses yang punya window terlihat tidak pernah ditangguhkan.** Versi pertama
  menangguhkan proses browser utama Chrome — seluruh window membeku, tak bisa
  dibedakan dari crash. Sekarang hanya proses tanpa window yang boleh ditangguhkan.
- **Sasaran mengikuti metrik yang tembus.** Kalau yang tembus CPU, yang ditindak
  pemakan CPU; kalau RAM, pemakan RAM. Sebelumnya selalu diurut berdasarkan RAM,
  jadi saat CPU yang bermasalah ia menangguhkan aplikasi yang tidak bersalah.
- **Proporsionalitas.** L4 hanya menyentuh proses yang benar-benar bagian dari
  masalah (≥10% CPU atau ≥150 MB). Menangguhkan proses 3,8% sementara ada yang
  memakai 25% adalah kerusakan tanpa manfaat.

### Kalau plafon tidak bisa ditahan

Mode ini **mengukur keberhasilannya sendiri** dan melapor apa adanya:

```
CPU di bawah 85% : 100% waktu   (tembus 0x, puncak 45%)
RAM di bawah 85% :  75% waktu   (tembus 1x, puncak 92%)
```

(Angka di atas ditangkap saat plafon default masih 85%. Dengan plafon 80%
sekarang, barisnya berbunyi `di bawah 80%`.)

Kalau pelaku CPU-nya ada di luar kendali, ia menyebut namanya:

```
TIDAK BISA DITAHAN: python pakai 15.8% CPU tapi tidak ada di EcoTargets.
```

**Batas yang tidak bisa dilewati:** RAM tidak bisa diturunkan seperti CPU.
CPU itu soal penjadwalan — bisa diatur. RAM itu soal kapasitas. Kalau aplikasi
yang sedang dipakai memang butuh 7 GB, tidak ada perintah yang membuatnya muat
di 8 GB. Yang bisa dilakukan hanya menangguhkan yang lain, dan itu ada batasnya.
Kalau laporan menunjukkan RAM tembus terus, jawabannya menutup tab atau menambah
RAM — dan mode ini akan mengatakannya, bukan pura-pura berhasil.

## Pembersihan RAM tingkat sistem (mode MemClear)

Setara menu **Empty** di RAMMap, lewat `NtSetSystemInformation`. **Butuh
administrator** — tanpa itu Windows menolak dengan `STATUS_PRIVILEGE_NOT_HELD`,
sama seperti RAMMap. Alat ini mengaktifkan privilege yang diperlukan sendiri
(`SeProfileSingleProcessPrivilege`, `SeIncreaseQuotaPrivilege`).

| Operasi | Yang terjadi | Termasuk set standar |
|---|---|---|
| Empty Working Sets | Lepas working set semua proses; halaman pindah ke standby | ya |
| Empty System Working Set | Kecilkan cache file sistem | ya |
| Empty Modified Page List | Tulis halaman kotor ke disk lalu pindahkan ke standby | ya |
| Empty Priority 0 Standby List | Buang cache prioritas terendah saja | ya |
| **Empty Standby List** | **Buang seluruh cache disk mesin** | **tidak** — pakai `-Purge` |

Terukur pada mesin uji (8 GB, sebagai administrator):

```
RAM bebas: 2180 -> 4774 MB  (+2594 MB)
```

### Kenapa Empty Standby List tidak masuk set standar

Standby list bukan memori terbuang — itu cache berisi data yang siap dipakai
tanpa menyentuh disk, dan Windows **sudah otomatis melepasnya** begitu aplikasi
butuh memori. Membuangnya membuat angka "free RAM" melonjak, tapi setiap
pembacaan berikutnya harus kembali ke disk. Di HDD efeknya terasa jelas.

Berguna kalau standby list memang macet (kejadian nyata setelah menyalin file
besar, atau stutter di game). Merugikan kalau dijalankan rutin. Karena itu
sifatnya opt-in lewat `-Purge`, dan ada cooldown pada mode otomatis.

### Pemicu otomatis

Mode `memclear` (menu 10) itu untuk pembersihan **manual, sekarang juga**. Tapi
pembersihan juga berjalan **otomatis** di setiap mode yang memang bertindak:

| Mode | Menu | Bersihkan RAM otomatis di 80% -> 75% |
|---|---|---|
| Optimize | 5 | ya |
| Ceiling | 6 | ya |
| Guard | 7 | ya |
| Relieve | 8 | ya (sekali jalan) |
| Auto | 9 | ya |
| Watch | 2 | **tidak** — Watch tidak pernah mengubah apa pun |

Ini bekerja sebagai **band, bukan sekali tembak**: menyala di `MemPurgeAtRam`
(default **80%**) lalu menyapu terus sampai RAM turun di bawah
`MemPurgeTargetLow` (default **75%**). Satu lintasan sering berhenti di 79% --
tepat di bawah pemicu, jadi tick berikutnya tidak melakukan apa-apa dan mesin
tetap mentok di plafon. Menyapu ke lantai yang lebih rendah memberi ruang napas
yang benar-benar terasa. Lintasan dibatasi 3x, dan lintasan yang tidak
menghasilkan apa-apa langsung menghentikan loop -- sisanya memang memori yang
sedang dipakai, dan tidak ada sapuan yang bisa melepas itu.

Jeda `MemPurgeCooldownSec` (default 120 detik) menjaga mesin yang memang hidup
di atas ambang tidak membuang cache setiap beberapa detik. Keduanya bisa diubah
saat dijalankan dengan `-PurgeAt <n>` dan `-PurgeTo <n>`.

Tanpa hak admin ia memberi tahu sekali lalu melewatinya — tidak diam-diam gagal:

```
RAM 92% >= 80%: pembersihan memori butuh administrator - dilewati.
Jalankan Start.cmd sebagai administrator agar ini otomatis.
```

Terukur di mode Auto sebagai administrator (ambang sengaja diturunkan ke 35%
supaya terpicu; ditangkap sebelum band ditambahkan, jadi barisnya belum
mencantumkan target dan jumlah lintasan):

```
RAM 50% >= 35% - membersihkan memori tingkat sistem...
RAM bebas +1804 MB (4005 -> 5809 MB)
...
Pembersihan memori: 1x, total RAM bebas bertambah 1804 MB
```

Band 80% -> 75% ini sengaja sama dengan plafon Ceiling: pembersihan penuh itu
mahal, jadi jeda `MemPurgeCooldownSec` yang menjaganya tetap sesekali, bukan
tindakan rutin.

## Lag dan freeze (mode Guard)

`relieve` dan `auto` bersifat **reaktif** — baru bertindak setelah CPU/RAM tembus
80%. Saat itu lag-nya sudah terlanjur terasa. `guard` bersifat **preventif**:

| Yang dilakukan | Kenapa itu yang bikin lag |
|---|---|
| **Prioritaskan aplikasi yang sedang dipakai** (`AboveNormal`) | Lag biasanya bukan "CPU penuh", tapi "aplikasi yang saya ketik kalah rebutan". Hanya menaikkan proses yang ada di `Normal` — yang sengaja diparkir rendah oleh aplikasinya sendiri (mis. tab background Chrome) tidak diganggu |
| **Tahan aplikasi background terus-menerus** | Bukan hanya saat spike |
| **Ambang lebih rendah** (`GuardCpuThreshold` / `GuardRamThreshold`, default 15 dan 10 poin di bawah ambang normal) | Bertindak sebelum Windows mulai mengompres memori, karena begitu itu terjadi freeze-nya sudah berjalan |
| **Deteksi freeze** | Mencatat window yang berhenti merespons |

Semua boost dilepas saat mode ditutup, termasuk lewat Ctrl+C.

### Deteksi freeze

Freeze bukan angka CPU — itu window yang berhenti memompa message loop.
PerfGuard menanyai proses yang punya window (`Responding`), dan mencatat setiap
kejadian ke `logs\hangs.csv` **lengkap dengan CPU, RAM, dan disk pada detik itu**.

Konteks itu yang menentukan diagnosanya: kalau freeze terjadi saat free RAM di
bawah 500 MB, laporan akan menyebut itu akibat memori habis, bukan bug aplikasi.

Pemeriksaan dilakukan tiap tick ke-3, karena `Responding` memblokir sampai 5
detik per window — memeriksanya tiap tick justru akan menyebabkan stutter sendiri.

Batasnya: hanya window utama yang diperiksa. Aplikasi yang window utamanya sehat
tapi dialog anaknya membeku tidak terdeteksi.

## Audit sistem (mode Tune)

Memeriksa penyebab lag yang tidak kelihatan dari daftar proses:

power plan, jenis disk (HDD/SSD), ruang kosong, page file, jumlah aplikasi
startup, efek visual, SysMain, Windows Search indexer, restart tertunda, dan
kapasitas RAM.

**Report-only secara default.** `-Apply` hanya menyentuh dua hal yang
sepenuhnya reversibel — power plan dan efek visual — dan mencatat nilai lamanya
ke `logs	une-undo.txt`. Sisanya sengaja tidak diotomatiskan: mematikan service
atau item startup di PC orang lain terlalu berisiko, jadi PerfGuard memberi
langkah persisnya dan membiarkan kamu yang memutuskan.

Yang juga sengaja tidak dilakukan: **tidak menyarankan mematikan SysMain**.
Itu saran internet yang populer tapi di HDD justru merugikan. PerfGuard hanya
menyarankannya kalau mode Watch benar-benar membuktikan SysMain pelakunya.

## Laporan (mode Export)

Menulis dua file ke `logs\`, dinamai `PerfGuard-<NAMAPC>-<tanggal>.html` / `.txt`:

- **HTML** — sepenuhnya mandiri: CSS inline, grafik SVG inline, nol referensi
  eksternal. Bisa dibuka di PC tanpa internet, dan tinggal Ctrl+P untuk jadi PDF.
- **TXT** — UTF-8 tanpa BOM, siap ditempel langsung ke tiket.

Isinya: spesifikasi mesin, kesimpulan otomatis, temuan bertingkat
(KRITIS / PERHATIAN / INFO), rekomendasi, grafik CPU-RAM sepanjang pemantauan,
tabel pemakai memori, dan tabel pelaku spike.

### Kesimpulan otomatis

Ini bagian yang paling berguna: memisahkan tiga penyakit yang bagi user terlihat
sama persis — "PC-nya 100% terus".

| Kesimpulan | Dasarnya | Artinya |
|---|---|---|
| **Kehabisan RAM** | Free RAM < 500 MB, `Memory Compression` jadi pemakan CPU teratas, atau paging > 1000/detik | Bukan masalah aplikasi. Windows sibuk mengompres dan menukar halaman memori |
| **Bottleneck disk** | Disk > 80% sibuk pada mayoritas spike | CPU cuma menunggu I/O. Curigai HDD tua, disk penuh, atau scan AV |
| **Didominasi satu aplikasi** | Satu app jadi nomor satu pada >40% spike | Beban terkonsentrasi, tangani app itu dulu |
| **Beban tersebar** | CPU menembus plafon (80%) tapi tanpa pelaku dominan | Terlalu banyak aplikasi background untuk kapasitas CPU-nya |

Tanpa metrik disk dan paging, laporan hanya bisa menyalahkan aplikasi — padahal
sering kali aplikasi bukan penyebabnya.

## Angka CPU-nya cocok dengan Task Manager

Task Manager sejak Windows 8 **tidak** menampilkan `% Processor Time` (persentase
waktu CPU tidak idle). Yang ditampilkannya adalah **`% Processor Utility`**, yang
menormalkan terhadap clock dasar: CPU yang sibuk penuh tapi berjalan di bawah
base clock tidak dihitung 100%.

Versi awal alat ini memakai `% Processor Time`, sehingga angkanya konsisten lebih
tinggi dari Task Manager — kadang dua sampai tiga kali lipat:

| `% Processor Time` (lama) | `% Processor Utility` (Task Manager) |
|---|---|
| 17% | 10% |
| 15% | 5% |
| 9% | 7% |

Sekarang PerfGuard membaca `PercentProcessorUtility` dari
`Win32_PerfFormattedData_Counters_ProcessorInformation`, sumber yang sama dengan
Task Manager. Angka per-proses ikut diskalakan dengan faktor yang sama, supaya
bagian-bagiannya tetap konsisten dengan totalnya.

Hasil pengukuran berdampingan, 8 sampel:

```
rata-rata PerfGuard   : 11,1%
rata-rata Task Manager: 11,1%
rata-rata selisih mutlak: 3,5 poin
```

Sisa selisihnya adalah jitter waktu — kedua angka tidak dibaca pada instan yang
sama persis, dan counter WMI diperbarui sekitar sekali per detik. Bias
sistematisnya sudah hilang.

Kalau mesin target terlalu lama untuk punya counter ini (pra-Windows 8),
PerfGuard otomatis mundur ke `% Processor Time` seperti sebelumnya.

## Adaptasi otomatis ke mesin target

Saat pertama jalan, PerfGuard memindai mesin dan menulis `config.json` sendiri.
Tidak ada daftar aplikasi hardcoded dari mesin lain.

- **Aplikasi**: hanya proses yang benar-benar berjalan di mesin itu yang masuk
  daftar target. Yang tidak dikenali dibiarkan — *tidak dikenal berarti tidak disentuh*.
- **Ambang batas**: diskalakan ke hardware. 2 core → CPU 75%. RAM ≤4 GB → 73%,
  ≤8 GB → 77%. Laptop 2-core/8GB kesulitan jauh lebih cepat daripada desktop 8-core/32GB.
- **Kemampuan OS**: dideteksi, bukan diasumsikan.

Jalankan `Profile` lagi setelah menginstal atau menghapus aplikasi di mesin itu.

## Kompatibilitas OS

Header di setiap mode menyebutkan apa yang bisa dilakukan mesin itu:

| Kondisi | Yang dipakai |
|---|---|
| Windows 10 build 19041+ | `EcoQoS + priority` — jalur penuh |
| Windows lebih lama, ≥4 core | `priority + affinity` — proses rakus dipin ke separuh core |
| Windows lebih lama, 2 core | `priority only` — affinity dilewati, membelah 2 core akan melumpuhkan aplikasi |
| Windows 7 / Server 2008 R2 | Scheduled task otomatis pakai `schtasks.exe` |

EcoQoS tidak dipercaya dari nomor build saja — API-nya benar-benar dipanggil ke
proses sendiri sebagai probe, lalu dibatalkan. Image OEM dan SKU Server tidak
selalu berperilaku sesuai build.

Minimum: **PowerShell 3.0**. Windows 7 tanpa update PowerShell (bawaan 2.0)
tidak didukung.

**Tanpa hak admin** tetap jalan, tapi proses milik user lain atau aplikasi
elevated tidak bisa disentuh. Header akan memberi tahu.

## Yang benar-benar dilakukan

| Aksi | Mekanisme | Reversibel |
|---|---|---|
| Throttle CPU | `SetProcessInformation` + EcoQoS, sama dengan "Efficiency mode" di Task Manager, plus priority `BelowNormal` | Ya |
| Fallback throttle | `ProcessorAffinity` ke separuh core, kalau EcoQoS tidak ada | Ya |
| Redakan RAM | `EmptyWorkingSet`, **hanya** pada proses yang benar-benar dorman | Tidak perlu |
| Suspend | `NtSuspendProcess`, hanya app di `SuspendTargets`, hanya dengan `-Aggressive` | Ya, otomatis saat app difokuskan lagi |
| Anti-lag | Prioritas `AboveNormal` untuk aplikasi yang sedang difokuskan | Ya, dilepas saat pindah fokus atau keluar |

Tidak pernah mematikan proses. Tidak pernah menyentuh aplikasi yang sedang
difokuskan user.

## Yang sengaja dilindungi

Selain proses sistem dan antivirus, **helper driver tidak pernah disentuh sama
sekali**: touchpad (`SynTPEnh`, `ETDCtrl`), audio (`SmartAudio3`,
`RtkAudUService64`, `Nahimic`), grafis (`igfxCUIService`, `nvcontainer`).

Menangguhkan `SynTPEnh` mematikan scroll dan gesture touchpad. Di PC orang lain
itu tidak bisa diterima, dan proses-proses ini pemakaian CPU-nya nyaris nol —
tidak ada yang bisa dimenangkan di sana. Mode `Profile` menampilkannya di baris
`protected` supaya kelihatan apa yang dilewati.

VPN dan agen keamanan juga tidak masuk daftar target.

## Yang TIDAK dilakukan, dan kenapa

**Tidak melakukan "RAM cleaning" massal.** Trik RAM booster abal-abal adalah
memanggil `EmptyWorkingSet` ke semua proses. Angka "free RAM" langsung cantik,
tapi halaman memori cuma dibuang ke standby list, lalu aplikasi menariknya balik
dari disk beberapa detik kemudian.

Terukur saat pengembangan alat ini:

```
Klaim working set dilepas            : 2802 MB
RAM bebas yang benar-benar bertambah :  253 MB
CPU                                  : 6% -> 40%
```

Karena itu browser dan editor **dikeluarkan** dari `TrimTargets`, dan PerfGuard
hanya melaporkan selisih *available memory* yang nyata.

## config.json

Dibuat otomatis. Aman diedit; jalankan `Profile` untuk membuat ulang.

| Kunci | Arti |
|---|---|
| `CpuThreshold` / `RamThreshold` | Ambang persen yang dianggap spike |
| `SampleSeconds` | Jeda antar sampel di mode watch/auto |
| `EcoMinCpu` | CPU% minimum sebelum proses layak di-throttle |
| `IdleCpuPercent` | Di bawah ini proses dianggap dorman dan boleh di-trim |
| `NeverTouch` | Jangan pernah disentuh |
| `EcoTargets` | Boleh di-throttle saat CPU tinggi |
| `TrimTargets` | Boleh di-trim saat dorman. Jangan masukkan aplikasi aktif |
| `SuspendTargets` | Boleh di-suspend, hanya dengan `-Aggressive` |
| `GuardCpuThreshold` / `GuardRamThreshold` | Ambang preventif mode Guard |
| `BoostForeground` | Naikkan prioritas aplikasi yang sedang dipakai |
| `CeilingCpu` / `CeilingRam` | Plafon keras mode Ceiling (80) |
| `CeilingTargetLow` | Target yang dituju setelah bertindak (75) |
| `MemPurgeAtRam` | RAM% pemicu pembersihan otomatis (80) |
| `MemPurgeTargetLow` | RAM% target sapuan pembersihan (75) |
| `MemPurgeCooldownSec` | Jeda minimum antar pembersihan (120) |
| `MemPurgeOps` | Operasi yang dijalankan otomatis |
| `CeilingAggressive` | Izinkan eskalasi L4 (`-Gentle` mematikannya) |

## Kalau ada yang nyangkut

```
PerfGuard.cmd restore -Aggressive
```

Menyapu semua `EcoTargets` yang tertinggal di `BelowNormal` kembali ke `Normal`.
Proses di priority `Idle` sengaja dilewati — itu Chrome mengatur tab
background-nya sendiri.

Suspend juga otomatis dibatalkan saat PerfGuard ditutup (termasuk Ctrl+C).

## Batas jujur

PerfGuard mengatur ulang prioritas dan penjadwalan. Ia tidak bisa menciptakan
memori yang tidak ada.

Kalau `report` menunjukkan proses `Memory Compression` milik Windows sendiri
sebagai pemakan CPU teratas, atau memberi peringatan merah soal free RAM di
bawah 500 MB, artinya CPU 100% itu disebabkan **kehabisan RAM**, bukan oleh
aplikasi manapun. Pada kondisi itu satu-satunya solusi nyata adalah menutup tab
atau menambah RAM.
#   P e r f G u a r d  
 