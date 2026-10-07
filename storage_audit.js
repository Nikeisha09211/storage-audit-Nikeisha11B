#!/usr/bin/env node

/**
 * ============================================================================
 * STORAGE AUDIT UTILITY (storage_audit.js)
 * Modul Praktikum P12: Audit & Pembersihan Penyimpanan
 * ============================================================================
 * Kebutuhan Sistem:
 * - STG-01: Recursive Scan (Node.js fs, path, crypto)
 * - STG-02: Duplicate Detection (SHA-256 matching)
 * - STG-03: Giant File Flagging (>= 2 MB / 2.048 KB)
 * - STG-04: Structured Terminal Report
 * - STG-05: Safe Cleanup Confirmation (Y/N prompt, retain 1 original)
 * - STG-06: Zero-Dependency Portability (fs, path, crypto, readline)
 * ============================================================================
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

// Konfigurasi Ambang Batas (Threshold)
const GIANT_FILE_THRESHOLD_BYTES = 2 * 1024 * 1024; // 2 MB = 2.048 KB = 2.097.152 Bytes

// File yang tidak boleh dihapus atau dipindai oleh utilitas
const PROTECTED_FILENAMES = new Set([
  'storage_audit.js',
  'storage_audit.py',
  'rename_batch_p11.js'
]);

/**
 * Format ukuran byte menjadi representasi manusia (Bytes, KB, MB)
 */
function formatSize(bytes) {
  if (bytes < 1024) {
    return `${bytes} B`;
  } else if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(2)} KB`;
  } else {
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }
}

/**
 * Format angka dengan pemisah ribuan
 */
function formatNumber(num) {
  return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

/**
 * Hitung hash SHA-256 dari sebuah file secara efisien menggunakan stream
 */
function calculateSha256(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', err => reject(err));
  });
}

/**
 * Heuristik skor untuk menentukan file mana yang merupakan "File Asli"
 * File dengan penamaan paling bersih / tanpa kata "copy", "salinan", "(1)", dll
 * mendapatkan skor penalti paling rendah (prioritas utama untuk dipertahankan).
 */
function getOriginalScore(fileName) {
  const lower = fileName.toLowerCase();
  let penalty = 0;

  if (/\s*-\s*copy/i.test(lower)) penalty += 100;
  if (/_copy/i.test(lower)) penalty += 100;
  if (/\s*-\s*salinan/i.test(lower)) penalty += 100;
  if (/_salinan/i.test(lower)) penalty += 100;
  if (/\s*\(\d+\)/.test(lower)) penalty += 100;
  if (/_backup/i.test(lower)) penalty += 100;
  if (/_final/i.test(lower)) penalty += 50;
  if (/_fix/i.test(lower)) penalty += 50;
  if (/_edit\d*/i.test(lower)) penalty += 50;
  if (/_v\d+/i.test(lower)) penalty += 50;

  penalty += lower.length;
  return penalty;
}

/**
 * STG-01: Memindai direktori secara rekursif
 */
async function scanDirectory(dirPath, rootDir, collectedFiles = []) {
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);
    const relPath = path.relative(rootDir, fullPath);

    // Abaikan folder kontrol versi & dependensi
    if (entry.isDirectory()) {
      if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === '.agents') {
        continue;
      }
      await scanDirectory(fullPath, rootDir, collectedFiles);
    } else if (entry.isFile()) {
      // Abaikan skrip audit itu sendiri
      if (PROTECTED_FILENAMES.has(entry.name.toLowerCase())) {
        continue;
      }

      try {
        const stats = fs.statSync(fullPath);
        const hash = await calculateSha256(fullPath);
        const isTmp = entry.name.toLowerCase().endsWith('.tmp') || entry.name.toLowerCase().endsWith('.temp');

        collectedFiles.push({
          name: entry.name,
          relativePath: relPath,
          absolutePath: fullPath,
          size: stats.size,
          mtime: stats.mtime,
          hash: hash,
          isTmp: isTmp
        });
      } catch (err) {
        console.error(`[PERINGATAN] Gagal memproses file "${relPath}": ${err.message}`);
      }
    }
  }

  return collectedFiles;
}

/**
 * Prompt interaktif konfirmasi pengguna (readline)
 */
function promptUser(question) {
  return new Promise(resolve => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    rl.question(question, answer => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

/**
 * Fungsi Utama
 */
async function main() {
  const args = process.argv.slice(2);
  let autoYes = false;
  let targetArg = null;

  for (const arg of args) {
    if (arg === '-y' || arg === '--yes') {
      autoYes = true;
    } else if (!targetArg && !arg.startsWith('-')) {
      targetArg = arg;
    }
  }

  // Resolusi Direktori Target
  let targetDir = process.cwd();

  if (targetArg) {
    const resolved = path.resolve(process.cwd(), targetArg);
    if (fs.existsSync(resolved) && fs.statSync(resolved).isDirectory()) {
      targetDir = resolved;
    } else {
      const candidateInside = path.resolve(process.cwd(), 'Bahan Latihan P12');
      if (fs.existsSync(candidateInside) && fs.statSync(candidateInside).isDirectory()) {
        targetDir = candidateInside;
      } else {
        const baseName = path.basename(process.cwd());
        if (targetArg.toLowerCase().includes('bahan latihan p12') || targetArg.toLowerCase().includes('p12')) {
          console.log(`[INFO] Folder "${targetArg}" tidak ditemukan sebagai subdirektori terpisah.`);
          console.log(`[INFO] Menggunakan direktori aktif saat ini ("${baseName}") sebagai target pemindaian.`);
          targetDir = process.cwd();
        } else {
          console.error(`[ERROR] Direktori target tidak ditemukan: ${targetArg}`);
          process.exit(1);
        }
      }
    }
  } else {
    // Cek jika subfolder "Bahan Latihan P12" ada
    const candidateInside = path.resolve(process.cwd(), 'Bahan Latihan P12');
    if (fs.existsSync(candidateInside) && fs.statSync(candidateInside).isDirectory()) {
      targetDir = candidateInside;
    }
  }

  console.log('\n' + '='.repeat(80));
  console.log('       STORAGE AUDIT CLI UTILITY - SISTEM AUDIT & OPTIMASI PENYIMPANAN');
  console.log('='.repeat(80));
  console.log(`Target Direktori : ${targetDir}`);
  console.log(`Waktu Mulai      : ${new Date().toLocaleString('id-ID')}`);
  console.log(`Status           : Memindai file dan menghitung hash SHA-256...`);

  // STG-01: Recursive Scan
  const startTime = Date.now();
  const allFiles = await scanDirectory(targetDir, targetDir);
  const scanDuration = ((Date.now() - startTime) / 1000).toFixed(2);

  if (allFiles.length === 0) {
    console.log('\n[INFO] Tidak ditemukan file untuk diaudit di direktori ini.');
    return;
  }

  let totalSize = 0;
  const giantFiles = [];
  const hashMap = new Map();
  const tmpFiles = [];

  for (const file of allFiles) {
    totalSize += file.size;

    // STG-03: Giant File Flagging (>= 2 MB)
    if (file.size >= GIANT_FILE_THRESHOLD_BYTES) {
      giantFiles.push(file);
    }

    // STG-02: Kelompokkan berdasarkan Hash SHA-256
    if (!hashMap.has(file.hash)) {
      hashMap.set(file.hash, []);
    }
    hashMap.get(file.hash).push(file);

    // Kumpulkan file sampah sementara .tmp
    if (file.isTmp) {
      tmpFiles.push(file);
    }
  }

  // Filter kelompok duplikat (file dengan hash sama >= 2)
  const duplicateGroups = [];
  let totalPotentialSavings = 0;
  const duplicateFilesToDelete = [];

  for (const [hash, group] of hashMap.entries()) {
    if (group.length > 1) {
      // Urutkan grup: file dengan nama paling bersih / asli berada di indeks 0
      group.sort((a, b) => getOriginalScore(a.name) - getOriginalScore(b.name));

      const originalFile = group[0];
      const duplicateCopies = group.slice(1);

      const groupSavings = duplicateCopies.reduce((acc, curr) => acc + curr.size, 0);
      totalPotentialSavings += groupSavings;

      duplicateGroups.push({
        hash: hash,
        original: originalFile,
        duplicates: duplicateCopies,
        sizePerFile: originalFile.size,
        groupSavings: groupSavings
      });

      for (const dup of duplicateCopies) {
        duplicateFilesToDelete.push(dup);
      }
    }
  }

  // Urutkan file raksasa dari yang terbesar
  giantFiles.sort((a, b) => b.size - a.size);

  // STG-04: Terminal Report
  console.log('\n' + '-'.repeat(80));
  console.log(' [1] RINGKASAN AUDIT PENYIMPANAN (SUMMARY)');
  console.log('-'.repeat(80));
  console.log(` - Total File Dipindai      : ${allFiles.length} file (dalam ${scanDuration} detik)`);
  console.log(` - Total Ukuran Direktori   : ${formatNumber(totalSize)} Byte (${formatSize(totalSize)})`);
  console.log(` - File Raksasa (>= 2 MB)   : ${giantFiles.length} file`);
  console.log(` - Kelompok File Duplikat   : ${duplicateGroups.length} kelompok (${duplicateFilesToDelete.length} salinan duplikat)`);
  console.log(` - File Sampah (.tmp)       : ${tmpFiles.length} file`);
  console.log(` - Estimasi Hemat Ruang     : ${formatNumber(totalPotentialSavings)} Byte (${formatSize(totalPotentialSavings)})`);
  const savingsPct = totalSize > 0 ? ((totalPotentialSavings / totalSize) * 100).toFixed(2) : '0';
  console.log(` - Rasio Efisiensi Ruang    : ${savingsPct}% kapasitas dapat dipulihkan`);

  // Bagian File Raksasa (STG-03)
  console.log('\n' + '-'.repeat(80));
  console.log(` [2] DAFTAR FILE RAKSASA (GIANT FILES >= 2 MB / 2.048 KB) [STG-03]`);
  console.log('-'.repeat(80));
  if (giantFiles.length === 0) {
    console.log(' (Tidak ada file raksasa yang melebihi batas 2 MB)');
  } else {
    console.log('No.  Ukuran (MB)    Ukuran (KB)       Ukuran (Byte)     Nama File');
    console.log('-'.repeat(80));
    giantFiles.forEach((file, idx) => {
      const mbStr = (file.size / (1024 * 1024)).toFixed(2) + ' MB';
      const kbStr = formatNumber((file.size / 1024).toFixed(0)) + ' KB';
      const bStr = formatNumber(file.size) + ' B';
      const num = String(idx + 1).padStart(2, ' ') + '.';
      console.log(`${num}  ${mbStr.padEnd(14)} ${kbStr.padEnd(17)} ${bStr.padEnd(17)} ${file.relativePath}`);
    });
    console.log(`\n Total File Raksasa Ditemukan: ${giantFiles.length} file`);
  }

  // Bagian Kelompok Duplikat (STG-02)
  console.log('\n' + '-'.repeat(80));
  console.log(` [3] DAFTAR KELOMPOK DUPLIKAT (IDENTICAL SHA-256 HASH) [STG-02]`);
  console.log('-'.repeat(80));
  if (duplicateGroups.length === 0) {
    console.log(' (Tidak ditemukan file duplikat)');
  } else {
    duplicateGroups.forEach((group, idx) => {
      const shortHash = group.hash.substring(0, 16) + '...';
      console.log(`\nKelompok #${idx + 1} [Hash: ${shortHash}]`);
      console.log(`  Ukuran per file : ${formatSize(group.sizePerFile)} (${formatNumber(group.sizePerFile)} Byte)`);
      console.log(`  Potensi Hemat   : ${formatSize(group.groupSavings)}`);
      console.log(`  [ASLI / SIMPAN] : ${group.original.relativePath}`);
      group.duplicates.forEach(dup => {
        console.log(`  [SALINAN/HAPUS] : ${dup.relativePath}`);
      });
    });
    console.log(`\n Total Kelompok Duplikat : ${duplicateGroups.length} kelompok`);
    console.log(` Total Salinan Duplikat  : ${duplicateFilesToDelete.length} file`);
  }

  // File Sementara .tmp jika ada
  if (tmpFiles.length > 0) {
    console.log('\n' + '-'.repeat(80));
    console.log(` [4] DAFTAR FILE SAMPAH SEMENTARA (.tmp)`);
    console.log('-'.repeat(80));
    tmpFiles.forEach((f, idx) => {
      console.log(`  ${idx + 1}. ${f.relativePath} (${formatSize(f.size)})`);
    });
  }

  // STG-05: Safe Cleanup Confirmation
  console.log('\n' + '='.repeat(80));
  console.log(' [5] KONFIRMASI PEMBERSIHAN AMAN (SAFE CLEANUP CONFIRMATION) [STG-05]');
  console.log('='.repeat(80));

  const totalFilesToRemove = duplicateFilesToDelete.length + tmpFiles.length;

  if (totalFilesToRemove === 0) {
    console.log('[INFO] Tidak ada file duplikat atau file sampah .tmp yang perlu dibersihkan.');
    console.log('Status: Penyimpanan sudah optimal.');
    console.log('='.repeat(80) + '\n');
    return;
  }

  console.log(`Perhatian: Tindakan ini akan:`);
  console.log(` - Mempertahankan 1 file asli per kelompok duplikat (${duplicateGroups.length} file asli aman).`);
  console.log(` - Menghapus ${duplicateFilesToDelete.length} salinan duplikat yang berlebih.`);
  if (tmpFiles.length > 0) {
    console.log(` - Menghapus ${tmpFiles.length} file sampah sementara (.tmp).`);
  }
  console.log(` - Membebaskan estimasi ruang sebesar ${formatSize(totalPotentialSavings)}.`);

  let confirmed = false;
  if (autoYes) {
    console.log('\n[INFO] Flag -y / --yes terdeteksi. Melanjutkan pembersihan otomatis...');
    confirmed = true;
  } else {
    console.log('');
    const answer = await promptUser('Apakah kamu ingin menghapus file duplikat yang tidak terpakai? (Y/N): ');
    confirmed = answer.toUpperCase() === 'Y' || answer.toUpperCase() === 'YES';
  }

  if (!confirmed) {
    console.log('\n[BATAL] Pembersihan dibatalkan oleh pengguna (N).');
    console.log('Keamanan terjamin: Tidak ada file yang dihapus atau diubah.');
    console.log('='.repeat(80) + '\n');
    return;
  }

  // Eksekusi Pembersihan
  console.log('\n' + '-'.repeat(80));
  console.log(' MENGEKSEKUSI PEMBERSIHAN AMAN...');
  console.log('-'.repeat(80));

  let deletedCount = 0;
  let freedBytes = 0;

  // Hapus salinan duplikat
  for (const dup of duplicateFilesToDelete) {
    try {
      if (fs.existsSync(dup.absolutePath)) {
        fs.unlinkSync(dup.absolutePath);
        deletedCount++;
        freedBytes += dup.size;
        console.log(` [DIHAPUS] Salinan: ${dup.relativePath} (${formatSize(dup.size)})`);
      }
    } catch (err) {
      console.error(` [GAGAL] Tidak dapat menghapus ${dup.relativePath}: ${err.message}`);
    }
  }

  // Hapus file sampah .tmp (jika belum terhapus)
  for (const tmp of tmpFiles) {
    try {
      if (fs.existsSync(tmp.absolutePath)) {
        fs.unlinkSync(tmp.absolutePath);
        deletedCount++;
        freedBytes += tmp.size;
        console.log(` [DIHAPUS] Sampah:  ${tmp.relativePath} (${formatSize(tmp.size)})`);
      }
    } catch (err) {
      console.error(` [GAGAL] Tidak dapat menghapus ${tmp.relativePath}: ${err.message}`);
    }
  }

  console.log('\n' + '='.repeat(80));
  console.log(' PEMBERSIHAN SELESAI DENGAN SUKSES!');
  console.log('='.repeat(80));
  console.log(` - Jumlah File Dihapus    : ${deletedCount} file`);
  console.log(` - Ruang Yang Dibebaskan  : ${formatNumber(freedBytes)} Byte (${formatSize(freedBytes)})`);
  console.log(` - File Asli Dipertahankan: ${duplicateGroups.length} file`);
  console.log('='.repeat(80) + '\n');
}

// Jalankan program utama
main().catch(err => {
  console.error('[FATAL ERROR]:', err);
  process.exit(1);
});
