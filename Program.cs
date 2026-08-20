using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Security.Cryptography;
using System.Text;
using System.Linq;

namespace ChunkCrypt
{
    class Program
    {
        static string marker = "[no-mode]";
        static string extension = "LOCKED";
        static int IV_SIZE = 8;

        static void Main(string[] args)
        {
            Console.WriteLine("\n================================================");
            Console.WriteLine("   Intermittent Encryption Demo   ");
            Console.WriteLine("================================================\n");

            if (args.Length < 2)
            {
                Console.WriteLine("Usage: ./binary <enc/dec> <filename>");
                return;
            }

            string mode = args[0].ToLower();
            string fileName = args[1];

            try
            {
                if (mode == "enc")
                {
                    string uniqueKey = Algo.getUniqueKey(47);
                    byte[] salt = Algo.Salsa20.generateSalt();
                    Console.WriteLine($"[+] Target : {fileName}");
                    Console.WriteLine($"[+] KEY    : {uniqueKey}");
                    Console.WriteLine($"[+] SALT   : {Convert.ToBase64String(salt)}");

                    EncryptProcess(fileName, uniqueKey, salt);
                    Console.WriteLine("\n[!] SUCCESS: File is LOCKED.");
                }
                else if (mode == "dec")
                {
                    Console.Write("[?] Input Key  : ");
                    string k = Console.ReadLine();
                    Console.Write("[?] Input Salt : ");
                    string s = Console.ReadLine();
                    byte[] salt = Convert.FromBase64String(s);

                    if (DecryptProcess(fileName, k, salt))
                        Console.WriteLine("\n[+] SUCCESS: File Restored.");
                    else
                        Console.WriteLine("\n[-] FAILED: Key mismatch or Corrupted file.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n[ERROR] : {ex.Message}");
                Console.WriteLine($"Stack: {ex.StackTrace}");
            }
        }

        public static double CalculateEntropy(string filePath)
        {
            byte[] fileData = File.ReadAllBytes(filePath);
            if (fileData.Length == 0) return 0;

            var counts = new Dictionary<byte, int>();
            foreach (byte b in fileData)
            {
                if (counts.ContainsKey(b)) counts[b]++;
                else counts[b] = 1;
            }

            double entropy = 0;
            foreach (var count in counts.Values)
            {
                double p = (double)count / fileData.Length;
                entropy -= p * Math.Log(p, 2);
            }
            return entropy;
        }

        public static void EncryptProcess(string file, string password, byte[] salt)
        {
            long fileSize = new FileInfo(file).Length;
            string originalFileName = Path.GetFileName(file);

            // Skip file kosong
            if (fileSize < 1)
            {
                //Console.WriteLine($"[SKIP] {Path.GetFileName(file)} (empty)");
                return;
            }

            // Derive key
            Rfc2898DeriveBytes RFCDB = new Rfc2898DeriveBytes(password, salt, 100, HashAlgorithmName.SHA256);
            byte[] key = RFCDB.GetBytes(32);
            RFCDB.Dispose();

            // Generate IV
            byte[] iv = new byte[IV_SIZE];
            using (var rngCrypto = new RNGCryptoServiceProvider())
            {
                rngCrypto.GetBytes(iv);
            }

            // Setup parameters
            int seed = Algo.AdvancedLogic.GetDeterministicSeed(key, originalFileName, fileSize);
            Algo.CustomRandom rng = new Algo.CustomRandom(seed);
            Algo.AdvancedLogic.GetAdaptiveParams(file, fileSize, out int chunkSize, out int minJump, out int maxJump);

            Console.WriteLine($"[DEBUG] ChunkSize: {chunkSize}, MinJump: {minJump}, MaxJump: {maxJump}");

            int totalChunks = 0;
            long totalEncrypted = 0;
            byte[] buffer = new byte[chunkSize];

            // Hitung ukuran file baru (file asli + footer)
            byte[] markerBytes = Encoding.UTF8.GetBytes(marker);
            int footerSize = IV_SIZE + markerBytes.Length;
            long newFileSize = fileSize + footerSize;

            // Extend file size dulu menggunakan FileStream
            using (FileStream fs = new FileStream(file, FileMode.Open, FileAccess.Write))
            {
                fs.SetLength(newFileSize);
                fs.Flush();
            }

            // Buka MMF dengan ukuran baru
            using (var mmf = MemoryMappedFile.CreateFromFile(file, FileMode.Open, null, newFileSize, MemoryMappedFileAccess.ReadWrite))
            {
                using (var accessor = mmf.CreateViewAccessor())
                {
                    long currentPos = 0;

                    // ENKRIPSI KONTEN (hanya sampai fileSize asli, jangan sentuh footer)
                    while (currentPos < fileSize)
                    {
                        int bytesToRead = (int)Math.Min(chunkSize, fileSize - currentPos);
                        if (bytesToRead <= 0) break;

                        // Baca data
                        accessor.ReadArray(currentPos, buffer, 0, bytesToRead);

                        // Enkripsi
                        byte[] encrypted;
                        using (Algo.Salsa20 salsa = new Algo.Salsa20())
                        {
                            encrypted = salsa.Encrypt(buffer.Take(bytesToRead).ToArray(), key, iv);
                        }

                        // Tulis kembali
                        accessor.WriteArray(currentPos, encrypted, 0, encrypted.Length);

                        totalChunks++;
                        totalEncrypted += bytesToRead;
                        currentPos += bytesToRead;

                        if (currentPos >= fileSize) break;
                        if (minJump == 0 && maxJump == 0) continue;

                        int jump = rng.Next(minJump, maxJump);
                        if (currentPos + jump >= fileSize) break;

                        currentPos += jump;
                    }

                    // Tulis footer menggunakan MMF (mulai dari posisi fileSize)
                    long footerPos = fileSize;

                    // Tulis IV (8 bytes)
                    accessor.WriteArray(footerPos, iv, 0, IV_SIZE);
                    footerPos += IV_SIZE;

                    // Tulis marker (9 bytes untuk "[no-mode]")
                    accessor.WriteArray(footerPos, markerBytes, 0, markerBytes.Length);

                    // Flush semua perubahan ke disk
                    accessor.Flush();
                }
            }

            // Rename file
            string encryptedFile = file + "." + extension;
            if (File.Exists(encryptedFile)) File.Delete(encryptedFile);
            File.Move(file, encryptedFile);

            // Calculate stats
            double score = CalculateEntropy(encryptedFile);
            double coverage = ((double)totalEncrypted / fileSize) * 100;

            Console.WriteLine($"[STATS] Encrypted Chunks: {totalChunks}");
            Console.WriteLine($"[STATS] Coverage: {coverage:F2}% ({totalEncrypted}/{fileSize} bytes)");
            Console.WriteLine($"[STATS] Entropy Score: {score:F2} (Target: 5.0 - 6.5)");
        }

        public static bool DecryptProcess(string file, string password, byte[] salt)
        {
            byte[] markBytes = Encoding.UTF8.GetBytes(marker);
            int footerSize = IV_SIZE + markBytes.Length;
            FileInfo fi = new FileInfo(file);
            long totalSize = fi.Length;

            if (totalSize < footerSize)
            {
                Console.WriteLine("[ERROR] File too small or corrupted");
                return false;
            }

            long originalLength = totalSize - footerSize;
            byte[] iv = new byte[IV_SIZE];
            byte[] mCheck = new byte[markBytes.Length];

            // Buka MMF dengan ukuran penuh, baca footer, lalu truncate
            using (var mmf = MemoryMappedFile.CreateFromFile(file, FileMode.Open, null, totalSize, MemoryMappedFileAccess.ReadWrite))
            {
                using (var accessor = mmf.CreateViewAccessor())
                {
                    // Baca IV dari posisi (originalLength)
                    long footerPos = originalLength;
                    accessor.ReadArray(footerPos, iv, 0, IV_SIZE);
                    footerPos += IV_SIZE;

                    // Baca marker
                    accessor.ReadArray(footerPos, mCheck, 0, markBytes.Length);

                    // Validasi marker
                    if (!mCheck.SequenceEqual(markBytes))
                    {
                        Console.WriteLine("[ERROR] Invalid marker - wrong file or corrupted");
                        return false;
                    }

                    // DERIVE KEY
                    Rfc2898DeriveBytes RFCDB = new Rfc2898DeriveBytes(password, salt, 50);
                    byte[] key = RFCDB.GetBytes(32);
                    RFCDB.Dispose();

                    string originalName = Path.GetFileName(file).Replace("." + extension, "");
                    string tempOriginalPath = Path.Combine(Path.GetDirectoryName(file), originalName);

                    int decSeed = Algo.AdvancedLogic.GetDeterministicSeed(key, originalName, originalLength);
                    Algo.CustomRandom rng = new Algo.CustomRandom(decSeed);
                    Algo.AdvancedLogic.GetAdaptiveParams(tempOriginalPath, originalLength,
                        out int chunkSize, out int minJump, out int maxJump);

                    Console.WriteLine($"[DEBUG] Decrypt - Chunk: {chunkSize}, Jump: {minJump}-{maxJump}");

                    byte[] buffer = new byte[chunkSize];
                    int chunksDecrypted = 0;
                    long currentPos = 0;

                    // DEKRIPSI KONTEN (hanya sampai originalLength, jangan sentuh footer)
                    while (currentPos < originalLength)
                    {
                        int bytesToRead = (int)Math.Min(chunkSize, originalLength - currentPos);
                        if (bytesToRead <= 0) break;

                        // Baca encrypted data
                        accessor.ReadArray(currentPos, buffer, 0, bytesToRead);

                        // Dekripsi
                        byte[] decrypted;
                        using (Algo.Salsa20 salsa = new Algo.Salsa20())
                        {
                            decrypted = salsa.Decrypt(buffer.Take(bytesToRead).ToArray(), key, iv);
                        }

                        // Tulis plaintext kembali
                        accessor.WriteArray(currentPos, decrypted, 0, decrypted.Length);

                        chunksDecrypted++;
                        currentPos += bytesToRead;

                        if (currentPos >= originalLength) break;
                        if (minJump == 0 && maxJump == 0) continue;

                        int jump = rng.Next(minJump, maxJump);
                        if (currentPos + jump >= originalLength) break;

                        currentPos += jump;
                    }

                    Console.WriteLine($"[DEBUG] Decrypted {chunksDecrypted} chunks");

                    // Flush sebelum truncate
                    accessor.Flush();
                }
            }

            // TUNGGU MMF TERTUTUP
            System.Threading.Thread.Sleep(200);

            // Truncate footer menggunakan FileStream SETELAH MMF tertutup
            using (FileStream fs = new FileStream(file, FileMode.Open, FileAccess.Write))
            {
                fs.SetLength(originalLength);
                fs.Flush();
            }

            // Rename file
            string cleanName = file.Replace("." + extension, "");
            if (File.Exists(cleanName)) File.Delete(cleanName);
            File.Move(file, cleanName);

            return true;
        }
    }
}
