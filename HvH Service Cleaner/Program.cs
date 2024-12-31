using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using System.Threading;
using System.Linq;

class Program
{
    static void Main(string[] args)
    {
        OpenUrlOnStart(); // URL beim Start öffnen


        Console.Title = "HvH Service Cleaner"; // Set CMD window title

        while (true)
        {
            Console.Clear();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("====================================================");
            Console.WriteLine("                  HvH Service Cleaner               ");
            Console.WriteLine("====================================================");
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.WriteLine("");
            Console.WriteLine("====================================================");
            Console.WriteLine("  1. Clean - Perform Cleanup");
            Console.WriteLine("  2. Temp Clean - Delete Temporary Files");
            Console.WriteLine("  3. Booster - Optimize System and Internet");
            Console.WriteLine("  4. Advanced Cleanup - Includes Spoofing");
            Console.WriteLine("  5. All-in-One - Perform All Tasks");
            Console.WriteLine("  6. Exit - Exit Tool");
            Console.WriteLine("====================================================");
            Console.Write("Select an option (1/2/3/4/5/6): ");

            string choice = Console.ReadLine();
            switch (choice)
            {
                case "1":
                    Clean();
                    break;
                case "2":
                    TempClean();
                    break;
                case "3":
                    Booster();
                    break;
                case "4":
                    AdvancedCleanup();
                    break;
                case "5":
                    AllInOne();
                    break;
                case "6":
                    return;
                default:
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("[WARN] Invalid selection! Please choose a valid option.");
                    Console.ResetColor();
                    Pause();
                    break;
            }
        }
    }

    static void OpenUrlOnStart()
    {
        string url = "https://discord.gg/HvHService"; // Hier die gewünschte URL einfügen
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = url,
                UseShellExecute = true
            });
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[INFO] Opened URL: {url}");
            Console.ResetColor();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[ERROR] Could not open URL: {ex.Message}");
            Console.ResetColor();
        }
    }

static void Clean()
    {
        Console.Clear();
        Console.WriteLine("====================================================");
        Console.WriteLine("                  Clean - Performing Cleanup        ");
        Console.WriteLine("====================================================");

        if (!IsAdmin())
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[ERROR] This script must be run as Administrator!");
            Console.ResetColor();
            Pause();
            return;
        }

        DeleteFiles("C:\\Windows\\System32\\winevt\\Logs\\*");
        DeleteFiles("C:\\Windows\\System32\\sru\\SRUDB.dat");
        DeleteFiles("C:\\Windows\\Prefetch\\*");
        DeleteFiles("C:\\Windows\\Temp\\*");
        DeleteFiles(Path.GetTempPath());
        DeleteFiles("C:\\Temp\\*");

        ClearBrowserCache();
        ClearQuickAccess();
        CleanupDisk();

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("[+] Cleanup completed successfully!");
        Console.ResetColor();
        Pause();
    }

    static void TempClean()
    {
        Console.Clear();
        Console.WriteLine("====================================================");
        Console.WriteLine("            Temp Clean - Deleting Temporary Files   ");
        Console.WriteLine("====================================================");

        DeleteFiles(Path.GetTempPath());
        DeleteFiles("C:\\Windows\\Temp\\*");
        DeleteFiles("C:\\Temp\\*");

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("[+] Temporary files deleted successfully!");
        Console.ResetColor();
        Pause();
    }

    static void Booster()
    {
        Console.Clear();
        Console.WriteLine("====================================================");
        Console.WriteLine("            Booster - Optimizing System            ");
        Console.WriteLine("====================================================");

        DeleteFiles("C:\\Windows\\Prefetch\\*");
        RunCommand("defrag", "C: /O");
        RunCommand("netsh", "interface ip reset");
        RunCommand("netsh", "winsock reset");
        RunCommand("netsh", "int tcp set global autotuninglevel=normal");
        RunCommand("netsh", "int tcp set global congestionprovider=ctcp");

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("[+] System and internet optimized successfully!");
        Console.ResetColor();
        Pause();
    }

    static void AdvancedCleanup()
    {
        Console.Clear();
        Console.WriteLine("====================================================");
        Console.WriteLine("            Advanced Cleanup - Includes Spoofing   ");
        Console.WriteLine("====================================================");

        KillProcess("Steam.exe");
        Console.ForegroundColor = ConsoleColor.Blue;
        Console.WriteLine("[INFO] Steam process terminated.");
        Console.ResetColor();

        ModifyHostsFile();
        Console.ForegroundColor = ConsoleColor.Blue;
        Console.WriteLine("[INFO] Hosts file modified.");
        Console.ResetColor();

        DeleteRegistryKeys();
        Console.ForegroundColor = ConsoleColor.Blue;
        Console.WriteLine("[INFO] Registry keys deleted.");
        Console.ResetColor();

        CleanupDirectories();
        Console.ForegroundColor = ConsoleColor.Blue;
        Console.WriteLine("[INFO] Directories cleaned up.");
        Console.ResetColor();

        SpoofMACAddresses();
        Console.ForegroundColor = ConsoleColor.Blue;
        Console.WriteLine("[INFO] MAC addresses spoofed.");
        Console.ResetColor();

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("[+] Advanced cleanup completed successfully!");
        Console.ResetColor();
        Pause();
    }

    static void AllInOne()
    {
        Console.Clear();
        Console.WriteLine("====================================================");
        Console.WriteLine("            All-in-One - Performing All Tasks       ");
        Console.WriteLine("====================================================");

        Clean();
        TempClean();
        Booster();
        AdvancedCleanup();

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("[+] All tasks completed successfully!");
        Console.ResetColor();
        Pause();
    }

    static void KillProcess(string processName)
    {
        RunCommand("taskkill", $"/F /IM {processName} /T");
        Console.ForegroundColor = ConsoleColor.Blue;
        Console.WriteLine($"[INFO] Process {processName} terminated.");
        Console.ResetColor();
    }

    static void ModifyHostsFile()
    {
        string hostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers\\etc\\hosts");

        try
        {
            if (!File.Exists(hostsPath))
            {
                throw new FileNotFoundException($"The hosts file does not exist at: {hostsPath}");
            }

            File.AppendAllText(hostsPath, "127.0.0.1 xboxlive.com\n");
            File.AppendAllText(hostsPath, "127.0.0.1 user.auth.xboxlive.com\n");
            File.AppendAllText(hostsPath, "127.0.0.1 presence-heartbeat.xboxlive.com\n");

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[+] Hosts file modified successfully.");
            Console.ResetColor();
        }
        catch (UnauthorizedAccessException)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[ERROR] Access denied! Run the program as Administrator.");
            Console.ResetColor();
        }
        catch (FileNotFoundException ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[ERROR] {ex.Message}");
            Console.ResetColor();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[ERROR] Failed to modify the hosts file: {ex.Message}");
            Console.ResetColor();
        }
    }


    static void DeleteRegistryKeys()
    {
        string[] keys = {
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\MSLicensing\\HardwareID",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Tracing",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Internet Explorer\\TypedURLs",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\MSLicensing\\Store",
            "HKEY_CURRENT_USER\\Software\\WinRAR\\ArcHistory",
            "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\bam\\State\\UserSettings",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Tracing",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Tracing",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Tracing",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Internet Explorer\\TypedURLs",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{GUID}",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Taskband",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\ActivityCache\\Activities",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal Server Client\\Default",
            "HKEY_CURRENT_USER\\Software\\WinRAR\\ArcHistory",
            "HKEY_CURRENT_USER\\Software\\WinRAR\\DialogEditHistory\\ExtrPath",
            "HKEY_CURRENT_USER\\Software\\WinRAR\\DialogEditHistory\\ArcName",
            "HKEY_CURRENT_USER\\Software\\WinRAR\\DialogEditHistory\\UnpPath",
            "HKEY_CURRENT_USER\\Software\\7-Zip\\FM\\FileHistory",
            "HKEY_CURRENT_USER\\Software\\7-Zip\\FM\\FolderHistory",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\Shell\\Bags",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage",
            "HKEY_CURRENT_USER\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\EventStore",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VolumeCaches",
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters",
            "HKEY_CURRENT_USER\\Software\\Google\\Drive\\SyncPrefs",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\OneDrive\\Accounts",
            "HKEY_CURRENT_USER\\Software\\Dropbox\\Client",
            "HKEY_CURRENT_USER\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\MicrosoftEdge",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"
        };

        foreach (var key in keys)
        {
            RunCommand("reg", $"DELETE {key} /F");
        }
    }

    static void CleanupDirectories()
    {
        string[] directories = {
            "%LocalAppData%\\FiveM\\FiveM.app\\cache",
            "%LocalAppData%\\FiveM\\FiveM.app\\logs",
            "%userprofile%\\AppData\\Roaming\\CitizenFX",
            "%AppData%\\Steam\\logs\\*",
            "%LocalAppData%\\Steam\\htmlcache\\*",
            "%LocalAppData%\\CrashDumps\\*",
            "%LocalAppData%\\Microsoft\\Edge\\User Data\\Default\\Cache",
            "%LocalAppData%\\Opera Software\\Opera Stable\\Cache",
            "%AppData%\\Microsoft\\Windows\\Recent\\AutomaticDestinations",
            "%LocalAppData%\\Temp",
            "%AppData%\\Microsoft\\Windows\\Recent",
            "%LocalAppData%\\Packages\\*\\LocalCache",
            "%LocalAppData%\\Google\\Chrome\\User Data\\Default\\Cache",
            "%LocalAppData%\\Google\\Chrome\\User Data\\Default\\Code Cache",
            "%LocalAppData%\\Google\\Chrome\\User Data\\Default\\Service Worker\\CacheStorage",
            "%AppData%\\Mozilla\\Firefox\\Profiles\\*\\cache2",
            "%AppData%\\Mozilla\\Firefox\\Profiles\\*\\storage\\default",
            "%LocalAppData%\\Microsoft\\Edge\\User Data\\Default\\Cache",
            "%LocalAppData%\\Microsoft\\Edge\\User Data\\Default\\Code Cache",
            "%AppData%\\discord\\Cache",
            "%AppData%\\discord\\Code Cache",
            "%AppData%\\discord\\GPUCache",
            "%AppData%\\Steam\\Dumps",
            "%LocalAppData%\\Steam\\htmlcache",
            "%LocalAppData%\\Steam\\userdata",
            "%ProgramData%\\Microsoft\\Windows Defender\\Scans\\History\\Service",
            "%ProgramData%\\Microsoft\\Windows Defender\\Scans\\History\\Results\\Resource",
            "%SystemRoot%\\System32\\winevt\\Logs",
            "%SystemRoot%\\Minidump",
            "%SystemRoot%\\MEMORY.DMP",
            "%SystemRoot%\\Prefetch",
            "%SystemRoot%\\SoftwareDistribution\\Download",
            "%AppData%\\Microsoft\\Windows\\Recent\\AutomaticDestinations",
            "%AppData%\\Microsoft\\Windows\\Recent\\CustomDestinations",
            "%LocalAppData%\\Microsoft\\Windows\\WER\\ReportArchive",
            "%LocalAppData%\\Microsoft\\Windows\\WER\\ReportQueue",
            "%LocalAppData%\\Microsoft\\Edge\\User Data\\Default\\History",
            "%LocalAppData%\\Google\\Chrome\\User Data\\Default\\History",
            "%AppData%\\Mozilla\\Firefox\\Profiles\\*\\places.sqlite",
            "%SystemRoot%\\System32\\winevt\\Logs\\Application.evtx",
            "%SystemRoot%\\System32\\winevt\\Logs\\Security.evtx",
            "%SystemRoot%\\System32\\winevt\\Logs\\System.evtx",
            "%SystemRoot%\\Prefetch",
            "%SystemRoot%\\System32\\Tasks",
            "%SystemRoot%\\Logs\\WindowsUpdate",
            "%SystemRoot%\\SoftwareDistribution\\ReportingEvents.log",
            "%LocalAppData%\\CrashDumps",
            "%ProgramData%\\Microsoft\\Windows Defender\\Support",
            "%LocalAppData%\\Microsoft\\Terminal Server Client\\Cache",
            "%LocalAppData%\\Google\\Chrome\\User Data\\Default\\Service Worker\\CacheStorage",
            "%AppData%\\Mozilla\\Firefox\\Profiles\\*\\cache2",
            "%AppData%\\Mozilla\\Firefox\\Profiles\\*\\storage\\default",
            "%AppData%\\discord\\Cache",
            "%AppData%\\discord\\Code Cache",
            "%AppData%\\discord\\GPUCache",
            "%AppData%\\Steam\\Dumps",
            "%LocalAppData%\\Microsoft\\Windows\\WER\\ReportArchive",
            "%LocalAppData%\\Microsoft\\Windows\\WER\\ReportQueue",
            "%LocalAppData%\\Google\\Chrome\\User Data\\Default\\History",
            "%AppData%\\Mozilla\\Firefox\\Profiles\\*\\places.sqlite",
            "%SystemRoot%\\System32\\winevt\\Logs\\Application.evtx",
            "%SystemRoot%\\System32\\winevt\\Logs\\Security.evtx",
            "%SystemRoot%\\System32\\winevt\\Logs\\System.evtx",
            "%SystemRoot%\\Logs\\WindowsUpdate",
            "%SystemRoot%\\SoftwareDistribution\\ReportingEvents.log",
            "%ProgramData%\\Microsoft\\Windows Defender\\Support",
            "%LocalAppData%\\Microsoft\\Terminal Server Client\\Cache",
            "%LocalAppData%\\Microsoft\\Windows\\INetCache",
            "%LocalAppData%\\Microsoft\\Windows\\WebCache",
            "%LocalAppData%\\Packages\\Microsoft.Windows.Cortana_cw5n1h2txyewy\\LocalState\\DeviceSearchCache",
            "%LocalAppData%\\ConnectedDevicesPlatform\\L",
            "%AppData%\\Microsoft\\Windows\\Recent Items",
            "%LocalAppData%\\Temp\\*.tmp",
            "%LocalAppData%\\Packages\\*\\Settings",
            "%ProgramData%\\Microsoft\\Windows\\WER\\Temp",
            "%ProgramData%\\Microsoft\\Windows\\WER\\ReportArchive",
            "%ProgramData%\\Microsoft\\Windows\\WER\\ReportQueue",
            "%ProgramData%\\Microsoft\\Search\\Data\\Applications\\Windows",
            "%ProgramData%\\Microsoft\\Search\\Data\\Temp",
            "%SystemRoot%\\ServiceProfiles\\NetworkService\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache",
            "%SystemRoot%\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache",
            "%SystemRoot%\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache",
            "%SystemRoot%\\System32\\Tasks\\Microsoft\\Windows\\DiskCleanup",
            "%SystemRoot%\\System32\\Tasks\\Microsoft\\Windows\\UpdateOrchestrator",
            "%SystemRoot%\\System32\\Tasks\\Microsoft\\Windows\\WDI",
            "%SystemRoot%\\Installer\\$PatchCache$",
            "%SystemRoot%\\Installer\\$InstallerCache$",
            "%SystemRoot%\\System32\\LogFiles\\WMI\\RtBackup",
            "%SystemRoot%\\System32\\LogFiles\\ETW",
            "%LocalAppData%\\Microsoft\\Windows\\INetCache",
            "%LocalAppData%\\Microsoft\\Windows\\WebCache",
            "%LocalAppData%\\Packages\\Microsoft.Windows.Cortana_cw5n1h2txyewy\\LocalState\\DeviceSearchCache",
            "%LocalAppData%\\ConnectedDevicesPlatform\\L",
            "%AppData%\\Microsoft\\Windows\\Recent Items",
            "%LocalAppData%\\Temp\\*.tmp",
            "%LocalAppData%\\Packages\\*\\Settings",
            "%ProgramData%\\Microsoft\\Windows\\WER\\Temp",
            "%ProgramData%\\Microsoft\\Windows\\WER\\ReportArchive",
            "%ProgramData%\\Microsoft\\Windows\\WER\\ReportQueue",
            "%ProgramData%\\Microsoft\\Search\\Data\\Applications\\Windows",
            "%ProgramData%\\Microsoft\\Search\\Data\\Temp",
            "%SystemRoot%\\ServiceProfiles\\NetworkService\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache",
            "%SystemRoot%\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache"



    };

        foreach (var dir in directories)
        {
            string resolvedPath = Environment.ExpandEnvironmentVariables(dir);

            try
            {
                if (resolvedPath.Contains("*"))
                {
                    // Verzeichnisse mit Platzhaltern auflösen
                    var matchedDirs = Directory.GetParent(resolvedPath)
                        ?.EnumerateDirectories(Path.GetFileName(resolvedPath));

                    foreach (var subDir in matchedDirs)
                    {
                        Directory.Delete(subDir.FullName, true);
                        Console.WriteLine($"[INFO] Directory {subDir.FullName} deleted successfully.");
                    }
                }
                else if (Directory.Exists(resolvedPath))
                {
                    Directory.Delete(resolvedPath, true);
                    Console.WriteLine($"[INFO] Directory {resolvedPath} deleted successfully.");
                }
                else
                {
                    Console.WriteLine($"[WARN] Directory {resolvedPath} does not exist.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Failed to delete directory {resolvedPath}: {ex.Message}");
            }
        }
    }

    static void SpoofMACAddresses()
    {
        string adapterName = "Ethernet"; // Netzwerkadapter-Name (anpassen!)
        string randomMac = GenerateRandomMAC();

        // Adapter deaktivieren
        RunCommand("netsh", $"interface set interface \"{adapterName}\" disabled");

        // Registry-Schlüssel setzen
        RunCommand("reg", $"add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\\0001\" /v NetworkAddress /t REG_SZ /d {randomMac} /f");

        // Adapter wieder aktivieren
        RunCommand("netsh", $"interface set interface \"{adapterName}\" enabled");

        Console.WriteLine($"MAC-Adresse geändert zu: {randomMac}");
    }

    static string GenerateRandomMAC()
    {
        Random random = new Random();
        byte[] macBytes = new byte[6];

        // Die ersten drei Bytes sind der OUI (Organizationally Unique Identifier) - setze hier eine Zufällige aus dem Bereich für private MAC-Adressen
        macBytes[0] = (byte)(0x02 | (random.Next(0, 256) & 0xFE)); // Setze das Lokale-Bit
        macBytes[1] = (byte)random.Next(0, 256);
        macBytes[2] = (byte)random.Next(0, 256);

        // Die letzten drei Bytes sind zufällig
        macBytes[3] = (byte)random.Next(0, 256);
        macBytes[4] = (byte)random.Next(0, 256);
        macBytes[5] = (byte)random.Next(0, 256);

        // Konvertiere in das übliche MAC-Adresse-Format
        return string.Join("", macBytes.Select(b => b.ToString("X2")));
    }

    static void CleanupDisk()
    {
        RunCommand("cleanmgr", "/sagerun:1");
        Console.WriteLine("[INFO] Disk Cleanup initialized.");
    }

    static void ClearQuickAccess()
    {
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Microsoft\\Windows\\Recent\\AutomaticDestinations");
        DeleteFiles(path);
        Console.ForegroundColor = ConsoleColor.Blue;
        Console.WriteLine("[INFO] Quick Access cleared.");
        Console.ResetColor();
    }

    static void RestartExplorer()
    {
        try
        {
            // Stop explorer.exe
            KillProcess("explorer.exe");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[+] Explorer process terminated.");
            Console.ResetColor();

            // Pause for 1 Second
            Thread.Sleep(1000);

            // Batch-Datei erstellen und ausführen
            string batchFilePath = Path.Combine(Path.GetTempPath(), "RestartExplorer.bat");
            File.WriteAllText(batchFilePath, "start explorer.exe");

            Process.Start(new ProcessStartInfo
            {
                FileName = batchFilePath,
                UseShellExecute = true, // Batch-Datei unabhängig starten
                WindowStyle = ProcessWindowStyle.Hidden // Kein Konsolenfenster anzeigen
            });

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[+] Explorer restarted using batch file.");
            Console.ResetColor();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[ERROR] Failed to restart Explorer: {ex.Message}");
            Console.ResetColor();
        }
    }

    static void ClearBrowserCache()
    {
        string[] browserPaths = {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google\\Chrome\\User Data\\Default\\Cache"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Mozilla\\Firefox\\Profiles")
        };

        foreach (var path in browserPaths)
        {
            DeleteFiles(path);
        }
        Console.ForegroundColor = ConsoleColor.Blue;
        Console.WriteLine("[INFO] Browser cache cleared.");
        Console.ResetColor();
    }

    static void DeleteFiles(string path)
    {
        try
        {
            foreach (string file in Directory.GetFiles(Path.GetDirectoryName(path) ?? "", "*", SearchOption.AllDirectories))
            {
                File.Delete(file);
            }
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine($"[INFO] Files under {path} deleted successfully.");
            Console.ResetColor();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[ERROR] Error deleting files under {path}: {ex.Message}");
            Console.ResetColor();
        }
    }

    static void RunCommand(string command, string arguments)
    {
        try
        {
            Process process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = command,
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            process.Start();
            process.WaitForExit();
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine($"[INFO] {command} {arguments} executed successfully.");
            Console.ResetColor();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[ERROR] Error executing {command} {arguments}: {ex.Message}");
            Console.ResetColor();
        }
    }

    static bool IsAdmin()
    {
        var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var principal = new System.Security.Principal.WindowsPrincipal(identity);
        return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    static void Pause()
    {
        Console.WriteLine("Press any key to continue...");
        Console.ReadKey();
    }
}