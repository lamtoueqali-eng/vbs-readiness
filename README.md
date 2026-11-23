# VBS Readiness

**Find every VBScript dependency on a Windows PC before Microsoft disables VBScript by default.**

Microsoft is phasing out VBScript in Windows. It is planned to be **disabled by default around 2026–2027**, then removed completely in a later release. Logon scripts, scheduled tasks and startup items that still rely on VBScript may stop working without warning.

VBS Readiness scans a machine, tells you what will break, and how hard each script will be to migrate.

---

## Features

**Read-only.** Nothing is changed on your system and nothing is sent over the internet.

1. **Finds VBScript files** (`.vbs` `.vbe` `.wsf` `.wsc` `.hta`) on all fixed drives, or only in the folders you choose (for example a `\\server\NETLOGON` share).
2. **Finds what launches VBScript:**
   - Scheduled tasks
   - Registry Run / RunOnce keys (32 and 64-bit)
   - Startup folders of every user profile
   - Group Policy logon / startup scripts
   - Windows services
   - Scripts launched from elsewhere (network shares) are picked up too
3. **Analyses each script:**
   - 30+ COM objects detected (`WScript.Shell`, `ADODB`, `Outlook.Application`, `InternetExplorer.Application`...), each with its PowerShell replacement
   - Conversion traps: `On Error Resume Next`, `Execute`/`Eval`, `SendKeys`, HTA interfaces, Classic ASP, 1-based string indexes, case-sensitive comparisons, locale-dependent dates...
   - Security flags: hard-coded passwords, passwords in connection strings, plain HTTP, download-then-run patterns
   - **Risk score (0–100)** and **migration difficulty** for each script
4. **Checks whether VBScript is enabled** in Windows (Feature on Demand status, needs administrator rights).
5. **Outlook module (new Outlook readiness):** the new Outlook for Windows does not run COM/VSTO add-ins or VBA macros. VBS Readiness lists the installed Outlook version, add-ins, VBA macro projects, PST files and templates that will be affected.
6. **Report:** an HTML report that opens automatically, plus CSV files for Excel.

## Quick start

1. Download: green **Code** button → **Download ZIP** (or the latest **[Release](../../releases/latest)**)
2. Unzip it
3. Right-click `Run-VBSReadiness.bat` → **Run as administrator** (it also works without administrator rights, but the VBScript status check is skipped)
4. The HTML report opens when the scan is done. It is saved next to the script, with a CSV file.

**Scan only specific folders** (faster, useful for logon-script shares):

```powershell
powershell -ExecutionPolicy Bypass -File .\VBSReadiness.ps1 -Path '\\fileserver\NETLOGON','D:\Scripts'
```

**Try it on the sample script:**

```powershell
powershell -ExecutionPolicy Bypass -File .\VBSReadiness.ps1 -Path .\exemple
```

### Options

| Option | What it does |
|---|---|
| `-Path` | Folders to scan instead of all fixed drives |
| `-OutDir` | Where to save the report |
| `-SkipOutlook` | Skip the Outlook module |
| `-IncludeWindowsFolder` | Also scan `C:\Windows` (usually only Microsoft's own scripts) |
| `-SelfTest` | Creates a temporary fake environment, scans it, shows PASS/FAIL, then deletes everything (no Outlook needed) |

Requirements: Windows 10 or 11, Windows PowerShell 5.1 (built in).

## Need help migrating?

The scanner is free and works on its own.

If you would rather not convert the scripts yourself:

- **Automatic converter** (pay per use): [VBScript to PowerShell on Apify](https://apify.com/ali-lamtoueq/vbscript-to-powershell)
- **Done-for-you conversion** with clean, commented scripts and a deployment guide: [open an issue](../../issues/new) and say how many scripts you have.

## FAQ

**Is it safe to run on production machines?**
Yes. It only reads. Nothing is modified, deleted or executed. (Only `-SelfTest` creates files, in a temporary folder, and deletes them afterwards.)

**Does it send my data anywhere?**
No. The scan runs locally and the report stays on your machine.

**When will VBScript actually be disabled?**
Microsoft says "approximately 2026 or 2027" for phase 2 (disabled by default, can still be re-enabled). Phase 3 (complete removal) has no date yet.

## License

Free to use, including at work. © 2026 Ali Lamtoueq. All rights reserved.
