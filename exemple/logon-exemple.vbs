' Logon script - maps drives and logs
Option Explicit
On Error Resume Next
Dim oNet, oShell, fso, f, user, i, arr(3)
Set oNet = CreateObject("WScript.Network")
Set oShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
user = oNet.UserName
oNet.MapNetworkDrive "S:", "\\srv01\shared"
If InStr(user, "adm") > 0 Then MsgBox "Admin: " & Mid(user, 1, 3)
If user = "Admin" Then WScript.Echo "hello"
oShell.RegWrite "HKCU\Software\Acme\LastLogon", Now, "REG_SZ"
Set f = fso.OpenTextFile("C:\Logs\logon.txt", 8, True)
f.WriteLine FormatDateTime(Now) & " " & user
f.Close
Set http = CreateObject("MSXML2.XMLHTTP.6.0")
http.Open "GET", "http://intranet/api/ping?pwd=x", False
password = "S3cret!"
Set wmi = GetObject("winmgmts:\\.\root\cimv2")
Set ol = CreateObject("Outlook.Application")
Execute "x = 1"
WScript.Quit 0
