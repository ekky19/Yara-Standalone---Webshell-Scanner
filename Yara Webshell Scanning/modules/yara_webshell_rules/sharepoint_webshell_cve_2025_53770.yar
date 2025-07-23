rule WEBSHELL_ASPX_Sharepoint_CVE_2025_53770
{
    meta:
        description = "Detects spinstall0.aspx-style web shell used in CVE-2025-53770 SharePoint exploitation"
        author = "Ekrem Ozdemir"
        date = "2025-07-23"
        reference = "https://research.eye.security/sharepoint-under-siege/"

    strings:
        $s1 = "<script runat=\"server\" language=\"c#\" CODEPAGE=\"65001\">" ascii
        // C# inline ASP.NET code block — typical structure of a malicious .aspx webshell

        $s2 = "System.Reflection.Assembly.Load" ascii
        // Reflection-based dynamic assembly loading — often used in obfuscated or dynamic code execution

        $s3 = "System.Web.Configuration.MachineKeySection" ascii
        // Access to the MachineKey section of ASP.NET config — used to steal ValidationKey and DecryptionKey

        $s4 = "System.Management.Automation" ascii
        // Indicates PowerShell execution via .NET — used to launch in-memory PowerShell scripts

        $s5 = "RunspaceFactory.CreateRunspace" ascii
        // A method used to build isolated PowerShell sessions for stealthy execution

        $s6 = "powershell.exe" ascii
        // Hardcoded call to the PowerShell binary — a classic sign of command execution in webshells

        $s7 = "EncodedCommand" ascii
        // Key PowerShell argument for passing base64 payloads — often used in exploitation and evasion

        $s8 = "Response.Write(cg.ValidationKey+" ascii
        // Directly leaks the cryptographic signing key to the HTTP response — exfiltration mechanism

    condition:
        filesize < 8KB and 4 of ($s*)
}


rule CVE_2025_53770_SharpyShell_CryptoDumper
{
    meta:
        description = "Detects crypto-dumping ASPX payload dropped during CVE-2025-53770 SharePoint RCE exploitation"
        author = "Ekrem Ozdemir"
        date = "2025-07-23"
        reference = "https://research.eye.security/sharepoint-under-siege/"
        threat = "ToolShell-based 0-day exploiting unauthenticated RCE in SharePoint"
        tags = "CVE-2025-53770 CVE-2025-49704 ToolShell SharePoint SharpyShell"

    strings:
        $aspx_header = "<script runat=\"server\" language=\"c#\" CODEPAGE=\"65001\">" ascii
        // Marks a server-side script in ASP.NET, often used for malicious payloads

        $namespace1  = "System.Reflection.Assembly.Load" ascii
        // Loads .NET assemblies via reflection, used to pull System.Web into scope dynamically

        $namespace2  = "System.Web.Configuration.MachineKeySection" ascii
        // Core target of this dropper — where cryptographic keys are stored

        $method_invoke = "Invoke(null, new object[0])" ascii
        // Static method invocation used to call GetApplicationConfig() on MachineKeySection

        $response_key = "Response.Write(cg.ValidationKey+" ascii
        // Begins exfiltration of the crypto key via HTTP response body

        $response_decrypt = "+cg.DecryptionKey+" ascii
        // Appends the DecryptionKey to the same HTTP response — further exfiltration

        $viewstate_keydump = "|cg.CompatibilityMode);" ascii
        // Ends the key dump with the compatibility mode — full leak format for ViewState attacks

        $file_marker = "Page_load()" ascii fullword
        // Typical function name in ASP.NET that executes on page load — used by SharpyShell

        $filename_hint = "spinstall0.aspx" ascii nocase
        // Known dropped file name from real-world attacks — useful for matching static paths

    condition:
        filesize < 8KB and
        5 of ($*)
}
