/*
 * Starter detection rules for malysis.
 * These are deliberately broad triage rules, not high-fidelity family rules.
 * Drop your own .yar files in this directory (or point --rules elsewhere).
 */

rule upx_packed
{
    meta:
        description = "UPX section names present"
        severity = "medium"
    strings:
        $a = "UPX0" ascii
        $b = "UPX1" ascii
        $c = "UPX!" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule embedded_pe_in_non_pe
{
    meta:
        description = "A Windows executable is embedded inside a file that is not itself a PE"
        severity = "high"
    strings:
        $mz = "This program cannot be run in DOS mode"
    condition:
        uint16(0) != 0x5A4D and $mz
}

rule base64_encoded_pe
{
    meta:
        description = "Base64 encoded MZ header"
        severity = "high"
    strings:
        $a = "TVqQAAMAAAAEAAA" ascii wide
        $b = "TVpQAAIAAAAEAA8" ascii wide
        $c = "TVoAAAAAAAAAAAA" ascii wide
    condition:
        any of them
}

rule powershell_encoded_command
{
    meta:
        description = "Encoded or download-and-execute PowerShell"
        severity = "high"
    strings:
        $enc1 = "-EncodedCommand" ascii wide nocase
        $enc2 = "-enc " ascii wide nocase
        $enc3 = "FromBase64String" ascii wide nocase
        $dl1 = "DownloadString" ascii wide nocase
        $dl2 = "DownloadFile" ascii wide nocase
        $iex = "Invoke-Expression" ascii wide nocase
        $iex2 = "IEX(" ascii wide nocase
        $hid = "-w hidden" ascii wide nocase
    condition:
        2 of them
}

rule lolbin_usage
{
    meta:
        description = "References to living-off-the-land binaries"
        severity = "low"
    strings:
        $a = "certutil" ascii wide nocase
        $b = "bitsadmin" ascii wide nocase
        $c = "mshta" ascii wide nocase
        $d = "regsvr32" ascii wide nocase
        $e = "rundll32" ascii wide nocase
        $f = "wmic process call create" ascii wide nocase
        $g = "schtasks /create" ascii wide nocase
    condition:
        2 of them
}

rule vba_autoexec_macro
{
    meta:
        description = "VBA macro with an automatic execution trigger"
        severity = "high"
    strings:
        $a = "AutoOpen" ascii wide nocase
        $b = "Document_Open" ascii wide nocase
        $c = "Workbook_Open" ascii wide nocase
        $d = "Auto_Close" ascii wide nocase
        $shell = "Shell" ascii wide nocase
        $create = "CreateObject" ascii wide nocase
    condition:
        1 of ($a, $b, $c, $d) and 1 of ($shell, $create)
}

rule office_dde_field
{
    meta:
        description = "DDE field that executes a command on open"
        severity = "high"
    strings:
        $a = "DDEAUTO" ascii wide nocase
        $b = "dde c:\\\\" ascii wide nocase
    condition:
        any of them
}

rule pdf_active_content
{
    meta:
        description = "PDF containing JavaScript or an automatic action"
        severity = "medium"
    strings:
        $js = "/JavaScript" ascii
        $js2 = "/JS" ascii
        $oa = "/OpenAction" ascii
        $launch = "/Launch" ascii
    condition:
        uint32(0) == 0x46445025 and any of them
}

rule anti_vm_strings
{
    meta:
        description = "Sandbox and virtualisation artefact checks"
        severity = "medium"
    strings:
        $a = "VMwareService" ascii wide nocase
        $b = "VBoxTray" ascii wide nocase
        $c = "vboxguest" ascii wide nocase
        $d = "SbieDll" ascii wide nocase
        $e = "wine_get_unix_file_name" ascii
        $f = "QEMU" ascii wide
        $g = "VIRTUAL HD" ascii wide nocase
    condition:
        2 of them
}

rule webshell_generic
{
    meta:
        description = "Generic PHP webshell pattern"
        severity = "high"
    strings:
        $php = "<?php" ascii
        $a = /eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ ascii nocase
        $b = /assert\s*\(\s*\$_(POST|GET|REQUEST)/ ascii nocase
        $c = /system\s*\(\s*\$_(POST|GET|REQUEST)/ ascii nocase
        $d = /shell_exec\s*\(\s*\$_(POST|GET|REQUEST)/ ascii nocase
        $e = "preg_replace" ascii nocase
    condition:
        $php and 1 of ($a, $b, $c, $d)
}

rule ransom_note_language
{
    meta:
        description = "Text typical of a ransom note"
        severity = "high"
    strings:
        $a = "your files have been encrypted" ascii wide nocase
        $b = "decryption key" ascii wide nocase
        $c = "bitcoin" ascii wide nocase
        $d = ".onion" ascii wide nocase
        $e = "shadow copies" ascii wide nocase
        $f = "vssadmin delete shadows" ascii wide nocase
    condition:
        2 of them
}
