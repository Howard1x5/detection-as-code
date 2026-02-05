/*
 * Emotet File Indicators
 * Loader/Dropper malware known for PowerShell cradles and rundll32 execution
 * References: MITRE T1059.001, T1218.011, T1547.001
 */

rule emotet_loader_strings {
    meta:
        description = "Detects Emotet loader based on common strings"
        author = "Detection Pipeline"
        date = "2026-02-05"
        severity = "critical"
        mitre_attack = "T1059.001,T1218.011"
        family = "emotet"

    strings:
        $s1 = "rundll32.exe" ascii wide nocase
        $s2 = "regsvr32" ascii wide nocase
        $s3 = "DllRegisterServer" ascii
        $s4 = "DllUnregisterServer" ascii
        $enc1 = {8B ?? 83 ?? ?? 33 ?? 8B ?? 83 ?? ??}  // XOR decryption loop
        $enc2 = {C1 ?? 04 33 ?? C1 ?? 05}  // Bit rotation
        $api1 = "VirtualAlloc" ascii
        $api2 = "VirtualProtect" ascii
        $api3 = "CreateThread" ascii
        $pdb1 = "emotet" ascii nocase
        $pdb2 = "heodo" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        (
            ($pdb1 or $pdb2) or
            (2 of ($s*) and 2 of ($api*)) or
            (any of ($enc*) and 2 of ($api*))
        )
}

rule emotet_doc_dropper {
    meta:
        description = "Detects Emotet malicious document dropper"
        author = "Detection Pipeline"
        date = "2026-02-05"
        severity = "high"
        mitre_attack = "T1566.001,T1059.001"
        family = "emotet"

    strings:
        $ole = {D0 CF 11 E0 A1 B1 1A E1}
        $macro1 = "AutoOpen" ascii
        $macro2 = "Document_Open" ascii
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "-enc" ascii wide nocase
        $ps3 = "IEX" ascii wide nocase
        $ps4 = "Invoke-Expression" ascii wide nocase
        $dl1 = "DownloadString" ascii wide nocase
        $dl2 = "DownloadFile" ascii wide nocase
        $dl3 = "WebClient" ascii wide nocase
        $dl4 = "Net.WebClient" ascii wide nocase
        $obf1 = "chr(" ascii wide nocase
        $obf2 = "replace(" ascii wide nocase

    condition:
        $ole at 0 and
        filesize < 5MB and
        any of ($macro*) and
        (2 of ($ps*) or 2 of ($dl*) or 2 of ($obf*))
}

rule emotet_epoch_dll {
    meta:
        description = "Detects Emotet epoch DLL payloads"
        author = "Detection Pipeline"
        date = "2026-02-05"
        severity = "critical"
        mitre_attack = "T1055,T1218.011"
        family = "emotet"

    strings:
        $mz = {4D 5A}
        $export1 = "Control_RunDLL" ascii
        $export2 = "DllMain" ascii
        $export3 = "ServiceMain" ascii
        $str1 = "%s\\%s.dll" ascii wide
        $str2 = "%TEMP%" ascii wide
        $str3 = "\\AppData\\Local\\" ascii wide
        $code1 = {68 ?? ?? ?? ?? FF 15}  // push addr; call
        $code2 = {8B 45 ?? 50 8B 4D ?? 51}  // mov eax; push; mov ecx; push

    condition:
        $mz at 0 and
        filesize < 1MB and
        any of ($export*) and
        (2 of ($str*) or 2 of ($code*))
}
