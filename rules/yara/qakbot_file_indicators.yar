/*
 * QakBot (Qbot) File Indicators
 * Banking trojan/loader known for HTML smuggling and regsvr32 execution
 * References: MITRE T1218.010, T1055, T1566.001
 */

rule qakbot_loader_strings {
    meta:
        description = "Detects QakBot loader based on common strings and patterns"
        author = "Detection Pipeline"
        date = "2026-02-05"
        severity = "critical"
        mitre_attack = "T1218.010,T1055"
        family = "qakbot"

    strings:
        $mz = {4D 5A}
        $s1 = "regsvr32" ascii wide nocase
        $s2 = "/s " ascii wide
        $s3 = "DllRegisterServer" ascii
        $cfg1 = "spx" ascii
        $cfg2 = "abc" ascii
        $cfg3 = "obama" ascii
        $cfg4 = "biden" ascii
        $api1 = "NtCreateThread" ascii
        $api2 = "NtWriteVirtualMemory" ascii
        $api3 = "NtAllocateVirtualMemory" ascii
        $api4 = "RtlCreateUserThread" ascii
        $str1 = "%s\\%s" ascii
        $str2 = "Content-Type:" ascii
        $str3 = "Mozilla" ascii

    condition:
        $mz at 0 and
        filesize < 3MB and
        (
            (2 of ($cfg*)) or
            (2 of ($api*) and any of ($s*)) or
            (all of ($s*) and any of ($str*))
        )
}

rule qakbot_html_smuggling {
    meta:
        description = "Detects QakBot HTML smuggling delivery document"
        author = "Detection Pipeline"
        date = "2026-02-05"
        severity = "high"
        mitre_attack = "T1027.006"
        family = "qakbot"

    strings:
        $html = "<html" ascii nocase
        $script = "<script" ascii nocase
        $blob1 = "Blob(" ascii
        $blob2 = "createObjectURL" ascii
        $blob3 = "URL.createObjectURL" ascii
        $decode1 = "atob(" ascii
        $decode2 = "fromCharCode" ascii
        $decode3 = "charCodeAt" ascii
        $dl1 = "download" ascii
        $dl2 = "href" ascii
        $dl3 = ".zip" ascii
        $dl4 = ".iso" ascii

    condition:
        $html and $script and
        filesize < 5MB and
        (2 of ($blob*) or 2 of ($decode*)) and
        2 of ($dl*)
}

rule qakbot_dll_payload {
    meta:
        description = "Detects QakBot DLL payload"
        author = "Detection Pipeline"
        date = "2026-02-05"
        severity = "critical"
        mitre_attack = "T1055.001,T1218.010"
        family = "qakbot"

    strings:
        $mz = {4D 5A}
        $export1 = "DllInstall" ascii
        $export2 = "DllRegisterServer" ascii
        $str1 = "netstat" ascii wide
        $str2 = "ipconfig" ascii wide
        $str3 = "whoami" ascii wide
        $str4 = "net view" ascii wide
        $inj1 = {64 A1 30 00 00 00}  // mov eax, fs:[30h] - PEB access
        $inj2 = {8B 40 0C 8B 40 14}  // PEB_LDR_DATA traversal
        $mutex = "Global\\" ascii wide

    condition:
        $mz at 0 and
        filesize < 2MB and
        any of ($export*) and
        (3 of ($str*) or any of ($inj*) or $mutex)
}
