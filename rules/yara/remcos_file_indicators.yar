/*
 * Remcos RAT File Indicators
 * Commercial RAT with keylogging, registry persistence
 * References: MITRE T1056.001, T1547.001, T1071.001
 */

rule remcos_rat_strings {
    meta:
        description = "Detects Remcos RAT based on embedded strings"
        author = "Detection Pipeline"
        date = "2026-02-05"
        severity = "critical"
        mitre_attack = "T1056.001,T1547.001"
        family = "remcos"

    strings:
        $mz = {4D 5A}
        $rem1 = "Remcos" ascii wide nocase
        $rem2 = "remcos" ascii wide
        $rem3 = "Breaking-Security" ascii wide
        $rem4 = "BreakingSecurity" ascii wide
        $cfg1 = "licence" ascii wide
        $cfg2 = "Screenshots" ascii wide
        $cfg3 = "Keylogger" ascii wide
        $cfg4 = "MicRecorder" ascii wide
        $cfg5 = "WebcamCapture" ascii wide
        $mutex1 = "Remcos_Mutex" ascii wide
        $mutex2 = "Rmc-" ascii wide
        $api1 = "GetAsyncKeyState" ascii
        $api2 = "SetWindowsHookEx" ascii
        $api3 = "GetClipboardData" ascii

    condition:
        $mz at 0 and
        filesize < 5MB and
        (
            any of ($rem*) or
            any of ($mutex*) or
            (3 of ($cfg*)) or
            (all of ($api*))
        )
}

rule remcos_config_resource {
    meta:
        description = "Detects Remcos RAT configuration in PE resources"
        author = "Detection Pipeline"
        date = "2026-02-05"
        severity = "critical"
        mitre_attack = "T1027"
        family = "remcos"

    strings:
        $mz = {4D 5A}
        $rc4_key = {00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F}
        $settings = "SETTINGS" ascii wide
        $version = /v?[0-9]+\.[0-9]+\.[0-9]+/ ascii wide
        $delimiter = "|" ascii
        $host = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]+/ ascii

    condition:
        $mz at 0 and
        filesize < 5MB and
        ($settings or $rc4_key) and
        ($version or $host or #delimiter > 10)
}

rule remcos_packed {
    meta:
        description = "Detects packed Remcos RAT samples"
        author = "Detection Pipeline"
        date = "2026-02-05"
        severity = "high"
        mitre_attack = "T1027.002"
        family = "remcos"

    strings:
        $mz = {4D 5A}
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $vmp = ".vmp" ascii
        $themida = ".themida" ascii
        $rem1 = {52 00 65 00 6D 00 63 00 6F 00 73}  // Unicode "Remcos"
        $rem2 = {52 65 6D 63 6F 73}  // ASCII "Remcos"

    condition:
        $mz at 0 and
        filesize < 10MB and
        (any of ($upx*) or $vmp or $themida) and
        (any of ($rem*))
}
