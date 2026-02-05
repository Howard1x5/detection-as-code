/*
 * Chrysalis Backdoor / Lotus Blossom APT
 * Source: Rapid7 Threat Intelligence Report (2025)
 * References: T1574.002, T1055, T1620, T1573
 */

rule chrysalis_backdoor_hashes {
    meta:
        description = "Detects Chrysalis backdoor components by known SHA-256 hashes"
        author = "Detection Pipeline"
        date = "2026-02-05"
        severity = "critical"
        mitre_attack = "T1027,T1574.002"
        family = "chrysalis"
        apt = "lotus_blossom"
        reference = "https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/"

    condition:
        // Known file hashes from Rapid7 report
        hash.sha256(0, filesize) == "a511be5164dc1122fb5a7daa3eef9467e43d8458425b15a640235796006590c9" or  // update.exe
        hash.sha256(0, filesize) == "2da00de67720f5f13b17e9d985fe70f10f153da60c9ab1086fe58f069a156924" or  // BluetoothService.exe
        hash.sha256(0, filesize) == "77bfea78def679aa1117f569a35e8fd1542df21f7e00e27f192c907e61d63a2e" or  // BluetoothService
        hash.sha256(0, filesize) == "3bdc4c0637591533f1d4198a72a33426c01f69bd2e15ceee547866f65e26b7ad" or  // log.dll
        hash.sha256(0, filesize) == "4a52570eeaf9d27722377865df312e295a7a23c3b6eb991944c2ecd707cc9906" or  // libtcc.dll
        hash.sha256(0, filesize) == "831e1ea13a1bd405f5bda2b9d8f2265f7b1db6c668dd2165ccc8a9c4c15ea7dd" or  // admin
        hash.sha256(0, filesize) == "b4169a831292e245ebdffedd5820584d73b129411546e7d3eccf4663d5fc5be3" or  // ConsoleApplication2.exe
        hash.sha256(0, filesize) == "fcc2765305bcd213b7558025b2039df2265c3e0b6401e4833123c461df2de51a"     // s047t5g.exe
}

rule chrysalis_backdoor_strings {
    meta:
        description = "Detects Chrysalis backdoor based on embedded strings and encryption keys"
        author = "Detection Pipeline"
        date = "2026-02-05"
        severity = "critical"
        mitre_attack = "T1573,T1071.001"
        family = "chrysalis"
        apt = "lotus_blossom"

    strings:
        $mz = {4D 5A}

        // Encryption keys
        $xor_key1 = "gQ2JR&9;" ascii wide
        $rc4_key1 = "qwhvb^435h&*7" ascii wide
        $rc4_key2 = "vAuig34%^325hGV" ascii wide
        $xor_key2 = "CRAZY" ascii wide

        // Mutex
        $mutex = "Global\\Jdhfv_1.0.1" ascii wide

        // C2 domains
        $c2_1 = "api.skycloudcenter.com" ascii wide
        $c2_2 = "api.wiresguard.com" ascii wide

        // C2 URL patterns
        $url1 = "/a/chat/s/" ascii wide
        $url2 = "/users/admin" ascii wide
        $url3 = "/update/v1" ascii wide
        $url4 = "/api/FileUpload/submit" ascii wide

        // Command tags
        $cmd_tag = {34 54}  // 4T - interactive shell
        $cmd_tags = "4Q" ascii  // identifier prefix

        // Config marker
        $config_marker = {30 80 08}  // offset 0x30808

    condition:
        $mz at 0 and
        filesize < 5MB and
        (
            any of ($xor_key*) or
            any of ($rc4_key*) or
            $mutex or
            2 of ($c2_*) or
            2 of ($url*) or
            ($cmd_tag and $cmd_tags)
        )
}

rule chrysalis_dll_sideload {
    meta:
        description = "Detects Chrysalis DLL sideloading component (log.dll)"
        author = "Detection Pipeline"
        date = "2026-02-05"
        severity = "critical"
        mitre_attack = "T1574.002"
        family = "chrysalis"
        apt = "lotus_blossom"

    strings:
        $mz = {4D 5A}
        $export1 = "DllMain" ascii
        $export2 = "ServiceMain" ascii

        // API resolution hashing (FNV-1a constants)
        $fnv_offset = {C5 9D 1C 81}  // 0x811C9DC5 little-endian
        $fnv_prime = {93 01 00 01}   // 0x1000193 little-endian
        $murmur = {6B CA EB 85}      // 0x85EBCA6B

        // Resolved DLLs
        $dll1 = "oleaut32.dll" ascii nocase
        $dll2 = "advapi32.dll" ascii nocase
        $dll3 = "wininet.dll" ascii nocase
        $dll4 = "shlwapi.dll" ascii nocase

        // Hidden directory
        $path1 = "\\Bluetooth\\" ascii wide
        $path2 = "BluetoothService" ascii wide

    condition:
        $mz at 0 and
        filesize < 2MB and
        (
            (any of ($fnv*) and $murmur) or
            (3 of ($dll*) and any of ($path*)) or
            (any of ($export*) and any of ($path*))
        )
}

rule chrysalis_tcc_loader {
    meta:
        description = "Detects Chrysalis TCC-based code execution component"
        author = "Detection Pipeline"
        date = "2026-02-05"
        severity = "critical"
        mitre_attack = "T1059,T1620"
        family = "chrysalis"
        apt = "lotus_blossom"

    strings:
        $mz = {4D 5A}

        // TCC indicators
        $tcc1 = "libtcc" ascii wide
        $tcc2 = "-nostdlib" ascii wide
        $tcc3 = "-run" ascii wide
        $tcc4 = "conf.c" ascii wide

        // Loader paths
        $path1 = "C:\\ProgramData\\USOShared\\" ascii wide
        $path2 = "svchost.exe" ascii wide

        // Warbird
        $warbird1 = "WbHeapExecuteCall" ascii
        $warbird2 = "clipc.dll" ascii wide

        // NtQuerySystemInformation with 0xB9
        $ntquery = {B9 00 00 00}  // parameter 0xB9

    condition:
        $mz at 0 and
        filesize < 3MB and
        (
            (2 of ($tcc*)) or
            ($path1 and $path2) or
            (any of ($warbird*)) or
            ($ntquery and any of ($tcc*))
        )
}

rule chrysalis_nsis_installer {
    meta:
        description = "Detects Chrysalis NSIS installer dropper"
        author = "Detection Pipeline"
        date = "2026-02-05"
        severity = "high"
        mitre_attack = "T1204.002,T1027"
        family = "chrysalis"
        apt = "lotus_blossom"

    strings:
        $nsis = "Nullsoft" ascii
        $nsis2 = "NSIS" ascii

        // Dropped files
        $drop1 = "BluetoothService.exe" ascii wide
        $drop2 = "log.dll" ascii wide
        $drop3 = "u.bat" ascii wide

        // Hidden directory creation
        $hidden = "\\AppData\\Roaming\\Bluetooth" ascii wide
        $attrib = "attrib +h" ascii wide

    condition:
        filesize < 10MB and
        any of ($nsis*) and
        (2 of ($drop*) or ($hidden and $attrib))
}
