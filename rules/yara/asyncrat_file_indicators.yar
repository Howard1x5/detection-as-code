/*
    AsyncRAT/VenomRAT File Indicators
    Author: Clint Howard
    Date: 2026-02-05

    Detection rules for AsyncRAT family based on known file artifacts,
    strings, and code patterns. These rules target the .NET-based RAT
    commonly used in phishing campaigns.

    References:
    - https://malpedia.caad.fkie.fraunhofer.de/details/win.asyncrat
    - https://attack.mitre.org/software/S0379/
*/

rule AsyncRAT_Strings_Generic {
    meta:
        description = "Detects AsyncRAT/VenomRAT based on characteristic strings"
        author = "Clint Howard"
        date = "2026-02-05"
        family = "AsyncRAT"
        severity = "high"
        mitre_attack = "T1219"
        confidence = "high"
        false_positives = "Unlikely - strings are specific to AsyncRAT"

    strings:
        // Class and namespace indicators
        $class1 = "AsyncClient" ascii wide
        $class2 = "ClientSocket" ascii wide
        $class3 = "Anti_Analysis" ascii wide
        $class4 = "HandlePacket" ascii wide

        // Configuration-related strings
        $config1 = "YOURPASSWORD" ascii wide  // Default stub password
        $config2 = "AsyncMutex" ascii wide
        $config3 = "VenomRAT" ascii wide
        $config4 = "ClientOnline" ascii wide

        // Capability indicators
        $cap1 = "keylogger" ascii wide nocase
        $cap2 = "screencapture" ascii wide nocase
        $cap3 = "filemanager" ascii wide nocase
        $cap4 = "ProcessList" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (2 of ($class*)) or
            (any of ($config*) and 1 of ($cap*)) or
            ($config3)  // VenomRAT string is highly specific
        )
}

rule AsyncRAT_AES_Config {
    meta:
        description = "Detects AsyncRAT encrypted configuration pattern"
        author = "Clint Howard"
        date = "2026-02-05"
        family = "AsyncRAT"
        severity = "high"
        mitre_attack = "T1573.001"
        confidence = "medium"
        false_positives = "Other .NET applications using base64 AES keys"

    strings:
        // Base64-encoded AES key pattern (256-bit = 44 chars with padding)
        $aes_key = /[A-Za-z0-9+\/]{43}=/ ascii

        // .NET crypto indicators
        $crypto1 = "RijndaelManaged" ascii wide
        $crypto2 = "AesCryptoServiceProvider" ascii wide
        $crypto3 = "FromBase64String" ascii wide

        // AsyncRAT-specific combo
        $stub = "Stub" ascii wide
        $client = "Client" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        $aes_key and
        (1 of ($crypto*)) and
        ($stub or $client)
}

rule AsyncRAT_AntiAnalysis {
    meta:
        description = "Detects AsyncRAT anti-analysis/evasion techniques"
        author = "Clint Howard"
        date = "2026-02-05"
        family = "AsyncRAT"
        severity = "high"
        mitre_attack = "T1497,T1082"
        confidence = "medium"
        false_positives = "Legitimate security tools with VM detection"

    strings:
        // VM detection strings
        $vm1 = "vmware" ascii wide nocase
        $vm2 = "virtualbox" ascii wide nocase
        $vm3 = "VIRTUAL" ascii wide
        $vm4 = "Sandboxie" ascii wide
        $vm5 = "SbieDll.dll" ascii wide

        // Debugger detection
        $dbg1 = "IsDebuggerPresent" ascii wide
        $dbg2 = "CheckRemoteDebuggerPresent" ascii wide

        // Process checks (sandbox detection)
        $proc1 = "wireshark" ascii wide nocase
        $proc2 = "fiddler" ascii wide nocase
        $proc3 = "processhacker" ascii wide nocase
        $proc4 = "procmon" ascii wide nocase

        // AsyncRAT class indicator
        $class = "Anti_Analysis" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            ($class and (2 of ($vm*) or 2 of ($proc*))) or
            (3 of ($vm*) and 2 of ($proc*) and 1 of ($dbg*))
        )
}

rule AsyncRAT_Network_Config {
    meta:
        description = "Detects AsyncRAT network configuration patterns"
        author = "Clint Howard"
        date = "2026-02-05"
        family = "AsyncRAT"
        severity = "high"
        mitre_attack = "T1071.001,T1571"
        confidence = "medium"
        false_positives = "Applications using similar port configurations"

    strings:
        // Default AsyncRAT ports
        $port1 = "6606" ascii wide
        $port2 = "7707" ascii wide
        $port3 = "8808" ascii wide
        $port4 = "4449" ascii wide  // Alternative common port

        // Connection-related strings
        $conn1 = "TcpClient" ascii wide
        $conn2 = "SslStream" ascii wide
        $conn3 = "NetworkStream" ascii wide
        $conn4 = "BeginConnect" ascii wide

        // AsyncRAT-specific
        $async1 = "AsyncClient" ascii wide
        $async2 = "ClientSocket" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (1 of ($port*)) and
        (2 of ($conn*)) and
        (1 of ($async*))
}
