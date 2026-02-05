/*
 * LokiBot File Indicators
 * Information stealer targeting credentials and cryptocurrency wallets
 * References: MITRE T1555, T1539, T1041
 */

rule lokibot_stealer_strings {
    meta:
        description = "Detects LokiBot stealer based on embedded strings"
        author = "Detection Pipeline"
        date = "2026-02-05"
        severity = "critical"
        mitre_attack = "T1555,T1539"
        family = "lokibot"

    strings:
        $mz = {4D 5A}
        $loki1 = "Loki" ascii wide nocase
        $loki2 = "lokibot" ascii wide nocase
        $panel = "/fre.php" ascii wide
        $panel2 = "/PvqDq929BSx_A_D_M1n_a.php" ascii wide
        $browser1 = "\\Google\\Chrome\\User Data" ascii wide
        $browser2 = "\\Mozilla\\Firefox\\Profiles" ascii wide
        $browser3 = "\\Opera Software\\Opera Stable" ascii wide
        $wallet1 = "wallet.dat" ascii wide
        $wallet2 = "Electrum" ascii wide
        $wallet3 = "Ethereum" ascii wide
        $ftp1 = "FileZilla" ascii wide
        $ftp2 = "WinSCP" ascii wide
        $ftp3 = "CoreFTP" ascii wide
        $mail1 = "Thunderbird" ascii wide
        $mail2 = "Outlook" ascii wide
        $steam = "\\Steam\\config" ascii wide

    condition:
        $mz at 0 and
        filesize < 2MB and
        (
            any of ($loki*) or
            any of ($panel*) or
            (3 of ($browser*)) or
            (2 of ($wallet*)) or
            (2 of ($ftp*) and any of ($browser*)) or
            (any of ($mail*) and any of ($browser*))
        )
}

rule lokibot_http_exfil_pattern {
    meta:
        description = "Detects LokiBot HTTP exfiltration patterns"
        author = "Detection Pipeline"
        date = "2026-02-05"
        severity = "high"
        mitre_attack = "T1041,T1071.001"
        family = "lokibot"

    strings:
        $mz = {4D 5A}
        $http1 = "POST " ascii
        $http2 = "Content-Type:" ascii
        $http3 = "application/octet-stream" ascii
        $http4 = "User-Agent:" ascii
        $ua1 = "Mozilla/4.0" ascii
        $ua2 = "Mozilla/5.0" ascii
        $header1 = "HWID=" ascii
        $header2 = "ession=" ascii
        $header3 = "Content-Length:" ascii
        $api1 = "WinHttpOpen" ascii
        $api2 = "WinHttpConnect" ascii
        $api3 = "WinHttpSendRequest" ascii
        $api4 = "InternetOpenA" ascii
        $api5 = "HttpSendRequestA" ascii

    condition:
        $mz at 0 and
        filesize < 2MB and
        (3 of ($http*)) and
        (any of ($ua*)) and
        (any of ($header*) or 2 of ($api*))
}

rule lokibot_credential_harvesting {
    meta:
        description = "Detects LokiBot credential harvesting capability"
        author = "Detection Pipeline"
        date = "2026-02-05"
        severity = "critical"
        mitre_attack = "T1555.003,T1555.004"
        family = "lokibot"

    strings:
        $mz = {4D 5A}
        $sql1 = "SELECT " ascii nocase
        $sql2 = "FROM logins" ascii nocase
        $sql3 = "password_value" ascii nocase
        $sql4 = "origin_url" ascii nocase
        $cred1 = "CryptUnprotectData" ascii
        $cred2 = "vaultcli.dll" ascii
        $cred3 = "CredEnumerate" ascii
        $reg1 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles" ascii
        $reg2 = "Software\\Microsoft\\Office\\Outlook" ascii
        $file1 = "logins.json" ascii
        $file2 = "signons.sqlite" ascii
        $file3 = "Login Data" ascii

    condition:
        $mz at 0 and
        filesize < 3MB and
        (
            (2 of ($sql*)) or
            (2 of ($cred*)) or
            (any of ($reg*)) or
            (2 of ($file*) and any of ($cred*))
        )
}
