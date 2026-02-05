/*
   YARA Rule: EICAR Test Pattern
   Description: Detects the EICAR antivirus test file pattern
   Author: Detection Pipeline Project
   Date: 2026-02-04
   Reference: https://www.eicar.org/download-anti-malware-testfile/
*/

rule EICAR_Test_File {
    meta:
        description = "Detects EICAR antivirus test file"
        author = "Detection Pipeline"
        date = "2026-02-04"
        reference = "https://www.eicar.org/"
        severity = "low"
        category = "test"

    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii wide
        $eicar_full = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR" ascii

    condition:
        any of them
}

rule EICAR_Test_File_Hash {
    meta:
        description = "Detects EICAR test file by known hash patterns"
        author = "Detection Pipeline"
        date = "2026-02-04"

    condition:
        // Standard EICAR SHA256
        hash.sha256(0, filesize) == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" or
        // Our test variant
        hash.sha256(0, filesize) == "38fe0839ebc448b226e226edcec3d9614301c2a5805887c7df648dfba4596e78"
}
