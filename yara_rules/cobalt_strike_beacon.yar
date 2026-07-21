/*
    Cobalt Strike Beacon detection rules.

    Coverage notes:
    - These are heuristic, string/structure-based indicators drawn from
      publicly documented Cobalt Strike internals (named pipe naming
      conventions, default HTTP/HTTPS beacon artifacts, and the beacon
      config's known single-byte XOR obfuscation). They are NOT exact
      byte-for-byte signatures of a specific CS version/build and will
      need tuning against real samples in your environment - Cobalt
      Strike's malleable C2 profiles let operators change or strip most
      of these strings, so a miss here is not proof of absence.
    - Named-pipe and default XOR-key indicators are widely referenced in
      public research (e.g. community "beacon config" parsers use 0x69
      and 0x2e as the default single-byte XOR keys for the raw config
      blob prior to metadata/version-specific obfuscation changes).
    - Combine with process/network behavior detections (sleep-mask
      patterns, injected-thread heuristics, JA3/JA3S, malleable-profile
      URI/header matching) rather than relying on this file alone.
*/

import "pe"

rule C2_Win_CobaltStrikeBeacon_NamedPipes
{
    meta:
        description = "Detects default/near-default Cobalt Strike Beacon named pipe naming patterns used for SMB beacon and inter-process communication"
        author = "detection-engineering-lab"
        date = "2026-07-20"
        reference = "https://www.cobaltstrike.com/help-smb-beacon"
        confidence = "medium"

    strings:
        $pipe1 = "\\\\.\\pipe\\msagent_" ascii
        $pipe2 = "\\\\.\\pipe\\status_" ascii
        $pipe3 = "\\\\.\\pipe\\MSSE-" ascii
        $pipe4 = "\\\\.\\pipe\\postex_" ascii
        $pipe5 = "\\\\.\\pipe\\mypipe-f" ascii

    condition:
        any of them
}

rule C2_Win_CobaltStrikeBeacon_HTTPArtifacts
{
    meta:
        description = "Detects default Cobalt Strike HTTP(S) beacon artifacts commonly left in place when operators don't fully customize a malleable C2 profile"
        author = "detection-engineering-lab"
        date = "2026-07-20"
        reference = "https://www.cobaltstrike.com/help-malleable-c2"
        confidence = "low"

    strings:
        $ua1 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" ascii
        // Contains a %d format placeholder (FP-prone per linter); mitigated
        // by requiring 2-of-N below rather than matching on this string alone.
        $hdr1 = "Content-Length: %d\r\n\r\n" ascii
        $marker1 = "beacon.dll" ascii nocase
        $marker2 = "beacon.x64.dll" ascii nocase
        // Contains a %s format placeholder (FP-prone per linter); same
        // 2-of-N mitigation as $hdr1.
        $marker3 = "%s (admin)" ascii
        $marker4 = "ReflectiveLoader" ascii

    condition:
        2 of them
}

rule C2_Win_CobaltStrikeBeacon_ConfigXOR
{
    meta:
        description = "Detects the byte pattern produced by the classic single-byte XOR (0x69 or 0x2e) obfuscation of a Cobalt Strike Beacon config's leading type/length header fields"
        author = "detection-engineering-lab"
        date = "2026-07-20"
        reference = "https://github.com/Sentinel-One/CobaltStrikeParser"
        confidence = "medium"

    strings:
        // Decoded header is 00 01 00 01 00 02 (three big-endian type/value
        // uint16 fields); these are that sequence XORed with each
        // candidate single-byte key.
        $xor69 = { 69 68 69 68 69 6B }
        $xor2e = { 2E 2F 2E 2F 2E 2C }

    condition:
        any of them
}

rule C2_Win_CobaltStrikeBeacon_Combined
{
    meta:
        description = "Detects Cobalt Strike Beacon with higher confidence by requiring both a beacon config XOR pattern and at least one independent artifact (named pipe or HTTP artifact) in the same sample"
        author = "detection-engineering-lab"
        date = "2026-07-20"
        reference = "https://attack.mitre.org/software/S0154/"
        confidence = "high"

    condition:
        C2_Win_CobaltStrikeBeacon_ConfigXOR
        and (C2_Win_CobaltStrikeBeacon_NamedPipes or C2_Win_CobaltStrikeBeacon_HTTPArtifacts)
}
