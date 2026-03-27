rule Win32_Spyware_Bowser {
    meta:
        description = "Détecte le Stealer Bowser (Python)"
        author = "Yaiito"
    strings:
        $a = "duckdns" ascii
        $b = "bowser" ascii
        $c = "pynput" ascii
    condition:
        any of them
}