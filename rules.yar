rule Fake_Malware_Detected {
    meta:
        description = "Detecta um arquivo de teste que simula comportamento malicioso"
        author = "Arthur"
    strings:
        $magic_word = "EVIL_CORP_MALWARE"
        $hex_pattern = { E2 43 53 5A }
    condition:
        $magic_word or $hex_pattern
}