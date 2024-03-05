rule agenttesla_detector {
    meta:
        author = "psy_maestro"
        date = "18/Feb/2024"
        description = "Detects AgentTesla"
        SHA256 = "e9c028ecb36a6fb2e3a9f2ce8e58fa444649dd3c47039765cca1967dcc99ef3b"
    strings:
        $anti_analysis1 = "cmdvrt32.dll" wide
        $anti_analysis2 = "snxhk.dll" wide
        $anti_analysis3 = "SxIn.dll" wide
        $anti_analysis4 = "Sf2.dll" wide
        $anti_analysis5 = "SbieDll.dll" wide

        $stealer1 = "Login Data" wide
        $stealer2 = "logins" wide
        $stealer3 = "\\User Data" wide
        $stealer4 = "autofill" wide
    condition:
        uint16(0) == 0x5A4D and //looks for MZ at 0x00
        uint32(uint32(0x3C)) == 0x00004550 and // PE at 0x3C
        all of them
}
