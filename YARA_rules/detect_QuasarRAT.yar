rule quasarRAT_detector {
 meta:
  author = "psy_maestro"
  date = "10/Feb/2024"
  description = "Detects QuasarRAT"
 strings:
     $str1 = "<p class=\"h\">[{0}" wide
     $str2 = "<p class=\"h\">[Enter]</p><br>" wide
     $str3 = "<p class=\"h\">[Esc]</p>" wide
     $str4 = "<meta http-equiv='Content-Type' content='text/html; charset=utf-8' />Log created on " wide
     $str5 = "<style>.h { color: 0000ff; display: inline; }</style>" wide
     $str6 = ":Zone.Identifier" wide
     $str7 = "echo DONT CLOSE THIS WINDOW!" wide
     $str8 = "Uninstalling... bye ;(" wide
 condition:
  uint16(0) == 0x5A4D and //looks for MZ at 0x00
  uint32(uint32(0x3C)) == 0x00004550 and // PE at 0x3C
  all of them
}
