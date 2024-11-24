rule RAT_Unknown_Sample {

    meta:
        last_updated = "20224-11-24"
        author = "PMAT"
        description = "Rule for PMAT example \"RAT.Unknown.exe\""

    strings:
        $pe_magic_bytes = { 4D 5A }
        $no_soup_string = "NO SOUP FOR YOU"
        $payload_server_name = "serv1.ec2-102-95-13-2-ubuntu.local"

    condition:
        $pe_magic_bytes at 0 and  // must be a PE
        $no_soup_string and       // contains the "NO SOUP" message
        $payload_server_name      // payload download server
}