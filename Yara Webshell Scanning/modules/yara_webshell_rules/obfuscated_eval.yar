rule obfuscated_eval
{
    meta:
        description = "Obfuscated eval via variable concatenation"
        family = "PHP.Obfuscated"
        filetype = "PHP"

    strings:
        $pattern = "$a = \"eva\".\"l\"; $a($_REQUEST['cmd']);"

    condition:
        $pattern
}