rule pbot_backdoor
{
    meta:
        description = "PBot style system backdoor"
        family = "PHP.PBot"
        filetype = "PHP"

    strings:
        $syscall = "system($_GET['cmd']);"

    condition:
        $syscall
}