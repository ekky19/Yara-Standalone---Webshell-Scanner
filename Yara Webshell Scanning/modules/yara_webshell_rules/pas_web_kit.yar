rule pas_web_kit
{
    meta:
        description = "PAS Web Kit Webshell"
        family = "PHP.PAS"
        filetype = "PHP"

    strings:
        $eval_cmd = "eval($_POST['cmd']);"
        $auth_check = "$_POST[\"pass\"] == \"secret\""

    condition:
        all of them
}
