rule generic_jsp_shell
{
    meta:
        description = "Generic JSP Webshell with exec()"
        family = "JSP.Generic"
        filetype = "JSP"

    strings:
        $jsp1 = "Runtime.getRuntime().exec(cmd);"
        $jsp2 = "request.getParameter(\"cmd\")"

    condition:
        all of them
}