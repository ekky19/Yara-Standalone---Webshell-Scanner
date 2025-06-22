rule hidden_iframe_loader
{
    meta:
        description = "Hidden iframe JavaScript loader"
        family = "Web.Injector"
        filetype = "HTML"

    strings:
        $iframe = "<iframe src=\"http://malicious-domain.com/evil.js\" style=\"display:none;\">"

    condition:
        $iframe
}