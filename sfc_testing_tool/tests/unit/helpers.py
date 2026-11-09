from sfc_tool.infrastructure.settings import Settings

NS = "http://example.invalid/sfc/"          # fake, non-corporate
SETTINGS = Settings(
    environment="QA", endpoint_url="http://qa-host.invalid/svc.asmx",
    allowed_hosts=["qa-host.invalid"], xml_namespace=NS,
    soap_action_base=NS, host_header="qa-host.invalid",
    connect_retries=1)


def soap_ok(method, text):
    return ('<?xml version="1.0" encoding="utf-8"?>'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soap:Body><%sResponse xmlns="%s"><%sResult>%s</%sResult></%sResponse>'
            '</soap:Body></soap:Envelope>' % (method, NS, method, text, method, method))


FAULT = ('<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
         '<soap:Body><soap:Fault><faultcode>soap:Server</faultcode>'
         '<faultstring>Boom</faultstring></soap:Fault></soap:Body></soap:Envelope>')


class FakeResponse:
    def __init__(self, status=200, body="", encoding="utf-8"):
        self.status_code = status
        self.content = body.encode("utf-8")
        self.encoding = encoding
        self.text = body


class FakeSession:
    """Scripted session: each item is a FakeResponse or an exception to raise."""
    def __init__(self, *script):
        self.script = list(script)
        self.calls = []

    def post(self, url, **kw):
        self.calls.append((url, kw))
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def close(self):
        pass
