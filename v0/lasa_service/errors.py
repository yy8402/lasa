"""Safe RFC 9457 failures shared by controllers, HTTP, and execution."""


class LasaError(Exception):
    def __init__(self, code, status=400, *, retry="never", effect="none"):
        super().__init__(code)
        self.code, self.status, self.retry, self.effect = code, status, retry, effect

    def public(self):
        return {
            "type": "https://errors.lasa.example/" + self.code.replace("_", "-"),
            "title": self.code.replace("_", " ").capitalize(),
            "status": self.status,
            "detail": "The operation could not satisfy the service contract.",
            "instance": "urn:lasa:request",
            "code": self.code,
            "retry": self.retry,
            "effect_disposition": self.effect,
        }
