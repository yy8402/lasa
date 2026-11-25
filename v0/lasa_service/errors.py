"""Safe RFC 9457 failures shared by controllers, HTTP, and execution."""


class LasaError(Exception):
    def __init__(
        self,
        code,
        status=400,
        *,
        retry="never",
        effect="none",
        instance="urn:lasa:request",
        detail=None,
    ):
        super().__init__(code)
        self.code, self.status, self.retry, self.effect = code, status, retry, effect
        self.instance, self.detail = instance, detail

    def public(self):
        return {
            "type": "https://errors.lasa.example/" + self.code.replace("_", "-"),
            "title": self.code.replace("_", " ").capitalize(),
            "status": self.status,
            "detail": self.detail or "The operation could not satisfy the service contract.",
            "instance": self.instance,
            "code": self.code,
            "retry": self.retry,
            "effect_disposition": self.effect,
        }
