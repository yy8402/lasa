import asyncio
import ipaddress
import socket
from contextlib import asynccontextmanager, nullcontext
from datetime import UTC, datetime, timedelta

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def certificate(root, *, dns_name=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_name or "LASA test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(dns_name)]
                if dns_name
                else [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = root / "certificate.pem"
    key_path = root / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    return cert_path, key_path


@asynccontextmanager
async def live_http(app, *, tls=None):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(16)
    sock.setblocking(False)
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            log_level="critical",
            lifespan="off",
            access_log=False,
            ssl_certfile=str(tls[0]) if tls else None,
            ssl_keyfile=str(tls[1]) if tls else None,
        )
    )
    server.capture_signals = nullcontext
    worker = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        for _ in range(100):
            if server.started:
                break
            await asyncio.sleep(0.01)
        assert server.started
        yield f"{'https' if tls else 'http'}://127.0.0.1:{sock.getsockname()[1]}"
    finally:
        server.should_exit = True
        async with asyncio.timeout(3):
            await worker
        sock.close()
