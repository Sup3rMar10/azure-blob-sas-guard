"""Real Azurite instances for the enforcement tests: one over HTTPS (so tokens that demand https can be used) and one over plain HTTP.

Azurite is found on PATH (`npm install -g azurite`) or via AZURITE_JS (the path of azurite.js, run with node); openssl makes a
throwaway certificate. If either is missing the tests ERROR rather than skip: a suite that silently skips its only integration
layer proves nothing. Each run uses a freshly generated account key; nothing secret is committed.
"""

import base64
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass

import pytest
from azure.storage.blob import BlobServiceClient

ACCOUNT = "sasacct"


def azurite_command() -> list[str]:
    js = os.environ.get("AZURITE_JS")
    if js:
        return ["node", js]
    exe = shutil.which("azurite")
    if exe:
        return [exe]
    raise RuntimeError("Azurite was not found: run `npm install -g azurite` or set AZURITE_JS to the path of azurite.js")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class Azurite:
    scheme: str
    port: int
    key: str
    cert: str | None
    proc: subprocess.Popen

    @property
    def endpoint(self) -> str:
        return f"{self.scheme}://127.0.0.1:{self.port}/{ACCOUNT}"

    @property
    def conn(self) -> str:
        return f"DefaultEndpointsProtocol={self.scheme};AccountName={ACCOUNT};AccountKey={self.key};BlobEndpoint={self.endpoint};"

    def service(self) -> BlobServiceClient:
        return BlobServiceClient.from_connection_string(self.conn, **({"connection_verify": self.cert} if self.cert else {}))

    def fetch(self, url: str, method: str = "GET", data: bytes | None = None) -> tuple[int, bytes]:
        headers = {"x-ms-version": "2023-11-03", **({"x-ms-blob-type": "BlockBlob"} if method == "PUT" else {})}
        req = urllib.request.Request(url, method=method, data=data, headers=headers)
        ctx = ssl.create_default_context(cafile=self.cert) if self.cert else None
        try:
            with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()


def start(scheme: str) -> Azurite:
    tmp = tempfile.mkdtemp(prefix="azurite-")
    key = base64.b64encode(os.urandom(64)).decode()
    ports = {n: free_port() for n in ("blob", "queue", "table")}
    cmd = [*azurite_command(), "--silent", "--location", tmp, "--skipApiVersionCheck",
           *[a for n, p in ports.items() for a in (f"--{n}Port", str(p), f"--{n}Host", "127.0.0.1")]]
    cert = None
    if scheme == "https":
        cert, k = os.path.join(tmp, "cert.pem"), os.path.join(tmp, "key.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", k, "-out", cert, "-subj", "/CN=127.0.0.1",
                        "-days", "1", "-addext", "subjectAltName=IP:127.0.0.1"], check=True, capture_output=True)
        cmd += ["--cert", cert, "--key", k]
    proc = subprocess.Popen(cmd, env={**os.environ, "AZURITE_ACCOUNTS": f"{ACCOUNT}:{key}"}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 30
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"Azurite exited early with code {proc.returncode}")
        try:
            socket.create_connection(("127.0.0.1", ports["blob"]), timeout=0.2).close()
            return Azurite(scheme, ports["blob"], key, cert, proc)
        except OSError:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("Azurite did not start listening in time")


def stop(a: Azurite) -> None:
    a.proc.terminate()
    try:
        a.proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        a.proc.kill()


@pytest.fixture(scope="session")
def az():
    a = start("https")
    yield a
    stop(a)


@pytest.fixture(scope="session")
def az_http():
    a = start("http")
    yield a
    stop(a)


def make_container(a: Azurite) -> str:
    name = f"c-{uuid.uuid4().hex[:10]}"
    client = a.service().create_container(name)
    client.upload_blob("a.txt", b"AAA")
    client.upload_blob("b.txt", b"BBB")
    return name


@pytest.fixture()
def container(az):
    return make_container(az)


@pytest.fixture()
def container_http(az_http):
    return make_container(az_http)
