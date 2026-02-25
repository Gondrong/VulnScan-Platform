import os, tempfile
import paramiko
from app.core.crypto import decrypt_str

def _write_temp_key(key_text: str) -> str:
    fd, path = tempfile.mkstemp(prefix="sshkey_", text=True)
    os.write(fd, key_text.encode("utf-8"))
    os.close(fd)
    os.chmod(path, 0o600)
    return path

def ssh_inventory(host: str, port: int, username: str, secret_type: str, secret_enc: str, passphrase_enc: str | None, timeout: float):
    secret = decrypt_str(secret_enc)
    passphrase = decrypt_str(passphrase_enc) if passphrase_enc else None

    pkey = None
    password = None
    key_path = None

    if secret_type == "password":
        password = secret
    else:
        key_path = _write_temp_key(secret)
        pkey = paramiko.RSAKey.from_private_key_file(key_path, password=passphrase)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host, port=port, username=username,
        password=password, pkey=pkey,
        timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
        look_for_keys=False, allow_agent=False
    )

    def cmd(c: str) -> str:
        stdin, stdout, stderr = client.exec_command(c, timeout=timeout)
        out = (stdout.read() or b"").decode("utf-8", errors="ignore")
        err = (stderr.read() or b"").decode("utf-8", errors="ignore")
        return (out + "\n" + err).strip()

    os_release = cmd("cat /etc/os-release 2>/dev/null || true")
    uname = cmd("uname -a 2>/dev/null || true")
    dpkg = cmd("dpkg-query -W -f='${Package}\\t${Version}\\n' 2>/dev/null | head -n 5000 || true")
    rpm  = cmd("rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n' 2>/dev/null | head -n 5000 || true")
    apk  = cmd("apk info -v 2>/dev/null | head -n 5000 || true")

    client.close()

    if key_path:
        try: os.remove(key_path)
        except: pass

    return {"os_release": os_release, "uname": uname, "dpkg": dpkg, "rpm": rpm, "apk": apk}
