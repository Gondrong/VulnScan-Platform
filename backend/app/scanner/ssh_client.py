"""
SSH client for authenticated inventory scans.
Supports RSA, Ed25519, ECDSA, and DSS key types.
"""
import io
import os
import tempfile
import logging

import paramiko
from app.core.crypto import decrypt_str

logger = logging.getLogger("vulnscan.ssh")


def _load_pkey(key_text: str, passphrase: str | None = None) -> paramiko.PKey:
    """
    Auto-detect and load an SSH private key.
    Tries Ed25519, ECDSA, RSA, DSS in order.
    """
    key_classes = [
        ("Ed25519", paramiko.Ed25519Key),
        ("ECDSA", paramiko.ECDSAKey),
        ("RSA", paramiko.RSAKey),
        ("DSS", paramiko.DSSKey),
    ]

    last_err = None
    for name, cls in key_classes:
        try:
            key_file = io.StringIO(key_text)
            return cls.from_private_key(key_file, password=passphrase)
        except paramiko.ssh_exception.SSHException:
            continue
        except Exception as e:
            last_err = e
            continue

    # If in-memory parsing failed, try writing to temp file (some key formats need it)
    fd, path = tempfile.mkstemp(prefix="sshkey_", text=True)
    try:
        os.write(fd, key_text.encode("utf-8"))
        os.close(fd)
        os.chmod(path, 0o600)

        for name, cls in key_classes:
            try:
                return cls.from_private_key_file(path, password=passphrase)
            except paramiko.ssh_exception.SSHException:
                continue
            except Exception as e:
                last_err = e
                continue
    finally:
        try:
            os.remove(path)
        except Exception:
            pass

    raise paramiko.ssh_exception.SSHException(
        f"Unable to parse SSH key — tried Ed25519, ECDSA, RSA, DSS. "
        f"Last error: {last_err}"
    )


def ssh_inventory(
    host: str,
    port: int,
    username: str,
    secret_type: str,
    secret_enc: str,
    passphrase_enc: str | None,
    timeout: float,
) -> dict:
    """
    Connect via SSH and collect OS + package inventory.
    Returns dict with keys: os_release, uname, dpkg, rpm, apk.
    """
    # Decrypt credentials
    try:
        secret = decrypt_str(secret_enc)
    except (ValueError, Exception) as e:
        raise RuntimeError(
            f"Cannot decrypt SSH credential — the SECRET_KEY may have changed "
            f"since this credential was saved. Delete the credential and re-add it "
            f"in the Credentials page. Detail: {e}"
        )

    passphrase = None
    if passphrase_enc:
        try:
            passphrase = decrypt_str(passphrase_enc)
        except Exception:
            pass  # passphrase may not be set

    pkey = None
    password = None

    if secret_type == "password":
        password = secret
    else:
        # Auto-detect key type
        pkey = _load_pkey(secret, passphrase)
        logger.info("Loaded SSH key type: %s", type(pkey).__name__)

    # Use reasonable timeouts (at least 15s for SSH)
    ssh_timeout = max(timeout, 15.0)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            pkey=pkey,
            timeout=ssh_timeout,
            banner_timeout=ssh_timeout,
            auth_timeout=ssh_timeout,
            look_for_keys=False,
            allow_agent=False,
        )
    except paramiko.AuthenticationException as e:
        raise RuntimeError(
            f"SSH authentication failed for {username}@{host}:{port} — "
            f"check username, key type, and passphrase. Error: {e}"
        )
    except paramiko.SSHException as e:
        raise RuntimeError(f"SSH connection error to {host}:{port}: {e}")
    except Exception as e:
        raise RuntimeError(f"Cannot connect to {host}:{port}: {e}")

    def cmd(c: str) -> str:
        try:
            stdin, stdout, stderr = client.exec_command(c, timeout=ssh_timeout)
            out = (stdout.read() or b"").decode("utf-8", errors="ignore")
            err = (stderr.read() or b"").decode("utf-8", errors="ignore")
            return (out + "\n" + err).strip()
        except Exception:
            return ""

    try:
        os_release = cmd("cat /etc/os-release 2>/dev/null || true")
        uname = cmd("uname -a 2>/dev/null || true")
        dpkg = cmd(
            "dpkg-query -W -f='${Package}\\t${Version}\\n' 2>/dev/null | head -n 5000 || true"
        )
        rpm = cmd(
            "rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n' 2>/dev/null | head -n 5000 || true"
        )
        apk = cmd("apk info -v 2>/dev/null | head -n 5000 || true")
    finally:
        client.close()

    return {
        "os_release": os_release,
        "uname": uname,
        "dpkg": dpkg,
        "rpm": rpm,
        "apk": apk,
    }
