"""
MQTT Anonymous Access & Security Scanner
Tests for unauthenticated MQTT access, weak credentials, full topic enumeration,
publish injection, and protocol-level security issues.

Uses paho-mqtt for robust MQTT protocol handling.
Based on team PoC: aggressive wildcard subscriptions + publish injection testing.
"""
import asyncio
import logging
import time
import ssl as _ssl

import paho.mqtt.client as mqtt

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.mqtt")

META = PluginMeta(
    plugin_id="iot.mqtt_scanner",
    name="MQTT Anonymous Access & Security",
    category="iot",
    depends_on=["net.port.discovery.v2"],
    consumes=["net.open_ports"],
    provides=["iot.mqtt_findings"],
    enabled_by_default=True,
    timeout_seconds=60.0,  # Longer timeout for full topic enumeration
)

# ── MQTT Ports ──────────────────────────────────────────────────────────
_MQTT_PORTS = [1883, 8883, 1884, 8884, 9001]

# ── Default / weak credentials to test ──────────────────────────────────
_WEAK_CREDS = [
    ("", ""),                    # Anonymous (no credentials)
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("mqtt", "mqtt"),
    ("user", "user"),
    ("guest", "guest"),
    ("test", "test"),
    ("mosquitto", "mosquitto"),
    ("iot", "iot"),
    ("device", "device"),
    ("public", "public"),
    ("root", "root"),
    ("admin", "1234"),
    ("pi", "raspberry"),
    ("user", "password"),
]

# ── Aggressive wildcard subscriptions (from team PoC) ───────────────────
_ENUM_WILDCARDS = [
    "#",                         # ALL topics (global wildcard)
    "$SYS/#",                    # Broker system stats
    "$share/group/#",            # Shared subscription wildcard
    "/#",                        # Root-level wildcard
    "+/+/+",                     # Three-level wildcard
    "+/+/#",                     # Two-level prefix + deep wildcard
    "+/#",                       # Single-level prefix + deep wildcard
    "+/+/+/+",                   # Four-level wildcard
]

# ── Common topic prefixes to probe ──────────────────────────────────────
_COMMON_TOPIC_PREFIXES = [
    "sensor/#", "device/#", "home/#", "iot/#", "data/#",
    "telemetry/#", "command/#", "status/#", "alert/#",
    "control/#", "config/#", "firmware/#", "update/#",
    "users/#", "system/#", "chat/#", "notification/#",
    "camera/#", "gps/#", "location/#", "energy/#",
]

# ── Topics to test publish injection ────────────────────────────────────
_INJECTION_TOPICS = [
    "users/status",
    "system/broadcast",
    "chat/global",
    "commands/execute",
    "device/control",
    "admin/command",
    "config/update",
    "firmware/push",
    "alert/trigger",
    "$SYS/broker/connection/vulnscan/state",
]

# ── CONNACK return codes ────────────────────────────────────────────────
_CONNACK_CODES = {
    0: "Connection Accepted",
    1: "Unacceptable Protocol Version",
    2: "Identifier Rejected",
    3: "Server Unavailable",
    4: "Bad Username/Password",
    5: "Not Authorized",
}


class MQTTProbe:
    """
    Synchronous MQTT probe using paho-mqtt.
    Designed to be run via asyncio.to_thread() from the async plugin.
    """

    def __init__(self, host: str, port: int, username: str = "",
                 password: str = "", use_tls: bool = False, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.timeout = timeout

        self.connected = False
        self.connect_rc = -1
        self.messages: list[dict] = []
        self.subscribed_topics: set[str] = set()
        self.publish_acks: list[str] = []

        self.client = mqtt.Client(
            client_id=f"vulnscan_{port}_{int(time.time()) % 10000}",
            clean_session=True,
        )

        # Set credentials if provided
        if username:
            self.client.username_pw_set(username, password)

        # TLS for port 8883
        if use_tls or port in (8883, 8884):
            self.client.tls_set(cert_reqs=_ssl.CERT_NONE)
            self.client.tls_insecure_set(True)

        # Callbacks
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.client.on_subscribe = self._on_subscribe
        self.client.on_publish = self._on_publish

    def _on_connect(self, client, userdata, flags, rc):
        self.connect_rc = rc
        if rc == 0:
            self.connected = True

    def _on_message(self, client, userdata, msg):
        payload_str = msg.payload.decode("utf-8", errors="ignore")[:200]
        self.messages.append({
            "topic": msg.topic,
            "payload": payload_str,
            "qos": msg.qos,
            "retain": msg.retain,
            "payload_len": len(msg.payload),
        })

    def _on_subscribe(self, client, userdata, mid, granted_qos):
        pass

    def _on_publish(self, client, userdata, mid):
        self.publish_acks.append(str(mid))

    def connect_test(self) -> tuple[bool, int]:
        """Test if connection succeeds. Returns (connected, return_code)."""
        try:
            self.client.connect(self.host, self.port, keepalive=30)
            self.client.loop_start()

            deadline = time.time() + self.timeout
            while self.connect_rc == -1 and time.time() < deadline:
                time.sleep(0.1)

            return self.connected, self.connect_rc
        except Exception as e:
            logger.debug(f"MQTT connect failed: {e}")
            return False, -1

    def enumerate_topics(self, listen_seconds: float = 10.0) -> list[dict]:
        """
        Subscribe to aggressive wildcards and listen for messages.
        Based on team PoC: uses multiple wildcard patterns for maximum coverage.
        """
        if not self.connected:
            return []

        # Subscribe to all aggressive wildcards
        for topic in _ENUM_WILDCARDS:
            try:
                self.client.subscribe(topic, qos=0)
                self.subscribed_topics.add(topic)
            except Exception:
                pass

        # Also subscribe to common prefixes
        for topic in _COMMON_TOPIC_PREFIXES:
            try:
                self.client.subscribe(topic, qos=0)
                self.subscribed_topics.add(topic)
            except Exception:
                pass

        # Listen for messages
        time.sleep(listen_seconds)

        return self.messages

    def test_publish_injection(self) -> list[dict]:
        """
        Attempt to publish to sensitive topics without authorization.
        Based on team PoC: tests write access to control/admin topics.
        """
        if not self.connected:
            return []

        injection_results = []
        payload = "VULNSCAN_INJECTION_TEST"

        for topic in _INJECTION_TOPICS:
            try:
                result = self.client.publish(topic, payload, qos=1)
                # rc=0 means the publish was accepted by the client library
                # The broker may still reject it silently
                injection_results.append({
                    "topic": topic,
                    "rc": result.rc,
                    "mid": result.mid,
                    "accepted": result.rc == mqtt.MQTT_ERR_SUCCESS,
                })
            except Exception:
                pass

        # Wait for PUBACK responses
        time.sleep(2)

        # Check which publishes were acknowledged (mid in self.publish_acks)
        for r in injection_results:
            r["acked"] = str(r["mid"]) in self.publish_acks

        return injection_results

    def disconnect(self):
        """Clean disconnect."""
        try:
            self.client.loop_stop()
            self.client.disconnect()
        except Exception:
            pass


def _run_mqtt_probe(host: str, port: int, username: str = "",
                    password: str = "", use_tls: bool = False,
                    do_enum: bool = False, do_inject: bool = False,
                    listen_seconds: float = 10.0) -> dict:
    """
    Synchronous MQTT probe — runs in a thread.
    Returns a dict with all results.
    """
    probe = MQTTProbe(host, port, username, password, use_tls)
    result = {
        "host": host,
        "port": port,
        "username": username,
        "connected": False,
        "connect_rc": -1,
        "messages": [],
        "topics_discovered": [],
        "sys_topics": [],
        "injection_results": [],
        "subscribed_wildcards": [],
    }

    try:
        connected, rc = probe.connect_test()
        result["connected"] = connected
        result["connect_rc"] = rc

        if not connected:
            return result

        if do_enum:
            messages = probe.enumerate_topics(listen_seconds=listen_seconds)
            result["messages"] = messages
            result["subscribed_wildcards"] = list(probe.subscribed_topics)

            # Extract unique topics
            all_topics = list(set(m["topic"] for m in messages))
            sys_topics = [t for t in all_topics if t.startswith("$SYS/")]
            user_topics = [t for t in all_topics if not t.startswith("$SYS/")]

            result["topics_discovered"] = sorted(user_topics)
            result["sys_topics"] = sorted(sys_topics)

        if do_inject:
            result["injection_results"] = probe.test_publish_injection()

    except Exception as e:
        logger.debug(f"MQTT probe error: {e}")
    finally:
        probe.disconnect()

    return result


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        ports = ctx.get("net.open_ports", []) or []
        findings = []
        mqtt_results = []

        # ── Find MQTT ports ────────────────────────────────────────────
        mqtt_ports = [p for p in ports if p in _MQTT_PORTS]

        # Probe common MQTT ports if not discovered by port scan
        if not mqtt_ports:
            for p in [1883, 8883]:
                try:
                    result = await asyncio.to_thread(
                        _run_mqtt_probe, target, p,
                        do_enum=False, do_inject=False,
                    )
                    if result["connect_rc"] >= 0:
                        mqtt_ports.append(p)
                except Exception:
                    pass

        if not mqtt_ports:
            return PluginResult(artifacts={"iot.mqtt_findings": []})

        # ── Step 1: Test anonymous access + full enumeration ───────────
        for port in mqtt_ports:
            use_tls = port in (8883, 8884)

            # Anonymous connection + topic enumeration + injection test
            result = await asyncio.to_thread(
                _run_mqtt_probe, target, port,
                username="", password="",
                use_tls=use_tls,
                do_enum=True,
                do_inject=True,
                listen_seconds=10.0,
            )

            if result["connected"]:
                # ── Finding: Anonymous access ──────────────────────────
                fp = stable_fingerprint(target, META.plugin_id, "anonymous_access", str(port))
                findings.append(Finding(
                    severity="critical",
                    plugin_id=META.plugin_id,
                    title=f"MQTT anonymous access on port {port}",
                    description=(
                        f"The MQTT broker at {target}:{port} accepts connections without "
                        f"any authentication. Anyone can connect, subscribe to all topics, "
                        f"publish messages, and control IoT devices."
                    ),
                    evidence=(
                        f"host={target} port={port} auth=none connack=0 (accepted) "
                        f"tls={'yes' if use_tls else 'no'}"
                    ),
                    affected=target,
                    fingerprint=fp,
                    confidence=0.98,
                    remediation=(
                        f"[CRITICAL] MQTT broker accepts anonymous connections on port {port}\n\n"
                        f"[IMMEDIATE ACTION]\n"
                        f"1. Enable authentication in the MQTT broker\n"
                        f"2. Require username/password for all connections\n"
                        f"3. Use TLS (port 8883) for encrypted connections\n\n"
                        f"[MOSQUITTO CONFIG]\n"
                        f"  allow_anonymous false\n"
                        f"  password_file /etc/mosquitto/passwd\n"
                        f"  listener 8883\n"
                        f"  certfile /etc/mosquitto/certs/server.crt\n"
                        f"  keyfile /etc/mosquitto/certs/server.key\n\n"
                        f"[ALSO]\n"
                        f"- Implement ACLs to restrict topic access per user\n"
                        f"- Use client certificate authentication for IoT devices\n"
                        f"- Restrict broker to internal network (firewall rules)"
                    ),
                    references=[
                        "https://owasp.org/www-project-internet-of-things/",
                        "https://mosquitto.org/man/mosquitto-conf-5.html",
                    ],
                ))
                mqtt_results.append({
                    "port": port, "anonymous": True, "severity": "critical",
                    "topics_count": len(result["topics_discovered"]),
                    "sys_topics_count": len(result["sys_topics"]),
                    "messages_count": len(result["messages"]),
                })

                # ── Finding: Topic enumeration ─────────────────────────
                all_topics = result["topics_discovered"]
                sys_topics = result["sys_topics"]
                total_messages = len(result["messages"])

                if all_topics or sys_topics:
                    total_topics = len(all_topics) + len(sys_topics)
                    fp = stable_fingerprint(target, META.plugin_id, "topic_enum", str(port))

                    # Build detailed topic breakdown
                    topic_breakdown = ""
                    if all_topics:
                        topic_breakdown += f"[USER TOPICS] ({len(all_topics)})\n"
                        for t in all_topics[:30]:
                            # Find a sample payload for this topic
                            sample = next(
                                (m["payload"][:80] for m in result["messages"] if m["topic"] == t),
                                ""
                            )
                            if sample:
                                topic_breakdown += f"  - {t} → {sample}\n"
                            else:
                                topic_breakdown += f"  - {t}\n"
                        if len(all_topics) > 30:
                            topic_breakdown += f"  ... and {len(all_topics) - 30} more\n"

                    if sys_topics:
                        topic_breakdown += f"\n[$SYS TOPICS] ({len(sys_topics)})\n"
                        for t in sys_topics[:15]:
                            sample = next(
                                (m["payload"][:80] for m in result["messages"] if m["topic"] == t),
                                ""
                            )
                            if sample:
                                topic_breakdown += f"  - {t} → {sample}\n"
                            else:
                                topic_breakdown += f"  - {t}\n"

                    findings.append(Finding(
                        severity="high",
                        plugin_id=META.plugin_id,
                        title=f"MQTT full topic enumeration: {total_topics} topic(s), {total_messages} message(s)",
                        description=(
                            f"Aggressive wildcard subscription on {target}:{port} discovered "
                            f"{len(all_topics)} user topic(s) and {len(sys_topics)} system topic(s) "
                            f"with {total_messages} total message(s) intercepted in 10 seconds. "
                            f"An attacker can monitor all IoT device data in real-time."
                        ),
                        evidence=(
                            f"host={target} port={port} "
                            f"user_topics={len(all_topics)} sys_topics={len(sys_topics)} "
                            f"messages={total_messages} "
                            f"wildcards_used={result['subscribed_wildcards'][:8]} "
                            f"topic_names={all_topics[:20]}"
                        ),
                        affected=target,
                        fingerprint=fp,
                        confidence=0.95,
                        remediation=(
                            f"[AFFECTED] Full topic enumeration via wildcard subscription\n\n"
                            f"{topic_breakdown}\n"
                            f"[FIX]\n"
                            f"1. Implement topic-level ACLs\n"
                            f"2. Restrict '#' and '+' wildcard subscriptions\n"
                            f"3. Use topic prefixes per device/user\n\n"
                            f"[MOSQUITTO ACL]\n"
                            f"  user sensor1\n"
                            f"  topic read sensor/1/#\n"
                            f"  topic write sensor/1/data\n\n"
                            f"[DENY WILDCARDS]\n"
                            f"  pattern deny #\n"
                            f"  pattern deny +/#"
                        ),
                        references=["https://mosquitto.org/man/mosquitto-conf-5.html"],
                    ))

                # ── Finding: $SYS info disclosure ──────────────────────
                if sys_topics:
                    # Extract broker version if available
                    version_msg = next(
                        (m for m in result["messages"] if "$SYS/broker/version" in m["topic"]),
                        None,
                    )
                    broker_info = version_msg["payload"] if version_msg else "unknown"

                    fp = stable_fingerprint(target, META.plugin_id, "sys_info", str(port))
                    findings.append(Finding(
                        severity="medium",
                        plugin_id=META.plugin_id,
                        title=f"MQTT $SYS topics expose broker information ({len(sys_topics)} topics)",
                        description=(
                            f"The $SYS topic tree at {target}:{port} reveals broker internals: "
                            f"version ({broker_info}), uptime, connected clients, message stats, etc."
                        ),
                        evidence=(
                            f"host={target} port={port} broker_info={broker_info} "
                            f"sys_topics={sys_topics[:10]} "
                            f"sys_samples={[(m['topic'], m['payload'][:50]) for m in result['messages'] if m['topic'].startswith('$SYS/')][:10]}"
                        ),
                        affected=target,
                        fingerprint=fp,
                        confidence=0.95,
                        remediation=(
                            f"[AFFECTED] $SYS topics publicly readable\n"
                            f"[BROKER] {broker_info}\n"
                            f"[SYS TOPICS]\n"
                            + "\n".join(f"  - {t}" for t in sys_topics[:15])
                            + f"\n\n[FIX] Restrict $SYS access:\n"
                            f"  Mosquitto ACL:\n"
                            f"    topic read $SYS/#\n"
                            f"    user admin\n\n"
                            f"  Or disable $SYS entirely:\n"
                            f"    sys_interval 0"
                        ),
                        references=["https://mosquitto.org/man/mosquitto-conf-5.html"],
                    ))

                # ── Finding: Publish injection ─────────────────────────
                acked_injections = [r for r in result["injection_results"] if r.get("acked")]
                accepted_injections = [r for r in result["injection_results"] if r.get("accepted")]

                if acked_injections:
                    injected_topics = [r["topic"] for r in acked_injections]
                    fp = stable_fingerprint(target, META.plugin_id, "publish_inject", str(port))
                    findings.append(Finding(
                        severity="critical",
                        plugin_id=META.plugin_id,
                        title=f"MQTT publish injection: {len(acked_injections)} topic(s) writable anonymously",
                        description=(
                            f"An anonymous client can publish messages to {len(acked_injections)} "
                            f"sensitive topic(s) on {target}:{port}. An attacker can inject fake "
                            f"sensor data, send unauthorized commands, or broadcast malicious messages."
                        ),
                        evidence=(
                            f"host={target} port={port} "
                            f"writable_topics={injected_topics} "
                            f"total_tested={len(result['injection_results'])} "
                            f"acked={len(acked_injections)}"
                        ),
                        affected=target,
                        fingerprint=fp,
                        confidence=0.95,
                        remediation=(
                            f"[CRITICAL] Anonymous publish injection confirmed\n"
                            f"[WRITABLE TOPICS]\n"
                            + "\n".join(f"  - {t}" for t in injected_topics)
                            + f"\n\n[IMPACT]\n"
                            f"- Inject fake sensor data (spoofing)\n"
                            f"- Send unauthorized device commands\n"
                            f"- Broadcast malicious payloads to subscribers\n"
                            f"- Trigger alerts or automations\n\n"
                            f"[FIX]\n"
                            f"1. Require authentication for all connections\n"
                            f"2. Implement per-topic write ACLs\n"
                            f"3. Use topic prefixes to isolate clients\n\n"
                            f"[MOSQUITTO ACL]\n"
                            f"  user device01\n"
                            f"  topic write device/01/telemetry\n"
                            f"  topic read device/01/command"
                        ),
                        references=[
                            "https://owasp.org/www-project-internet-of-things/",
                        ],
                    ))

                # ── Check for sensitive data in messages ───────────────
                sensitive_messages = []
                sensitive_patterns = [
                    "password", "token", "secret", "api_key", "credential",
                    "ssn", "credit_card", "private", "auth",
                ]
                for msg in result["messages"]:
                    payload_lower = msg["payload"].lower()
                    topic_lower = msg["topic"].lower()
                    for pattern in sensitive_patterns:
                        if pattern in payload_lower or pattern in topic_lower:
                            sensitive_messages.append(msg)
                            break

                if sensitive_messages:
                    fp = stable_fingerprint(target, META.plugin_id, "sensitive_data", str(port))
                    findings.append(Finding(
                        severity="high",
                        plugin_id=META.plugin_id,
                        title=f"MQTT exposes sensitive data in {len(sensitive_messages)} message(s)",
                        description=(
                            f"Messages intercepted on {target}:{port} contain potentially sensitive "
                            f"data (passwords, tokens, credentials, etc.) in plaintext."
                        ),
                        evidence=(
                            f"host={target} port={port} "
                            f"sensitive_count={len(sensitive_messages)} "
                            f"samples={[(m['topic'], m['payload'][:60]) for m in sensitive_messages[:5]]}"
                        ),
                        affected=target,
                        fingerprint=fp,
                        confidence=0.80,
                        remediation=(
                            f"[AFFECTED] Sensitive data in MQTT messages\n"
                            f"[SAMPLES]\n"
                            + "\n".join(
                                f"  - {m['topic']}: {m['payload'][:60]}"
                                for m in sensitive_messages[:10]
                            )
                            + f"\n\n[FIX]\n"
                            f"1. Encrypt sensitive payload data before publishing\n"
                            f"2. Use TLS (port 8883) for transport encryption\n"
                            f"3. Never transmit passwords/tokens in MQTT payloads\n"
                            f"4. Use application-layer encryption for sensitive fields"
                        ),
                        references=["https://owasp.org/www-project-internet-of-things/"],
                    ))

            elif result["connect_rc"] in (4, 5):
                # Authentication required — test weak credentials
                mqtt_results.append({"port": port, "anonymous": False, "auth_required": True})

                # ── Step 2: Test weak credentials ──────────────────────
                for username, password in _WEAK_CREDS[1:]:
                    cred_result = await asyncio.to_thread(
                        _run_mqtt_probe, target, port,
                        username=username, password=password,
                        use_tls=use_tls,
                        do_enum=True,
                        do_inject=False,
                        listen_seconds=5.0,
                    )

                    if cred_result["connected"]:
                        fp = stable_fingerprint(target, META.plugin_id, "weak_creds", str(port), username)

                        topic_info = ""
                        if cred_result["topics_discovered"]:
                            topic_info = (
                                f"\n\n[TOPICS ACCESSIBLE WITH THESE CREDENTIALS]\n"
                                + "\n".join(
                                    f"  - {t}" for t in cred_result["topics_discovered"][:20]
                                )
                            )

                        findings.append(Finding(
                            severity="critical",
                            plugin_id=META.plugin_id,
                            title=f"MQTT weak credentials: {username}/{password} on port {port}",
                            description=(
                                f"The MQTT broker at {target}:{port} accepts the weak credential "
                                f"'{username}'/'{password}'. An attacker can connect and interact "
                                f"with all authorized topics. "
                                f"Discovered {len(cred_result['topics_discovered'])} topic(s) "
                                f"and {len(cred_result['messages'])} message(s)."
                            ),
                            evidence=(
                                f"host={target} port={port} username={username} password={password} "
                                f"topics={len(cred_result['topics_discovered'])} "
                                f"messages={len(cred_result['messages'])}"
                            ),
                            affected=target,
                            fingerprint=fp,
                            confidence=0.98,
                            remediation=(
                                f"[CRITICAL] Weak MQTT credentials: {username}/{password}\n\n"
                                f"[IMMEDIATE ACTION]\n"
                                f"1. Change the password immediately\n"
                                f"2. Use strong, unique passwords (min 16 chars)\n"
                                f"3. Implement client certificate authentication\n\n"
                                f"[GENERATE STRONG PASSWORD]\n"
                                f"  mosquitto_passwd -b /etc/mosquitto/passwd {username} $(openssl rand -base64 24)\n\n"
                                f"[BEST PRACTICE]\n"
                                f"- Use unique credentials per device\n"
                                f"- Rotate credentials regularly\n"
                                f"- Consider certificate-based auth for IoT devices"
                                f"{topic_info}"
                            ),
                            references=["https://mosquitto.org/man/mosquitto_passwd-1.html"],
                        ))
                        mqtt_results.append({
                            "port": port,
                            "weak_creds": f"{username}/{password}",
                            "topics": len(cred_result["topics_discovered"]),
                        })
                        break  # One weak cred is enough

        # ── Step 3: Check for unencrypted MQTT (1883 vs 8883) ──────────
        if 1883 in mqtt_ports and 8883 not in mqtt_ports:
            fp = stable_fingerprint(target, META.plugin_id, "no_tls")
            findings.append(Finding(
                severity="high",
                plugin_id=META.plugin_id,
                title=f"MQTT running without TLS encryption (port 1883)",
                description=(
                    f"The MQTT broker at {target}:1883 is running on the unencrypted port. "
                    f"All data including credentials, topic names, and message payloads are "
                    f"transmitted in plaintext and can be intercepted."
                ),
                evidence=f"host={target} port=1883 tls_port_8883=not_found",
                affected=target,
                fingerprint=fp,
                confidence=0.90,
                remediation=(
                    f"[AFFECTED] MQTT on unencrypted port 1883\n\n"
                    f"[FIX] Enable TLS on port 8883:\n"
                    f"  Mosquitto config:\n"
                    f"    listener 8883\n"
                    f"    certfile /etc/mosquitto/certs/server.crt\n"
                    f"    keyfile /etc/mosquitto/certs/server.key\n"
                    f"    cafile /etc/mosquitto/certs/ca.crt\n"
                    f"    require_certificate true\n\n"
                    f"[ALSO]\n"
                    f"- Disable port 1883 entirely\n"
                    f"- Use Let's Encrypt for free TLS certificates\n"
                    f"- Require client certificates for mutual TLS"
                ),
                references=["https://mosquitto.org/man/mosquitto-tls-7.html"],
            ))

        return PluginResult(
            findings=findings,
            artifacts={"iot.mqtt_findings": mqtt_results},
        )

