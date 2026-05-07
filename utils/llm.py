import anthropic
from dotenv import load_dotenv

load_dotenv()

SYSTEM_PROMPT = """You are a senior mobile security researcher specializing in Android application analysis.

When given an AndroidManifest.xml, you perform a thorough attack surface analysis covering:

1. **Exported Components** — activities, services, receivers, and providers exposed to other apps or the system without proper permission guards.
2. **Dangerous Permissions** — permissions that grant access to sensitive device resources (location, contacts, camera, microphone, storage, phone state, SMS, etc.).
3. **Custom Permissions** — weak or misconfigured custom permission definitions that other apps could exploit.
4. **Intent Filters** — implicit intents that allow external apps to trigger internal components unexpectedly.
5. **Backup & Debug Flags** — `android:allowBackup`, `android:debuggable`, `android:testOnly` that expose data or enable ADB access.
6. **Network Security** — `android:usesCleartextTraffic`, missing `networkSecurityConfig`, `android:networkSecurityConfig` misconfigurations.
7. **Task Hijacking** — `android:taskAffinity` and `android:launchMode` combinations that allow screen overlay or task hijacking attacks.
8. **Deep Links & URI Schemes** — unvalidated intent filters for custom URI schemes or app links.
9. **Metadata & Secrets** — API keys, tokens, or sensitive strings in `<meta-data>` elements.
10. **Min SDK / Target SDK** — outdated `minSdkVersion` that retains legacy vulnerabilities.

For each finding:
- State the **severity** (Critical / High / Medium / Low / Informational)
- Identify the **vulnerable element** (component name, attribute, or permission)
- Explain the **attack scenario** — what can an attacker do?
- Suggest a **remediation**

End with a concise **Risk Summary** table."""


def analyze_manifest(xml_content: str) -> str:
    """Send decoded manifest XML to Claude and stream the attack surface analysis."""
    client = anthropic.Anthropic()

    print("\n[*] Sending manifest to Claude for security analysis...\n")
    print("=" * 60)
    print("  ATTACK SURFACE ANALYSIS")
    print("=" * 60 + "\n")

    collected = []

    with client.messages.stream(
        model="claude-opus-4-7",
        max_tokens=8192,
        thinking={"type": "adaptive"},
        system=[
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=[
            {
                "role": "user",
                "content": f"Analyze the following AndroidManifest.xml for security vulnerabilities and attack surface:\n\n```xml\n{xml_content}\n```",
            }
        ],
    ) as stream:
        for event in stream:
            if event.type == "content_block_delta":
                if event.delta.type == "text_delta":
                    print(event.delta.text, end="", flush=True)
                    collected.append(event.delta.text)

        final = stream.get_final_message()

    print("\n")

    usage = final.usage
    print(
        f"[*] Tokens — input: {usage.input_tokens} | output: {usage.output_tokens}"
        + (f" | cache_read: {usage.cache_read_input_tokens}" if usage.cache_read_input_tokens else "")
    )

    return "".join(collected)
