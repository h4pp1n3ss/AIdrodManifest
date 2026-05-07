# AIdrodManifest

An AI-powered Android Manifest analyzer that decodes `AndroidManifest.xml` files and uses Claude to identify security vulnerabilities and attack surface exposures.

---

## What It Does

`aidrod_manifest.py` is a two-stage pipeline:

**Stage 1 — Decode**
Reads an `AndroidManifest.xml` (plain XML from a source project or binary AXML from a compiled APK) and pretty-prints it to the console with correct namespace prefixes.

**Stage 2 — Analyze**
Sends the decoded XML to Claude (`claude-opus-4-7`) with a senior mobile security researcher persona. Claude performs a structured security audit and streams findings directly to your terminal, covering:

- Exported components without permission guards
- Dangerous and custom permissions
- Backup and debug flags (`allowBackup`, `debuggable`)
- Network security misconfigurations and missing certificate pinning
- Intent filter attack surface and deep-link vulnerabilities
- Task hijacking via `launchMode` / `taskAffinity`
- Secrets in `<meta-data>` elements
- SDK version legacy risks
- Missing or weak custom permission definitions

---

## Project Structure

```
AIdrodManifest/
├── aidrod_manifest.py      # Main entry point — decodes the manifest and runs the analysis
├── utils/
│   ├── __init__.py         # XML decoding helpers (is_apk, pretty_print_xml, decode_binary_xml …)
│   └── llm.py              # Claude API integration — streams the attack surface analysis
├── .env                    # API key (git-ignored)
├── sample_manifest.xml     # Example manifest for testing
└── requirements.txt        # Dependencies
```

---

## Requirements

- Python 3.12+
- [uv](https://github.com/astral-sh/uv) (or pip)
- An [Anthropic API key](https://console.anthropic.com/)

**Python dependencies** (installed via `uv add` or `pip install`):

| Package | Purpose |
|---|---|
| `anthropic` | Claude API SDK |
| `python-dotenv` | Load API key from `.env` |
| `androguard` | Decode binary AXML from compiled APKs |

---

## Setup

**1. Clone and enter the project**

```bash
git clone <repo-url>
cd AIdrodManifest
```

**2. Create the virtual environment and install dependencies**

```bash
uv sync
```

**3. Add your API key to `.env`**

```bash
# .env
ANTHROPIC_API_KEY=sk-ant-...
```

---

## Usage

```bash
# Analyze a plain XML manifest (from a source project)
python aidrod_manifest.py AndroidManifest.xml

# Analyze a binary manifest inside an APK
python aidrod_manifest.py MyApp.apk
```

---

## Sample Output

Running against the included `sample_manifest.xml`:

```
[*] File: /home/user/AIdrodManifest/sample_manifest.xml
[*] Size: 1,024 bytes
[+] Encoding: Plain XML

============================================================
  ANDROID MANIFEST
============================================================

<?xml version="1.0" ?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.myapp" android:versionCode="1" android:versionName="1.0">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="34"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
    <application android:allowBackup="true" android:icon="@mipmap/ic_launcher" android:label="@string/app_name" android:theme="@style/AppTheme">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <service android:name=".BackgroundService" android:exported="false"/>
    </application>
</manifest>

[*] Sending manifest to Claude for security analysis...

============================================================
  ATTACK SURFACE ANALYSIS
============================================================

# Android Manifest Security Analysis: `com.example.myapp`

## Detailed Findings

---

### 🟡 Finding 1: Backup Enabled — Data Exfiltration Risk

- **Severity:** Medium
- **Vulnerable Element:** `<application android:allowBackup="true">`
- **Attack Scenario:** With `allowBackup="true"`, an attacker with physical access or ADB
  can extract the app's private data via:
  ```
  adb backup -f data.ab -noapk com.example.myapp
  ```
  Extracted backups may include shared preferences, databases, cached tokens, session
  cookies, or PII.
- **Remediation:** Set `android:allowBackup="false"` if backups are not needed, or define
  explicit `android:dataExtractionRules` to whitelist non-sensitive paths.

---

### 🟡 Finding 2: Missing Network Security Configuration

- **Severity:** Medium
- **Vulnerable Element:** `<application>` (missing `android:networkSecurityConfig`)
- **Attack Scenario:** No certificate pinning is enforced — attackers performing MITM with
  malicious CAs or rogue Wi-Fi APs can intercept HTTPS traffic. User-installed CAs are
  trusted by default on API ≤ 23 (relevant since `minSdkVersion=21`).
- **Remediation:** Add a `networkSecurityConfig` with pinning and explicit cleartext block.

---

### 🟡 Finding 3: Outdated `minSdkVersion = 21` (Android 5.0)

- **Severity:** Medium
- **Vulnerable Element:** `<uses-sdk android:minSdkVersion="21">`
- **Attack Scenario:** API 21 lacks scoped storage, has weaker SSL/TLS defaults, and
  contains numerous unpatched WebView and Binder vulnerabilities.
- **Remediation:** Raise `minSdkVersion` to at least 24 (preferably 26+).

---

### 🟡 Finding 4: Dangerous Permission — `ACCESS_FINE_LOCATION`

- **Severity:** Medium
- **Vulnerable Element:** `<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>`
- **Attack Scenario:** Grants precise GPS-level location. If the app is later compromised,
  attackers can exfiltrate user location. GDPR/CCPA require strict justification.
- **Remediation:** Downgrade to `ACCESS_COARSE_LOCATION` if fine precision is not required.

---

### 🟢 Finding 5: Exported Launcher Activity (Acceptable but Reviewable)

- **Severity:** Informational
- **Vulnerable Element:** `<activity android:name=".MainActivity" android:exported="true">`
- **Attack Scenario:** Correctly exported for the launcher. However, any app can start it
  directly. If `MainActivity` reads `Intent` extras without validation it may be vulnerable
  to injection or task hijacking (StrandHogg / StrandHogg 2.0).
- **Remediation:** Sanitize all `getIntent()` data. Consider `singleTask` + empty
  `taskAffinity`.

---

### 🟢 Finding 6: Service Configuration — Acceptable

- **Severity:** Informational
- **Observation:** `BackgroundService` is correctly set as non-exported. ✅

---

### 🟡 Finding 7: Missing Explicit `android:debuggable="false"`

- **Severity:** Low
- **Attack Scenario:** A debuggable APK in production allows ADB memory dumps and
  Frida-style bypass of root/SSL checks.
- **Remediation:** Enforce `debuggable false` in the release build type in `build.gradle`.

---

## 📊 Risk Summary Table

| #  | Finding                         | Severity   | Component           | Recommendation                         |
|----|---------------------------------|------------|---------------------|----------------------------------------|
| 1  | `allowBackup="true"`            | 🟡 Medium  | `<application>`     | Disable or restrict backup             |
| 2  | Missing `networkSecurityConfig` | 🟡 Medium  | `<application>`     | Add NSC with pinning                   |
| 3  | `minSdkVersion=21`              | 🟡 Medium  | `<uses-sdk>`        | Raise to ≥24                           |
| 4  | `ACCESS_FINE_LOCATION`          | 🟡 Medium  | `<uses-permission>` | Justify or downgrade to coarse         |
| 5  | Exported `MainActivity`         | 🟢 Info    | `.MainActivity`     | Sanitize intent extras                 |
| 6  | `BackgroundService` unexported  | 🟢 Info    | `.BackgroundService`| None — correct ✅                      |
| 7  | No explicit `debuggable=false`  | 🟢 Low     | `<application>`     | Enforce in build config                |

### Overall Risk Posture: **Moderate-Low**

[*] Tokens — input: 1032 | output: 3201
```

---

## How It Works

### Input detection

| Input | Format detected | Action |
|---|---|---|
| `.xml` (source project) | Plain XML | Pretty-printed directly |
| `.xml` (compiled) | Binary AXML magic bytes `\x03\x00\x08\x00` | Decoded via `androguard` |
| `.apk` | ZIP file → Binary AXML inside | Extracted then decoded |

### LLM integration

The analysis in `utils/llm.py` uses:

- **Model:** `claude-opus-4-7` — Anthropic's most capable model
- **Adaptive thinking** (`thinking: {"type": "adaptive"}`) — Claude reasons through security implications before writing findings
- **Streaming** — results print token-by-token as they arrive, no waiting for the full response
- **Prompt caching** — the system prompt is cached so repeated runs cost ~10% of the first call's input price

---

## Security Note

The `.env` file containing your API key is listed in `.gitignore` and will never be committed. Never hardcode secrets in source files.
