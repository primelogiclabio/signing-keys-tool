# Signing Keys Tool

A small Java command-line tool that creates and checks RSA key pairs for digital signatures, one pair per environment
or per client. It needs nothing but a JDK: no OpenSSL, no libraries.

- Package: `io.primelogiclab.tools.signingkeystool`
- Maven: `io.primelogiclab.tools:signing-keys-tool:1.0`
- License: MIT
- Written: 2026-10-11

| At a glance | |
|---|---|
| Runtime dependencies | 0: only the JDK |
| Java | Compiled for Java 8, runs on newer JDKs |
| Files per pair | 3: private key, public key, certificate |
| Default lifetime | 5 years (1825 days, up to 3650) |
| Tests | 39, 0 failures on the last build (1 skipped on Windows) |

## Contents

1. [Why this tool exists](#1-why-this-tool-exists)
2. [Quick start](#2-quick-start)
3. [How it works](#3-how-it-works)
4. [The three files](#4-the-three-files)
5. [Command reference](#5-command-reference)
6. [Scenario walkthroughs](#6-scenario-walkthroughs)
7. [Safety measures built in](#7-safety-measures-built-in)
8. [Choosing options](#8-choosing-options)
9. [Build, tests and CI](#9-build-tests-and-ci)
10. [Limits and open questions](#10-limits-and-open-questions)
11. [References](#11-references)

---

## 1. Why this tool exists

Whenever one app signs something and other apps check the signature, you need a **key pair**. Common cases are JSON
Web Tokens signed with RS256, webhook payloads, license files, and signed configuration or documents. This tool makes
RSA pairs for signatures made with **SHA256withRSA**, which is what JWTs call RS256 ([RFC 7518](#standards-and-guidance)).
A pair has two halves:

- a **private key**, which signs. Only the one app that signs may have it.
- a **public key**, which verifies signatures. Every app that checks them gets a copy. It can't be used to sign
  anything.

Making a pair by hand is easy to get subtly wrong: the wrong file format, a key the loading code rejects, a public
key on one server that doesn't match the private key on another, or a pair nobody remembers to replace. This tool
handles all of those. It writes the files in the standard formats Java and most crypto and JWT libraries load. It
reads them back before it says it succeeded. It prints a short **fingerprint** so two servers can confirm they hold
the same public key. It also records an **expiry date**, so you get a warning before the pair needs replacing.

### An analogy: a signet ring and a wax seal

| In the analogy | In the tool | Why it fits |
|---|---|---|
| The signet ring | Private key | Only the signer has it. Pressing it into wax (signing) is what makes a document genuine. |
| A photo of the seal | Public key | Every gatekeeper keeps one. They can tell a real seal from a fake, but they can't make a seal from a photo. |
| The photo's serial number | Fingerprint | A short code two people can read out over the phone to make sure they have the same photo. |
| A "replace by" date on the photo | Certificate | It reminds the gatekeeper when to ask for a new ring. |

### Why not just use keytool or OpenSSL?

Both can make an RSA pair, but neither gets you all the way to files you can hand out safely. `keytool` comes with
every JDK, but it keeps keys inside a keystore and has no command that exports the private key as a PEM file
([keytool docs](#java-and-tools)). OpenSSL can write the files, but it's a separate install on Windows, and the
commands for a PKCS#8 private key, a matching public key and a certificate are easy to get wrong
([OpenSSL docs](#java-and-tools)). This tool uses keytool for the one step plain Java can't do, which is signing the
certificate. It writes the PEM files itself and adds the checks around them.

| Need | keytool alone | OpenSSL alone | signing-keys-tool |
|---|---|---|---|
| Private key as a PEM file (PKCS#8) | No: stays in the keystore | Yes | Yes |
| Already installed with Java | Yes | No: separate install on Windows | Yes: needs a JDK |
| Proves the two halves are a pair | No | By hand | Yes: signs and verifies a test string |
| Fingerprint of the public key | Partly: of the certificate, not the key | By hand: a two-command pipe | Yes: printed every time |
| Expiry warning | Partly: shows the dates | By hand: `x509 -checkend` | Yes: warns at 30 days, fails once expired |
| Folder per environment and client, no accidental overwrite, private key limited to its owner | No | No | Yes |

## 2. Quick start

You need a **JDK, version 8 or later**, that includes `keytool` (a standard JDK has it next to `java`). You also
need **Apache Maven** to build. The tool runs on Windows and Linux, and the same jar works on both.

```
# build: compiles, runs the tests, and writes signing-keys-tool.jar into the project folder
mvn package
```

Then run it in any one of three ways. They behave the same, and the launchers pass the exit code through.

| Where | Command |
|---|---|
| Any system, plain Java | `java -jar signing-keys-tool.jar <command> ...` |
| Windows launcher | `signing-keys-tool.cmd <command> ...` |
| Linux / macOS launcher | `./signing-keys-tool.sh <command> ...` |

The launchers find the jar next to the script, even through a symbolic link, so you can run them from any folder.
If the `.sh` file isn't executable, run `chmod +x signing-keys-tool.sh` once.

```
# a pair for production, written under ./keys/prod
java -jar signing-keys-tool.jar generate --env prod --out keys

# a separate pair for one client, under ./keys/prod/acme
java -jar signing-keys-tool.jar generate --env prod --client acme --out keys

# a QA pair that is valid for one year
java -jar signing-keys-tool.jar generate --env qa --days 365 --out keys

# read a pair back and check it (use keys\prod\acme on Windows)
java -jar signing-keys-tool.jar check keys/prod/acme
```

> **Always pass `--out` for real keys.** Without `--out`, files go to `signing-keys` inside the Java temp folder
> (`java.io.tmpdir`), for example `C:\Users\<you>\AppData\Local\Temp` or `/tmp`. That suits a test run. A temp
> folder is no place to keep a private key.

## 3. How it works

The tool is six small classes with no dependencies outside the JDK. One class reads the command line, one handles a
key pair on disk, and two helpers do the low-level work.

```
                 SigningKeysTool        command line: reads arguments, checks options,
                        |               prints results, turns errors into exit codes
                        v
                    KeyFiles            one pair on disk: writes the three files, reads them back,
                        |               works out fingerprint and expiry, locks down the private key
              +---------+---------+
              v                   v
           Keytool               Pem
   runs the JDK's keytool    wraps DER bytes in PEM text
   to make the pair and      (and unwraps PEM back to bytes)
   a self-signed cert

   UsageException -> exit 2 (command line is wrong)
   FailException  -> exit 1 (command line is fine, the work failed)
```

| Class | Job |
|---|---|
| `SigningKeysTool` | Reads the arguments, checks every option, prints the result, and turns errors into exit codes. |
| `KeyFiles` | Writes the three files. Reads them back the way an app that signs or verifies would. Works out the fingerprint and expiry, and limits the private key file to its owner. |
| `Keytool` | Runs the JDK's own `keytool` to create the RSA pair and a self-signed certificate. Then loads the result with `java.security.KeyStore`. |
| `Pem` | Wraps binary key bytes (DER) in PEM text: base64 in 64-character lines between BEGIN and END lines. Also unwraps PEM back to bytes. |
| `UsageException` | The command line is wrong. The tool prints the message and the usage text, and exits with 2. |
| `FailException` | The command line is fine but the work failed. The tool prints the message and exits with 1. |

### Why it runs keytool

The expiry date lives in an X.509 certificate, and a certificate has to be signed. The JDK has no public API for
building one. The usual workaround is a library such as Bouncy Castle, but this tool takes no dependencies. Instead it
runs the `keytool` that sits in the `bin` folder of the Java running the tool ([keytool docs](#java-and-tools)). That
keeps everything on one Java installation. The tool never parses keytool's text output: it reads the keystore keytool
wrote through the standard `KeyStore` API ([KeyStore docs](#java-and-tools)).

### What `generate` does, step by step

1. **Validate: check every input.** `--env`, `--client` and `--name` must match `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`,
   because they become folder and file names. `--bits` must be 2048, 3072 or 4096. `--days` must be 1 to 3650.
2. **Validate: refuse to overwrite.** If any of the three files already exists, stop with exit code 1 and change
   nothing, unless `--force` was given.
3. **Make: run keytool in a throwaway folder.** `keytool -genkeypair` with RSA, `SHA256withRSA`, the chosen validity
   and the common name `CN=<name> <env> [<client>]`. It writes into a PKCS#12 keystore in a new temp folder. The
   keystore password is a random 160-bit value passed through the `SIGNING_KEYS_PASSWORD` environment variable
   (`-storepass:env`), so it never appears on a command line.
4. **Make: load the result, then delete the keystore.** Read the private key and certificate through `KeyStore`,
   then delete the temp folder. If it can't be deleted, the tool warns loudly, because the keystore holds the
   private key. Nothing has been written to your folder yet, so a keytool failure leaves it as it was.
5. **Write: write the private key, locked down first.** Create the file empty, limit it to its owner (POSIX
   `rw-------`, or on Windows an access list with one entry for the owner), and only then write the key bytes. That
   way the key is never readable by others, even for a moment.
6. **Write: write the public key and the certificate.** The public key goes in as X.509 SubjectPublicKeyInfo, the
   certificate as an X.509 certificate. Both are PEM with LF line endings.
7. **Verify: read everything back with `check`.** The same check you can run later (below). So `generate` never
   reports a pair it couldn't load.
8. **Verify: print the report.** The full path of each file, key size, fingerprint, expiry date and `pair OK`.

### What `check` does

`check` reads the files the way an app written in Java would, with `KeyFactory` and the standard PKCS#8 and X.509 key
specs. A pair that passes here will load there. Only the public key is required: an app that only verifies
signatures has no private key, and pairs made by other tools have no certificate.

| What is in the folder | What `check` does | Result |
|---|---|---|
| No public key | Stops at once. | exit 1 |
| Public key that isn't an X.509 RSA key | Says it must start with `-----BEGIN PUBLIC KEY-----`. | exit 1 |
| Private key present | Signs the test string `signing-keys check` with `SHA256withRSA` and verifies it with the public key. | `pair OK`, or exit 1 "not a pair" |
| Private key in the old PKCS#1 form | Fails, and prints the OpenSSL command that converts it. | exit 1 |
| No private key | Says "public key only", so no pair was checked. | exit 0 |
| Certificate for a different public key | Says the certificate doesn't belong to this key. | exit 1 |
| Certificate, more than 30 days left | Prints the expiry date and days left. | exit 0 |
| Certificate, 30 days or fewer left | Prints the expiry, plus a warning on the error output. | exit 0 + warning |
| Certificate past its expiry | Says the key expired and to generate a new pair. | exit 1 |
| No certificate | Prints `expires unknown`. | exit 0 |

```
generated ---------------------------- 30 days before ------------ expiry date (notAfter) ---->
|  valid: check passes quietly         |  warning, still exit 0    |  expired: check fails, exit 1
```

Days left are counted in UTC and rounded up to whole days, so a key with 29.2 days left reports 30 days and gets a
warning. A key with 30.5 days left reports 31 and doesn't.

## 4. The three files

A pair is written to `<out>/<env>[/<client>]/`. The file names start with `--name`, which defaults to `signing`.

| File | Format | Who should hold it |
|---|---|---|
| `<name>-private.pem` | PKCS#8 ([RFC 5208](#standards-and-guidance)), first line `-----BEGIN PRIVATE KEY-----`, **no password** | The **one** app that signs |
| `<name>-public.pem` | X.509 SubjectPublicKeyInfo ([RFC 5280](#standards-and-guidance)), first line `-----BEGIN PUBLIC KEY-----` | Every app that verifies signatures |
| `<name>-cert.pem` | Self-signed X.509 certificate for the public key, first line `-----BEGIN CERTIFICATE-----`. Its `notAfter` date is the pair's expiry. | Anyone who runs `check` on a copy of the public key |

All three are PEM files: base64 text between BEGIN and END lines, wrapped at 64 characters
([RFC 7468](#standards-and-guidance)).

```
signing-keys-tool  --->  The app that signs (exactly one):   private + public + cert
                   --->  Every app that verifies:            public + cert
```

### The fingerprint

The fingerprint is the SHA-256 hash of the public key's DER bytes (the SubjectPublicKeyInfo inside the PEM), written
as 64 lowercase hex characters. Two copies of a public key match exactly when their fingerprints match. You can get
the same value with OpenSSL ([OpenSSL docs](#java-and-tools)):

```
openssl rsa -pubin -in signing-public.pem -outform DER | openssl dgst -sha256
```

> **What the expiry does, and doesn't do.** The two key files carry no expiry. The date is only in the certificate,
> and apps usually load only the two key files. So **nothing enforces the expiry when a signature is verified**: an
> "expired" key keeps working there. The expiry exists so `check` can tell you to replace the pair in time. A pair
> made without a certificate, by another tool for example, can't be given one later. Generate a new pair to get an
> expiry.

> **Never commit a private key.** The repository's `.gitignore` already excludes `keys/` and `*.pem`.

## 5. Command reference

Below, `signing-keys-tool` means whichever of the three ways you run it.

### generate

```
signing-keys-tool generate --env <environment> [--client <client>] [--out <folder>]
                           [--name <file prefix>] [--bits 2048|3072|4096] [--days <days>] [--force]
```

| Option | Meaning | Default |
|---|---|---|
| `--env` | The environment the pair is for, such as `dev`, `qa` or `prod`. Required. | none |
| `--client` | The client the pair is for, when each client has its own pair. | none |
| `--out` | The folder to write under. | `signing-keys` in `java.io.tmpdir` |
| `--name` | The start of the file names. | `signing` |
| `--bits` | The RSA key size: 2048, 3072 or 4096. | `2048` |
| `--days` | How many days the pair is valid, 1 to 3650. | `1825` (5 years) |
| `--force` | Replace files that already exist. | off |

### check

```
signing-keys-tool check <folder> [--name <file prefix>]
signing-keys-tool check --env <environment> [--client <client>] [--out <folder>] [--name <file prefix>]
```

Give either a folder or `--env`, which finds the folder the same way `generate` would. If you use `--env` without
`--out`, that means the temp folder.

### help

`help`, `--help` and `-h` print the usage text and exit 0.

### Command-line rules

- `check` refuses `--bits`, `--days` and `--force`, which only apply to `generate`.
- `generate` refuses a bare folder argument. Use `--out`, `--env` and `--client`.
- `check` takes a folder *or* `--env`/`--client`/`--out`, not both, and at most one folder.
- An option followed by another `--option` counts as having no value. Unknown options are refused.
- `--env`, `--client` and `--name` may contain letters, digits, `.`, `_` and `-`. They must start with a letter or
  digit and be at most 64 characters. That rules out `..` and slashes, so a name can't escape the output folder.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Done. This includes `check` with an expiry warning. |
| 1 | The work failed: a file exists, a key doesn't load, the pair doesn't match, the key has expired, or keytool failed. |
| 2 | The command line is wrong. The tool prints the error and the usage text. |

## 6. Scenario walkthroughs

The output below is what the tool prints. Paths are shortened, and your fingerprint will differ because every pair
is new.

### A. Setting up keys for a new client

Production needs its own pair for the client `acme`:

```
> java -jar signing-keys-tool.jar generate --env prod --client acme --out keys
Created the signing key pair for prod / acme
  private key  C:\work\keys\prod\acme\signing-private.pem
  public key   C:\work\keys\prod\acme\signing-public.pem
  certificate  C:\work\keys\prod\acme\signing-cert.pem
  key          RSA 2048 bits (SHA256withRSA / RS256)
  fingerprint  SHA-256 of the public key: 1aac9141ce06d3a01d8e64354337a8833c7e16c36af16b7d996c8f8cbba751b5
  expires      2031-10-11 (1825 days left)
  check        pair OK

The private key goes only to the app that signs. Every app that verifies signatures gets the
public key only. Keep the private key out of source control. Keep the certificate beside the
public key, so 'check' can warn there before the key expires.
```

Next: copy `signing-private.pem` to the app that signs, and nowhere else. Copy the public key and the certificate to
every app that verifies. Write down the fingerprint.

### B. Confirming a server has the right public key

A server that only verifies signatures holds the public key and the certificate. Run `check` there:

```
> java -jar signing-keys-tool.jar check C:\apps\verifier\keys
Checked C:\apps\verifier\keys
  public key   RSA 2048 bits (SHA256withRSA / RS256)
  fingerprint  SHA-256 of the public key: 1aac9141ce06d3a01d8e64354337a8833c7e16c36af16b7d996c8f8cbba751b5
  expires      2031-10-11 (1825 days left)
  check        public key only. There is no signing-private.pem here, so no pair was checked.
```

If the fingerprint matches the one printed by `generate`, the server has the right key. If it doesn't, every
signature from the signing app will fail there. Recopy the public key.

### C. A key nearing its expiry date

With 30 days or fewer left, `check` still exits 0 but adds a line on the error output:

```
warning: the key expires on 2031-10-11, in 21 days. Plan a new pair.
```

After the date has passed, `check` fails with exit code 1:

```
error: The key expired on 2031-10-11 (…\signing-cert.pem). Generate a new pair.
```

If you run `check` from a scheduled job, a warning doesn't change the exit code. Watch the error output too, or
you'll only notice once the key has expired.

### D. Running generate twice by accident

```
error: C:\work\keys\prod\acme\signing-private.pem already exists. Use --force to replace it. Anything signed with the old pair stops verifying once the new public key is in place.
```

Exit code 1, and nothing on disk changes. `--force` is the only way past this, and the message says why that
matters. Anything signed with the old private key won't verify against the new public key. For JWTs, that means
every token issued so far stops working.

### E. An old key in PKCS#1 form

A private key that starts with `-----BEGIN RSA PRIVATE KEY-----` is in the older PKCS#1 form
([RFC 8017](#standards-and-guidance)). Java's PKCS#8 key loader can't read it, so `check` fails and shows how to
convert it:

```
error: Cannot read …\signing-private.pem as a PKCS#8 private key (it must start with -----BEGIN PRIVATE KEY----- and have no password). It looks like a PKCS#1 key. Convert it: openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in <old file> -out <new file>
```

### F. A typo or an unsafe name

```
> java -jar signing-keys-tool.jar generate --env ../x
error: --env '../x' is not allowed. Use letters, digits, '.', '_' and '-' only, start with a letter or digit, and keep it to 64 characters.

signing-keys-tool: creates and checks RSA key pairs for digital signatures (SHA256withRSA, the RS256 of JWTs).
… usage text …
```

Exit code 2: the command line is wrong, so nothing was attempted.

## 7. Safety measures built in

Most of the code is about keeping a private key from ending up somewhere it shouldn't, or a broken pair from reaching
production.

| Risk | What the tool does |
|---|---|
| Overwriting a live pair by mistake | Refuses if any of the three files exists, unless you pass `--force`. The message warns that anything signed with the old pair stops verifying. |
| A name escaping the output folder | `--env`, `--client` and `--name` must match a safe pattern, so `..`, slashes and drive letters are refused. |
| Others reading the private key | Creates the file empty and limits it to its owner *before* writing the key. Warns if the file system can't do that. |
| The keystore password leaking | Uses a random 160-bit password and passes it to keytool through an environment variable, never as a command-line argument other processes could see. |
| A copy of the private key left in temp | Deletes the temporary keystore folder in a `finally` block. Warns, with the path, if it can't. |
| Reporting success for a pair that won't load | `generate` runs `check` on what it wrote before printing anything. |
| Keys committed to git | `.gitignore` covers `keys/` and `*.pem`. |
| Servers holding different public keys | Prints a fingerprint that can be compared, including with OpenSSL. |
| The `.sh` launcher breaking on Linux | `.gitattributes` forces LF line endings for `*.sh` and CRLF for `*.cmd`. |

## 8. Choosing options

### One pair per environment, or per client?

- **Per environment:** use `--env` alone when one app signs for everyone in that environment and every verifying app
  may accept anything it signs.
- **Per client:** add `--client` when something signed for one client must *not* be accepted for another. Each
  client also gets its own replacement schedule, so replacing one client's pair doesn't affect the others.
- **Never:** don't share a pair across environments. A QA signature would verify in production. The folder layout
  (`<out>/<env>/…`) is built to keep them apart.

### One pair per job

- **Separate jobs:** give each kind of signature its own pair with `--name`, for example `--name jwt` and
  `--name webhooks` in the same environment folder. Replacing one then doesn't break the other.
- **Not for encryption:** use these pairs for signatures only. Key-management guidance says each key should have one
  purpose ([NIST SP 800-57](#standards-and-guidance)), and `check` only tests signing.

### Key size: `--bits`

- **2048 (default):** the smallest size RS256 allows ([RFC 7518 §3.3](#standards-and-guidance)), and the fastest to
  sign and check.
- **3072 or 4096:** when a security policy asks for it. An RSA signature is as long as the key, so every signature
  grows from 256 bytes to 384 or 512 bytes, and signing gets slower.

### Lifetime: `--days`

- **Production:** the default 1825 days (5 years) suits keys that are expensive to replace, since replacing one
  invalidates everything signed with it.
- **Dev / QA:** shorter, such as `--days 365`, so replacing a pair stays routine.
- Keep in mind the expiry only drives `check`'s warning. It isn't enforced when signatures are verified.

## 9. Build, tests and CI

| Item | Value |
|---|---|
| Maven coordinates | `io.primelogiclab.tools:signing-keys-tool:1.0` (jar) |
| Java package | `io.primelogiclab.tools.signingkeystool` |
| Main class | `io.primelogiclab.tools.signingkeystool.SigningKeysTool` |
| Build output | `signing-keys-tool.jar` in the project folder, not `target/`. It's git-ignored. |
| Target bytecode | Java 8 (`maven.compiler.source/target 1.8`), so the jar also runs on servers that are still on Java 8 |
| Test framework | JUnit 4.13.1, test scope only ([JUnit 4](#to-build-and-run-it)) |
| License | MIT, in `LICENSE` |

### Tests

`SigningKeysToolTest` runs the tool end to end. Each test calls `SigningKeysTool.run(...)` with captured output
streams in a temporary folder. The expiry tests swap in a `Clock` moved forward in time, so they can test "29 days
left", "31 days left" and "expired" without waiting. The 39 tests cover file layout, name validation, overwrite
protection, file permissions, fingerprints, PKCS#1 detection, the expiry rules and cleanup of the temp keystore.

> **Last verified build: 2026-10-11.** JDK 21.0.2 and Maven 3.9.16 on Windows. `mvn clean package` ran 39 tests:
> 0 failures, 0 errors, 1 skipped. The skipped test checks file permissions that only apply on another type of file
> system, so it doesn't run on Windows. The jar's manifest names
> `io.primelogiclab.tools.signingkeystool.SigningKeysTool` as its main class.

### Continuous integration

`.github/workflows/build.yml` runs on every push to `main`, on pull requests and on demand:

- A matrix of `windows-latest` and `ubuntu-latest`, set up with Eclipse Temurin Java 8 through `actions/setup-java`
  ([setup-java, Temurin](#to-build-and-run-it)), with the Maven cache on.
- `mvn -B -ntp package` builds and tests.
- The Ubuntu job uploads `signing-keys-tool.jar` and both launchers as a download kept for 30 days, so the tool can be
  tried without building it.
- When a test fails, the job uploads `target/surefire-reports`.

## 10. Limits and open questions

- **The expiry is advisory.** Apps usually load only the two key files, so an expired pair keeps working there. Only
  `check` looks at the date.
- **No rollover.** Replacing a pair invalidates everything signed with the old one. The tool has no key IDs (such as
  the JWT `kid` header) and doesn't publish a key set, so it can't run old and new pairs side by side during a
  changeover. How to replace a production pair without disruption is left to the apps that use it.
- **Signatures only.** `check` tests signing and verifying. The tool doesn't test or advise on using a pair for
  encryption.
- **The private key has no password.** PKCS#8 without encryption is what Java's KeyFactory loads directly. Protection
  relies on file permissions and where you keep the file.
- **Windows permissions are strict.** On Windows the private key file ends up with a single access entry, for its
  owner. No other account is listed, which may matter for services running under a different account.
- **Other pairs can't get an expiry.** A certificate can't be added to a pair made by another tool. Generate a new
  one.
- **keytool is required.** A trimmed-down Java runtime may not include it. `generate` then fails with "keytool not
  found … Run this with a JDK." `check` doesn't need it.
- **The fingerprint isn't a JWK thumbprint.** It hashes the DER public key, not the JSON form defined in
  [RFC 7638](#standards-and-guidance), so it won't match a `kid` derived that way.
- **macOS isn't tested.** The `.sh` launcher's usage mentions macOS, but the README lists Windows and Linux, and CI
  runs only those two.
- **Your own app is out of scope.** `check` proves the files load with Java's standard key classes. Confirm once, in
  a test environment, that your own app loads them too.

## 11. References

### Standards and guidance

- [RFC 7518, JSON Web Algorithms, §3.3: RS256](https://www.rfc-editor.org/rfc/rfc7518#section-3.3): defines
  RS256 (RSASSA-PKCS1-v1_5 with SHA-256, Java's SHA256withRSA) and the 2048-bit minimum key size.
- [RFC 8017, PKCS #1 v2.2: RSA Cryptography](https://www.rfc-editor.org/rfc/rfc8017): the RSA standard. Its
  private key format is the older "RSA PRIVATE KEY" form the tool refuses.
- [RFC 5208, PKCS #8: Private-Key Information Syntax](https://www.rfc-editor.org/rfc/rfc5208): the private key
  file format ("PRIVATE KEY").
- [RFC 5280, Internet X.509 Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280):
  SubjectPublicKeyInfo (the public key format), certificates and the notAfter date.
- [RFC 7468, Textual Encodings of PKIX, PKCS, and CMS Structures](https://www.rfc-editor.org/rfc/rfc7468): the PEM
  text format, BEGIN/END labels and base64 lines.
- [RFC 7638, JSON Web Key (JWK) Thumbprint](https://www.rfc-editor.org/rfc/rfc7638): the JWK fingerprint method,
  which is not what this tool prints.
- [NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final):
  the one-purpose-per-key guidance behind "one pair per job".

### Java and tools

- keytool reference: [Java 8](https://docs.oracle.com/javase/8/docs/technotes/tools/unix/keytool.html) ·
  [Java 21](https://docs.oracle.com/en/java/javase/21/docs/specs/man/keytool.html): `-genkeypair`,
  `-storepass:env`, PKCS12 keystores, and the commands keytool offers (none exports a private key).
- [java.security.KeyStore API](https://docs.oracle.com/javase/8/docs/api/java/security/KeyStore.html): how the tool
  reads keytool's keystore without parsing text output.
- [Java Security Standard Algorithm Names](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html):
  the `SHA256withRSA` signature and `PKCS12` keystore names.
- OpenSSL: [openssl rsa](https://docs.openssl.org/master/man1/openssl-rsa/) ·
  [openssl dgst](https://docs.openssl.org/master/man1/openssl-dgst/) ·
  [openssl pkcs8](https://docs.openssl.org/master/man1/openssl-pkcs8/) ·
  [openssl x509](https://docs.openssl.org/master/man1/openssl-x509/): the fingerprint command, converting a PKCS#1
  key to PKCS#8, and `-checkend` for expiry checks.

### To build and run it

- [Eclipse Temurin JDK (adoptium.net)](https://adoptium.net/): the JDK the CI uses. Any JDK 8+ that includes keytool
  works.
- [Apache Maven download (maven.apache.org)](https://maven.apache.org/download.cgi): needed to build. Download only
  from maven.apache.org or the mirrors it lists.
- [JUnit 4](https://junit.org/junit4/): the test framework (4.13.1). Maven fetches it, so you don't install it.
- [actions/setup-java](https://github.com/actions/setup-java): the GitHub Action that installs Java in CI.

### Project files

- [README.md](../README.md): the user guide this document builds on.
- [LICENSE](../LICENSE): the MIT license.
- [pom.xml](../pom.xml): coordinates, Java 8 target, main class, JUnit version.
- [.github/workflows/build.yml](../.github/workflows/build.yml): the CI workflow.
- [src/main/java/io/primelogiclab/tools/signingkeystool/](../src/main/java/io/primelogiclab/tools/signingkeystool/):
  SigningKeysTool, KeyFiles, Keytool, Pem and the two exceptions.
- [SigningKeysToolTest.java](../src/test/java/io/primelogiclab/tools/signingkeystool/SigningKeysToolTest.java): the 39
  tests.

---

*Signing Keys Tool: project documentation, written 2026-10-11 from the source at version 1.0. An HTML copy of this page
is `signing-keys-tool.html` in the same folder.*
