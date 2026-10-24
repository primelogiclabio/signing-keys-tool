# Signing Keys Tool

A small command line tool that creates and checks **RSA key pairs for digital signatures**, one pair per environment
or per client. Use the pairs wherever one app signs and others verify with SHA256withRSA: JWTs (where it is called
RS256), webhook payloads, license files and the like. It is one Java program with no dependencies. It needs a JDK to
run, and it does not need OpenSSL.

## What it does

- **`generate`** writes a private key and a public key as PEM files, in a folder for the environment (and the client,
  when there is one), and a self-signed certificate that records when the pair **expires** (5 years by default). It
  reads the files back and checks them, so it never reports a pair it could not load. If the files already exist it
  stops and changes nothing, unless you pass `--force`. It limits the private key file to its owner.
- **`check`** reads a pair back, signs a test string with the private key and checks the signature with the public
  key. It prints the **fingerprint** of the public key, so you can confirm that two places hold the same one. It also
  prints the **expiry**, warns when 30 days or fewer are left, and fails once the key has expired.

### Why not just use keytool or OpenSSL?

`keytool` makes key pairs, but it keeps them inside a keystore and has no command that exports the private key as a
PEM file. OpenSSL can write the files, but it is often missing on Windows servers, and the commands for a PKCS#8
private key, a matching public key and a certificate are easy to get subtly wrong. This tool uses the JDK's own
`keytool` for the one step plain Java cannot do (signing the certificate), writes the standard PEM files itself, and
adds what neither tool does: a folder per environment and client, no accidental overwrites, a private key limited to
its owner, a read-back check, a fingerprint to compare copies, and expiry warnings.

## Requirements

- **Java 8 or later, with `keytool`** to run it. `keytool` comes with a standard JDK or JRE, next to `java`. `generate`
  uses it to sign the certificate. A stripped-down runtime may not have it, and `generate` then says so.
- **Maven** to build it.
- **Windows or Linux.** The jar is the same on both.

## Build

```
mvn package
```

This compiles the code, runs the tests and builds `target/signing-keys-tool-<version>.jar`. It also copies that jar to
`signing-keys-tool.jar` in the project folder, where the launchers look for it.

## Use

Run it any one of three ways. They do the same thing.

| Where | Command |
|---|---|
| Any system, plain Java | `java -jar signing-keys-tool.jar <command> ...` |
| Windows launcher | `signing-keys-tool.cmd <command> ...` |
| Linux and macOS launcher | `./signing-keys-tool.sh <command> ...` |

The launchers find the jar next to the script, so you can run them from any folder. If the `.sh` file is not
executable, run `chmod +x signing-keys-tool.sh` once.

For example:

```
java -jar signing-keys-tool.jar generate --env prod                           writes <tmp>/signing-keys/prod/signing-private.pem and signing-public.pem
java -jar signing-keys-tool.jar generate --env prod --out keys                writes keys/prod/signing-private.pem and signing-public.pem
java -jar signing-keys-tool.jar generate --env prod --client acme --out keys  writes them in keys/prod/acme
java -jar signing-keys-tool.jar generate --env qa --days 365 --out keys       a pair that is valid for one year
java -jar signing-keys-tool.jar check keys/prod/acme                          reads them back and checks them
```

Use `keys\prod` on Windows. The commands below are written as `signing-keys-tool <command>`. Read that as any one
of the three ways.

### generate

```
signing-keys-tool generate --env <environment> [--client <client>] [--out <folder>]
                           [--name <file prefix>] [--bits 2048|3072|4096] [--days <days>] [--force]
```

| Option | Meaning | Default |
|---|---|---|
| `--env` | The environment the pair is for, such as `dev`, `qa` or `prod`. Required. | none |
| `--client` | The client the pair is for, when each client has its own pair. | none |
| `--out` | The folder to write under. | `signing-keys`, in the Java temp folder (`java.io.tmpdir`) |
| `--name` | The start of the file names. | `signing` |
| `--bits` | The key size. | `2048` |
| `--days` | How many days the pair is valid, from 1 to 3650. | `1825` (5 years) |
| `--force` | Replace files that already exist. | off |

It writes `<out>/<env>[/<client>]/<name>-private.pem`, `<name>-public.pem` and `<name>-cert.pem`, and prints the full
path of each file.
Without `--out` that is under the Java temp folder, such as `C:\Users\<you>\AppData\Local\Temp` on Windows or `/tmp`
on Linux. Pass `--out` to write somewhere else. Move the private key to its final place, because the temp folder is
not a place to keep it.

`--env`, `--client` and `--name` become folder and file names. They may hold letters, digits, `.`, `_` and `-`, must
start with a letter or digit, and can be 64 characters long. Anything else, such as `..` or a slash, is refused.

### check

```
signing-keys-tool check <folder> [--name <file prefix>]
signing-keys-tool check --env <environment> [--client <client>] [--out <folder>] [--name <file prefix>]
```

- **Both files present:** it signs a test string with the private key and checks the signature with the public key.
  It prints `pair OK`, or fails if the keys are not a pair.
- **Public key only:** it checks that the public key loads and says that no pair was checked.
- **Public key missing:** it fails.

It prints the fingerprint either way: the SHA-256 of the public key, as 64 lowercase hex characters. It is the same
value as:

```
openssl rsa -pubin -in signing-public.pem -outform DER | openssl dgst -sha256
```

**The expiry.** When `<name>-cert.pem` is there, `check` also reads it:

- It prints `expires      2031-10-08 (1825 days left)`.
- With **30 days or fewer** left it still exits 0, and adds a line on the error output:
  `warning: the key expires on 2026-10-30, in 21 days. Plan a new pair.`
- Once the key has **expired** it fails with exit code 1.
- If the certificate is for a different public key, it fails.
- With no certificate it prints `expires      unknown` and still passes.

The certificate works without the private key, so copy it next to the public key on the apps that verify signatures,
and `check` can warn there too.

### The files

| File | Format | Who should hold it |
|---|---|---|
| `<name>-private.pem` | PKCS#8, first line `-----BEGIN PRIVATE KEY-----`, no password | The one app that signs |
| `<name>-public.pem` | X.509 SubjectPublicKeyInfo, first line `-----BEGIN PUBLIC KEY-----` | Every app that verifies signatures |
| `<name>-cert.pem` | Self-signed X.509 certificate for the public key, first line `-----BEGIN CERTIFICATE-----`. It holds the expiry. | Anyone who runs `check` on a copy of the public key |

The two key files have no expiry in them. The certificate is a separate file.

**What the expiry does and does not do.** Nothing enforces it when a signature is verified. An app that loads only the
two key files, as most do, keeps accepting signatures from an expired key. The expiry is there so that `check` can tell you to
replace the pair in time. A pair made without a certificate, by another tool for example, cannot be given one. Generate
a new pair to get an expiry.

A private key in the older PKCS#1 form (`-----BEGIN RSA PRIVATE KEY-----`) does not load. `check` says so and prints
the OpenSSL command that converts it.

Never commit a private key. `keys/` and `*.pem` are in this repository's `.gitignore`.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Done |
| 1 | The work failed: a file exists, a key does not load, the pair does not match, the key has expired |
| 2 | The command line is wrong. The tool prints the usage text. |

The launchers pass these codes through.

## License

MIT. See [LICENSE](LICENSE).
