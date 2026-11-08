package io.primelogiclab.tools.signingkeystool;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * One OpenPGP key on disk: {@code <folder>/<name>-openpgp-public.asc} and {@code <folder>/<name>-openpgp-secret.asc},
 * both ASCII-armored. The kind of key that signs releases for Maven Central: the public one goes to a keyserver,
 * the secret one, protected by its passphrase, to whoever runs the release.
 *
 * Unlike the RSA PEM pair, an OpenPGP key carries its own expiry and user ID in a self-signature, so there is
 * no third file.
 */
final class OpenPgpFiles {

    /** The key size when --bits is not given. */
    static final int DEFAULT_BITS = 4096;
    /** The key sizes generate accepts for OpenPGP. */
    static final int[] ALLOWED_BITS = {3072, 4096};

    /** "Name <email>": some text, a space, then an address in angle brackets. */
    private static final Pattern USER_ID = Pattern.compile("[^<>\\p{Cntrl}]*[^<>\\s\\p{Cntrl}] <[^<>\\s@]+@[^<>\\s@]+>");

    private static final byte[] TEST_MESSAGE = "signing-keys check".getBytes(StandardCharsets.UTF_8);
    private static final long SECONDS_PER_DAY = 24L * 60 * 60;

    /** What happened to the secret key during a check. */
    enum Secret {
        /** There is no secret key file (or the file checked is a public key). */
        ABSENT,
        /** The secret key is for the same key, but no passphrase was available to decrypt it. */
        NOT_DECRYPTED,
        /** The secret key decrypted with the passphrase and signed what the public key verifies. */
        PAIR_OK
    }

    /** What check found, for the command line to print. */
    static final class Report {
        final int bits;
        final String fingerprint;
        final String keyId;
        final List<String> userIds;
        final Instant created;
        /** When the key expires, or null when it never does. */
        final Instant expires;
        /** Whole days left until expires, rounded up. Only meaningful when expires is not null. */
        final long daysLeft;
        final Secret secret;

        Report(OpenPgp.Key key, Instant expires, long daysLeft, Secret secret) {
            this.bits = key.bits();
            this.fingerprint = key.fingerprintHex();
            this.keyId = key.keyId();
            this.userIds = key.userIds;
            this.created = Instant.ofEpochSecond(key.created);
            this.expires = expires;
            this.daysLeft = daysLeft;
            this.secret = secret;
        }

        boolean expiresSoon() {
            return expires != null && daysLeft <= KeyFiles.WARN_DAYS;
        }
    }

    private final Path folder;
    private final String name;
    private final PrintStream err;
    private final Clock clock;

    OpenPgpFiles(Path folder, String name, PrintStream err, Clock clock) {
        this.folder = folder;
        this.name = name;
        this.err = err;
        this.clock = clock;
    }

    /** {@code <folder>/<name>-openpgp-public.asc}: for the keyserver and anyone who verifies. */
    Path publicFile() {
        return folder.resolve(name + "-openpgp-public.asc");
    }

    /** {@code <folder>/<name>-openpgp-secret.asc}: for whoever signs releases. Protected by the passphrase. */
    Path secretFile() {
        return folder.resolve(name + "-openpgp-secret.asc");
    }

    static boolean isAllowedBits(int bits) {
        for (int allowed : ALLOWED_BITS) {
            if (allowed == bits) {
                return true;
            }
        }
        return false;
    }

    /** Refuses a user ID that is not "Name <email>". */
    static void requireUserId(String uid) throws UsageException {
        if (uid == null || uid.length() > 256 || !USER_ID.matcher(uid).matches()) {
            throw new UsageException("--uid '" + uid + "' is not allowed. Give it as \"Name <email>\", such as"
                    + " \"Example Releases <releases@example.com>\".");
        }
    }

    /**
     * Unless force is true, fails when either file exists. Called before the passphrase is asked for, so nobody
     * types one for a key that will not be made.
     */
    void requireNoFiles(boolean force) throws FailException {
        if (force) {
            return;
        }
        for (Path file : new Path[] {publicFile(), secretFile()}) {
            if (Files.exists(file)) {
                throw new FailException(file + " already exists. Use --force to replace it. "
                        + "Anything signed with the old key stops verifying once the new public key is in place.");
            }
        }
    }

    /**
     * Makes a new key, writes both files (the secret one limited to its owner), then reads them back with
     * check() and the same passphrase. Unless force is true, nothing is touched when either file exists.
     */
    Report generate(int bits, int days, String userId, char[] passphrase, boolean force) throws FailException {
        requireNoFiles(force);
        long created = clock.instant().getEpochSecond();
        OpenPgp.Generated made;
        try {
            made = OpenPgp.generate(bits, userId, created, days * SECONDS_PER_DAY, passphrase, new SecureRandom());
        } catch (GeneralSecurityException e) {
            throw new FailException("Could not make the OpenPGP key: " + e, e);
        }
        try {
            Files.createDirectories(folder);
            KeyFiles.writeOwnerOnly(secretFile(), made.secretArmored, err);
            Files.write(publicFile(), made.publicArmored.getBytes(StandardCharsets.US_ASCII));
        } catch (IOException e) {
            throw new FailException("Could not write the OpenPGP key in " + folder + ": " + e, e);
        }
        return check(confirm -> passphrase.clone());
    }

    /**
     * Reads the public key file and, when it is there, the secret key file. The secret key must be for the
     * same key. When a passphrase is to be had it is decrypted and must sign what the public key verifies.
     */
    Report check(Passphrase passphrase) throws FailException {
        Path publicFile = publicFile();
        if (!Files.exists(publicFile)) {
            throw new FailException("Missing " + publicFile + ". The public key file must be there.");
        }
        OpenPgp.Key publicKey = read(publicFile);
        if (publicKey.isSecret()) {
            throw new FailException(publicFile + " holds a secret key. Keep secret keys out of the public file.");
        }
        Secret secret = Secret.ABSENT;
        Path secretFile = secretFile();
        if (Files.exists(secretFile)) {
            OpenPgp.Key secretKey = read(secretFile);
            if (!secretKey.isSecret()) {
                throw new FailException(secretFile + " holds a public key, not a secret key.");
            }
            if (!Arrays.equals(secretKey.fingerprint(), publicKey.fingerprint())) {
                throw new FailException(secretFile + " is for key " + secretKey.fingerprintHex() + ", but "
                        + publicFile + " is for key " + publicKey.fingerprintHex() + ".");
            }
            secret = unlockAndTest(secretKey, secretFile, passphrase);
        }
        return report(publicKey, publicFile, secret);
    }

    /** Checks a single .asc file, public or secret, such as one exported from GnuPG. */
    Report checkFile(Path file, Passphrase passphrase) throws FailException {
        OpenPgp.Key key = read(file);
        Secret secret = key.isSecret() ? unlockAndTest(key, file, passphrase) : Secret.ABSENT;
        return report(key, file, secret);
    }

    /** Decrypts the secret key, when a passphrase is to be had, and signs a test string with it. */
    private Secret unlockAndTest(OpenPgp.Key key, Path file, Passphrase passphrase) throws FailException {
        char[] chars = passphrase.get(false);
        if (chars == null) {
            return Secret.NOT_DECRYPTED;
        }
        try {
            PrivateKey privateKey;
            try {
                privateKey = key.unlock(chars);
            } catch (FailException e) {
                throw new FailException(file + ": " + e.getMessage(), e);
            }
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(privateKey);
            signer.update(TEST_MESSAGE);
            byte[] signature = signer.sign();
            Signature checker = Signature.getInstance("SHA256withRSA");
            checker.initVerify(key.publicKey());
            checker.update(TEST_MESSAGE);
            if (!checker.verify(signature)) {
                throw new FailException(file + ": the secret key does not sign what the public key verifies.");
            }
            return Secret.PAIR_OK;
        } catch (GeneralSecurityException e) {
            throw new FailException("Could not sign and verify a test string with " + file + ": " + e, e);
        } finally {
            Arrays.fill(chars, '\0');
        }
    }

    /** The report for a key: fails when it is revoked or has expired. */
    private Report report(OpenPgp.Key key, Path file, Secret secret) throws FailException {
        if (key.revoked) {
            throw new FailException("The key " + key.fingerprintHex() + " in " + file + " has been revoked.");
        }
        Instant expires = null;
        long daysLeft = 0;
        if (key.validSeconds != 0) {
            expires = Instant.ofEpochSecond(key.created + key.validSeconds);
            Instant now = clock.instant();
            if (now.isAfter(expires)) {
                throw new FailException("The key expired on " + KeyFiles.date(expires) + " (" + file
                        + "). Extend it with gpg --quick-set-expire, or generate a new key.");
            }
            long millisLeft = Duration.between(now, expires).toMillis();
            long day = SECONDS_PER_DAY * 1000;
            daysLeft = (millisLeft + day - 1) / day;
        }
        return new Report(key, expires, daysLeft, secret);
    }

    /** Reads and parses an armored key file, failing with the file named. */
    private static OpenPgp.Key read(Path file) throws FailException {
        String text;
        try {
            text = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new FailException("Cannot read " + file + ": " + e, e);
        }
        OpenPgp.Armored armored;
        try {
            armored = OpenPgp.dearmor(text);
        } catch (IllegalArgumentException e) {
            throw new FailException(file + " is not an ASCII-armored OpenPGP key: " + e.getMessage(), e);
        }
        if (!armored.type.equals(OpenPgp.PUBLIC_BLOCK) && !armored.type.equals(OpenPgp.SECRET_BLOCK)) {
            throw new FailException(file + " holds a " + armored.type + ", not an OpenPGP key.");
        }
        try {
            return OpenPgp.read(armored.data);
        } catch (FailException e) {
            throw new FailException(file + " is not a key this tool can check: " + e.getMessage(), e);
        }
    }
}
