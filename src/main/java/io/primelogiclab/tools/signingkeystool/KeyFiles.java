package io.primelogiclab.tools.signingkeystool;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.regex.Pattern;

/**
 * One key pair on disk: {@code <folder>/<name>-private.pem}, {@code <folder>/<name>-public.pem} and
 * {@code <folder>/<name>-cert.pem}.
 *
 * The formats are the ones Java's KeyFactory and most crypto and JWT libraries load: the private key as PKCS#8
 * ("BEGIN PRIVATE KEY", no password) and the public key as X.509 SubjectPublicKeyInfo ("BEGIN PUBLIC KEY").
 * check() reads the files back the way an app written in Java would (PKCS8EncodedKeySpec and
 * X509EncodedKeySpec), so a pair that passes here loads there.
 *
 * The key files carry no expiry, so the third file is a self-signed X.509 certificate for the same public key,
 * and its notAfter date is the pair's expiry. Apps that sign or verify do not need to read it. It is there so
 * check() can warn before the pair runs out.
 */
final class KeyFiles {

    /** The start of the file names when --name is not given. */
    static final String DEFAULT_NAME = "signing";
    /** The key size when --bits is not given: the smallest that RS256 allows. */
    static final int DEFAULT_BITS = 2048;
    /** The key sizes generate accepts. */
    static final int[] ALLOWED_BITS = {2048, 3072, 4096};
    /** How long a pair is valid when --days is not given: 5 years. */
    static final int DEFAULT_DAYS = 1825;
    /** The longest validity generate accepts: 10 years. */
    static final int MAX_DAYS = 3650;
    /** check() reports an expiry this close, or closer, as a warning. */
    static final int WARN_DAYS = 30;

    /** Used to round the time left up to whole days. */
    private static final long MILLIS_PER_DAY = 24L * 60 * 60 * 1000;

    /** Environment, client and name become file and folder names, so they get a short, safe alphabet. */
    private static final Pattern SAFE_NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,63}");

    /** What check() signs with the private key and verifies with the public key to prove they belong together. */
    private static final byte[] TEST_MESSAGE = "signing-keys check".getBytes(StandardCharsets.UTF_8);

    /** What check() found, for the command line to print. */
    static final class Report {
        /** The size of the public key, in bits. */
        final int bits;
        /** The public key's fingerprint. See {@link KeyFiles#fingerprint(PublicKey)}. */
        final String fingerprint;
        /** True when the private key was present and signed what the public key verified. */
        final boolean pairChecked;
        /** When the certificate runs out, or null when there is no certificate file (a pair made by another tool, for example). */
        final Instant notAfter;
        /** Whole days left until notAfter, rounded up. Only meaningful when notAfter is not null. */
        final long daysLeft;

        Report(int bits, String fingerprint, boolean pairChecked, Instant notAfter, long daysLeft) {
            this.bits = bits;
            this.fingerprint = fingerprint;
            this.pairChecked = pairChecked;
            this.notAfter = notAfter;
            this.daysLeft = daysLeft;
        }

        /** True when the pair has an expiry and it is {@link KeyFiles#WARN_DAYS} days away or closer. */
        boolean expiresSoon() {
            return notAfter != null && daysLeft <= WARN_DAYS;
        }
    }

    private final Path folder;
    private final String name;
    /** Where warnings go, such as a private key file that could not be limited to its owner. */
    private final PrintStream err;
    /** What "now" is when check() decides whether the certificate has expired. */
    private final Clock clock;

    /** The pair called name in folder. Nothing is read or written until generate() or check() is called. */
    KeyFiles(Path folder, String name, PrintStream err, Clock clock) {
        this.folder = folder;
        this.name = name;
        this.err = err;
        this.clock = clock;
    }

    /** {@code <folder>/<name>-private.pem}: for the one app that signs. */
    Path privateFile() {
        return folder.resolve(name + "-private.pem");
    }

    /** {@code <folder>/<name>-public.pem}: for every app that verifies. */
    Path publicFile() {
        return folder.resolve(name + "-public.pem");
    }

    /** {@code <folder>/<name>-cert.pem}: the self-signed certificate that holds the expiry. */
    Path certFile() {
        return folder.resolve(name + "-cert.pem");
    }

    /**
     * Refuses a value that is not safe as a file or folder name, such as one with a slash or "..". The option is
     * named in the message, so the user knows which one to fix.
     */
    static void requireSafeName(String option, String value) throws UsageException {
        if (value == null || !SAFE_NAME.matcher(value).matches()) {
            throw new UsageException(option + " '" + value + "' is not allowed. Use letters, digits, '.', '_' and '-' only,"
                    + " start with a letter or digit, and keep it to 64 characters.");
        }
    }

    /** True when generate accepts this key size. See {@link #ALLOWED_BITS}. */
    static boolean isAllowedBits(int bits) {
        for (int allowed : ALLOWED_BITS) {
            if (allowed == bits) {
                return true;
            }
        }
        return false;
    }

    /** True when generate accepts this many days of validity: 1 to {@link #MAX_DAYS}. */
    static boolean isAllowedDays(int days) {
        return days >= 1 && days <= MAX_DAYS;
    }

    /** The UTC date of an instant, as yyyy-MM-dd. */
    static String date(Instant instant) {
        return instant.toString().substring(0, 10);
    }

    /**
     * Creates a new pair and a certificate that expires after the given number of days, writes the three files,
     * then reads them back with check(), so a pair is never reported that could not be loaded. The subject is
     * the certificate's common name. Unless force is true, nothing is touched when any of the three files
     * already exists, because replacing a pair breaks everything signed with the old one.
     */
    Report generate(int bits, int days, String subject, boolean force) throws FailException {
        if (!force) {
            for (Path file : new Path[] {privateFile(), publicFile(), certFile()}) {
                if (Files.exists(file)) {
                    throw new FailException(file + " already exists. Use --force to replace it. "
                            + "Anything signed with the old pair stops verifying once the new public key is in place.");
                }
            }
        }
        // Made before anything is written, so a keytool failure leaves the folder as it was.
        Keytool.Result made = Keytool.generate(bits, days, subject, err);
        try {
            Files.createDirectories(folder);
            // getEncoded() gives PKCS#8 for the private key and X.509 for the public key.
            writePrivate(Pem.encode("PRIVATE KEY", made.privateKey.getEncoded()));
            write(publicFile(), Pem.encode("PUBLIC KEY", made.certificate.getPublicKey().getEncoded()));
            write(certFile(), Pem.encode("CERTIFICATE", made.certificate.getEncoded()));
        } catch (IOException | GeneralSecurityException e) {
            throw new FailException("Could not write the key pair in " + folder + ": " + e, e);
        }
        return check();
    }

    /**
     * Reads the files back the way an app that signs or verifies would. The public key file must be there. The
     * private key file is optional, because an app that only verifies signatures holds the public key alone. When
     * both are there, signs a test string with the private key and checks it with the public key. The certificate
     * file is optional too, because pairs made by other tools have none. When it is there it must be for the
     * public key, and it must not have expired.
     */
    Report check() throws FailException {
        Path publicFile = publicFile();
        Path privateFile = privateFile();
        if (!Files.exists(publicFile)) {
            throw new FailException("Missing " + publicFile + ". The public key file must be there.");
        }
        PublicKey publicKey = readPublic(publicFile);
        if (!(publicKey instanceof RSAPublicKey)) {
            throw new FailException(publicFile + " is not an RSA public key.");
        }
        int bits = ((RSAPublicKey) publicKey).getModulus().bitLength();
        boolean pairChecked = false;
        if (Files.exists(privateFile)) {
            PrivateKey privateKey = readPrivate(privateFile);
            verifyPair(privateKey, publicKey);
            pairChecked = true;
        }
        Instant notAfter = null;
        long daysLeft = 0;
        Path certFile = certFile();
        if (Files.exists(certFile)) {
            X509Certificate certificate = readCertificate(certFile);
            if (!Arrays.equals(certificate.getPublicKey().getEncoded(), publicKey.getEncoded())) {
                throw new FailException(certFile + " is for a different public key than " + publicFile + ".");
            }
            notAfter = certificate.getNotAfter().toInstant();
            Instant now = clock.instant();
            if (now.isAfter(notAfter)) {
                throw new FailException("The key expired on " + date(notAfter) + " (" + certFile
                        + "). Generate a new pair.");
            }
            // Rounded up, so a key with any part of a day left never reports 0 days.
            long millisLeft = Duration.between(now, notAfter).toMillis();
            daysLeft = (millisLeft + MILLIS_PER_DAY - 1) / MILLIS_PER_DAY;
        }
        return new Report(bits, fingerprint(publicKey), pairChecked, notAfter, daysLeft);
    }

    /**
     * SHA-256 of the public key's DER bytes (the X.509 SubjectPublicKeyInfo inside the PEM), as 64 lowercase hex
     * characters. Compare two copies of a public key by comparing this. It matches
     * {@code openssl rsa -pubin -in <file> -outform DER | openssl dgst -sha256}.
     */
    static String fingerprint(PublicKey publicKey) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded());
            return String.format("%064x", new BigInteger(1, digest));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 is missing from this JVM", e);
        }
    }

    /** Loads an X.509 SubjectPublicKeyInfo public key, the way an app that verifies would. */
    private PublicKey readPublic(Path file) throws FailException {
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(readPem(file)));
        } catch (GeneralSecurityException e) {
            throw new FailException("Cannot read " + file + " as an X.509 public key (it must start with"
                    + " -----BEGIN PUBLIC KEY-----): " + e, e);
        }
    }

    /**
     * Loads a PKCS#8 private key, the way an app that signs would. An older PKCS#1 key does not load; the error
     * then says so and gives the OpenSSL command that converts it.
     */
    private PrivateKey readPrivate(Path file) throws FailException {
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(readPem(file)));
        } catch (GeneralSecurityException e) {
            String hint = firstLine(file).contains("RSA PRIVATE KEY")
                    ? " It looks like a PKCS#1 key. Convert it: openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt"
                            + " -in <old file> -out <new file>"
                    : "";
            throw new FailException("Cannot read " + file + " as a PKCS#8 private key (it must start with"
                    + " -----BEGIN PRIVATE KEY----- and have no password)." + hint, e);
        }
    }

    /** Loads the X.509 certificate that holds the expiry. */
    private X509Certificate readCertificate(Path file) throws FailException {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(readPem(file)));
        } catch (GeneralSecurityException e) {
            throw new FailException("Cannot read " + file + " as an X.509 certificate (it must start with"
                    + " -----BEGIN CERTIFICATE-----): " + e, e);
        }
    }

    /** The DER bytes of a PEM file. A file that cannot be read, or is not PEM, fails with the file named. */
    private static byte[] readPem(Path file) throws FailException {
        try {
            return Pem.decode(new String(Files.readAllBytes(file), StandardCharsets.US_ASCII));
        } catch (IOException e) {
            throw new FailException("Cannot read " + file + ": " + e, e);
        } catch (IllegalArgumentException e) {
            throw new FailException(file + " is not valid PEM text: " + e.getMessage(), e);
        }
    }

    /** The first line of a file, or "" when it cannot be read. Only used to recognize a PKCS#1 key for the hint. */
    private static String firstLine(Path file) {
        try {
            String text = new String(Files.readAllBytes(file), StandardCharsets.US_ASCII);
            int end = text.indexOf('\n');
            return end < 0 ? text : text.substring(0, end);
        } catch (IOException e) {
            return "";
        }
    }

    /**
     * Signs the test message with the private key and verifies it with the public key, using SHA256withRSA as an
     * app would. Fails when the two keys are not a pair.
     */
    private static void verifyPair(PrivateKey privateKey, PublicKey publicKey) throws FailException {
        try {
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(privateKey);
            signer.update(TEST_MESSAGE);
            byte[] signature = signer.sign();

            Signature checker = Signature.getInstance("SHA256withRSA");
            checker.initVerify(publicKey);
            checker.update(TEST_MESSAGE);
            if (!checker.verify(signature)) {
                throw new FailException("The public key does not match the private key. They are not a pair.");
            }
        } catch (GeneralSecurityException e) {
            throw new FailException("Could not sign and verify a test string: " + e, e);
        }
    }

    /** Writes a file that may be shared: the public key or the certificate. */
    private void write(Path file, String pem) throws IOException {
        Files.write(file, pem.getBytes(StandardCharsets.US_ASCII));
    }

    /** Creates the private key file, limits it to its owner, then writes the key, so it is never readable by others. */
    private void writePrivate(String pem) throws IOException {
        Path file = privateFile();
        if (!Files.exists(file)) {
            Files.createFile(file);
        }
        restrictToOwner(file);
        Files.write(file, pem.getBytes(StandardCharsets.US_ASCII),
                StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
    }

    /**
     * Limits a file to its owner: rw------- on a POSIX file system, or on Windows an access list with a single
     * entry, for the owner. When neither is possible it warns instead of failing, because the pair itself is
     * fine and the user can protect the file another way.
     */
    private void restrictToOwner(Path file) {
        try {
            PosixFileAttributeView posix = Files.getFileAttributeView(file, PosixFileAttributeView.class);
            if (posix != null) {
                posix.setPermissions(PosixFilePermissions.fromString("rw-------"));
                return;
            }
            AclFileAttributeView acl = Files.getFileAttributeView(file, AclFileAttributeView.class);
            if (acl != null) {
                UserPrincipal owner = Files.getOwner(file);
                AclEntry entry = AclEntry.newBuilder()
                        .setType(AclEntryType.ALLOW)
                        .setPrincipal(owner)
                        .setPermissions(EnumSet.allOf(AclEntryPermission.class))
                        .build();
                acl.setAcl(Collections.singletonList(entry));
                return;
            }
            err.println("warning: this file system cannot limit " + file + " to its owner. Protect it yourself.");
        } catch (IOException | UnsupportedOperationException e) {
            err.println("warning: could not limit " + file + " to its owner (" + e + "). Protect it yourself.");
        }
    }
}
