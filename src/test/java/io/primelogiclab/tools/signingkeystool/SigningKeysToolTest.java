package io.primelogiclab.tools.signingkeystool;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;

import org.junit.Assume;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * End-to-end tests. Each test runs the tool the way the command line does, through {@link SigningKeysTool#run},
 * in its own temporary folder, then looks at the files and at what was printed. The expiry tests pass a clock
 * moved forward in time instead of waiting.
 */
public class SigningKeysToolTest {

    /** A fresh folder for each test, used as --out. JUnit deletes it afterwards. */
    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    /** What the tool printed to standard output. */
    private final ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
    /** What the tool printed to the error output. */
    private final ByteArrayOutputStream errBytes = new ByteArrayOutputStream();

    /** Runs the tool with the real clock and returns its exit code. */
    private int run(String... args) throws Exception {
        return SigningKeysTool.run(args, new PrintStream(outBytes, true, "UTF-8"), new PrintStream(errBytes, true, "UTF-8"));
    }

    /** Runs with "now" moved, to see how check() treats a key as time passes. */
    private int runAt(Clock clock, String... args) throws Exception {
        return SigningKeysTool.run(args, new PrintStream(outBytes, true, "UTF-8"), new PrintStream(errBytes, true, "UTF-8"), clock);
    }

    /** A clock that many days ahead of the real one. */
    private static Clock daysFromNow(long days) {
        return Clock.offset(Clock.systemUTC(), Duration.ofDays(days));
    }

    /** Loads a certificate file, to look inside it. */
    private static X509Certificate certificate(Path file) throws Exception {
        byte[] der = Pem.decode(new String(Files.readAllBytes(file), StandardCharsets.US_ASCII));
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
    }

    /** How many of keytool's temporary keystore folders (signing-keys-*, see Keytool) are in the temp folder now. */
    private static int keystoreFolders() {
        String[] names = new File(System.getProperty("java.io.tmpdir")).list();
        int count = 0;
        for (String name : names == null ? new String[0] : names) {
            if (name.startsWith("signing-keys-")) {
                count++;
            }
        }
        return count;
    }

    /** Everything printed to standard output so far. */
    private String out() throws Exception {
        return new String(outBytes.toByteArray(), "UTF-8");
    }

    /** Everything printed to the error output so far. Passed as the assertion message, so a failure shows it. */
    private String err() throws Exception {
        return new String(errBytes.toByteArray(), "UTF-8");
    }

    /** The test's temporary folder, as a path to pass to --out. */
    private String root() {
        return tmp.getRoot().getAbsolutePath();
    }

    /** A path inside the test's temporary folder, such as file("prod", "signing-public.pem"). */
    private Path file(String first, String... more) {
        Path p = tmp.getRoot().toPath().resolve(first);
        for (String m : more) {
            p = p.resolve(m);
        }
        return p;
    }

    /** The first line of a PEM file, which says what is in it. */
    private static String firstLine(Path p) throws Exception {
        return Files.readAllLines(p, StandardCharsets.US_ASCII).get(0);
    }

    /** Sets a test up with a pair, then clears what that printed so each test reads only its own output. */
    private void generate(String env) throws Exception {
        assertEquals(err(), 0, run("generate", "--env", env, "--out", root()));
        outBytes.reset();
        errBytes.reset();
    }

    // ---- generate ----

    @Test
    public void generateWritesBothFilesInTheEnvironmentFolder() throws Exception {
        assertEquals(err(), 0, run("generate", "--env", "prod", "--out", root()));

        Path privateKey = file("prod", "signing-private.pem");
        Path publicKey = file("prod", "signing-public.pem");
        assertTrue(Files.exists(privateKey));
        assertTrue(Files.exists(publicKey));
        assertEquals("-----BEGIN PRIVATE KEY-----", firstLine(privateKey));
        assertEquals("-----BEGIN PUBLIC KEY-----", firstLine(publicKey));
        assertTrue(out().contains("pair OK"));
        assertTrue(out().contains("RSA 2048 bits"));
    }

    @Test
    public void withoutOutItWritesUnderTheJavaTempFolder() throws Exception {
        String saved = System.getProperty("java.io.tmpdir");
        System.setProperty("java.io.tmpdir", root());
        try {
            assertEquals(err(), 0, run("generate", "--env", "dev"));
            assertTrue(Files.exists(file("signing-keys", "dev", "signing-private.pem")));
            assertTrue(Files.exists(file("signing-keys", "dev", "signing-public.pem")));
            outBytes.reset();
            assertEquals(err(), 0, run("check", "--env", "dev"));
            assertTrue(out().contains("pair OK"));
        } finally {
            System.setProperty("java.io.tmpdir", saved);
        }
    }

    @Test
    public void aClientGetsItsOwnFolderUnderTheEnvironment() throws Exception {
        assertEquals(err(), 0, run("generate", "--env", "prod", "--client", "acme", "--out", root()));
        assertTrue(Files.exists(file("prod", "acme", "signing-private.pem")));
        assertTrue(Files.exists(file("prod", "acme", "signing-public.pem")));
        assertFalse(Files.exists(file("prod", "signing-private.pem")));
    }

    @Test
    public void nameChangesTheFileNames() throws Exception {
        assertEquals(err(), 0, run("generate", "--env", "dev", "--name", "jwt-signing", "--out", root()));
        assertTrue(Files.exists(file("dev", "jwt-signing-private.pem")));
        assertTrue(Files.exists(file("dev", "jwt-signing-public.pem")));
    }

    @Test
    public void bitsChangesTheKeySize() throws Exception {
        assertEquals(err(), 0, run("generate", "--env", "dev", "--bits", "3072", "--out", root()));
        assertTrue(out().contains("RSA 3072 bits"));
    }

    @Test
    public void pemLinesAreAtMost64CharactersLong() throws Exception {
        generate("dev");
        for (String name : new String[] {"signing-private.pem", "signing-public.pem"}) {
            for (String line : Files.readAllLines(file("dev", name), StandardCharsets.US_ASCII)) {
                assertTrue(line, line.length() <= 64 || line.startsWith("-----"));
            }
        }
    }

    @Test
    public void refusesToReplaceFilesWithoutForce() throws Exception {
        generate("prod");
        byte[] before = Files.readAllBytes(file("prod", "signing-public.pem"));

        assertEquals(1, run("generate", "--env", "prod", "--out", root()));
        assertTrue(err(), err().contains("already exists"));
        assertArrayEquals(before, Files.readAllBytes(file("prod", "signing-public.pem")));
    }

    @Test
    public void forceReplacesTheFiles() throws Exception {
        generate("prod");
        byte[] before = Files.readAllBytes(file("prod", "signing-public.pem"));

        assertEquals(err(), 0, run("generate", "--env", "prod", "--out", root(), "--force"));
        assertFalse(Arrays.equals(before, Files.readAllBytes(file("prod", "signing-public.pem"))));
        assertEquals(0, run("check", file("prod").toString()));
    }

    @Test
    public void envIsRequired() throws Exception {
        assertEquals(2, run("generate", "--out", root()));
        assertTrue(err().contains("--env is required"));
    }

    @Test
    public void rejectsNamesThatCouldEscapeTheOutputFolder() throws Exception {
        for (String bad : new String[] {"..", "../x", "a/b", "a\\b", "a b", ".hidden", ""}) {
            assertEquals("env '" + bad + "'", 2, run("generate", "--env", bad, "--out", root()));
        }
        assertEquals(2, run("generate", "--env", "dev", "--client", "../x", "--out", root()));
        assertEquals(2, run("generate", "--env", "dev", "--name", "x/y", "--out", root()));
        assertEquals("nothing was written", 0, tmp.getRoot().list().length);
    }

    @Test
    public void rejectsBitsThatAreNotAllowed() throws Exception {
        assertEquals(2, run("generate", "--env", "dev", "--bits", "1024", "--out", root()));
        assertEquals(2, run("generate", "--env", "dev", "--bits", "lots", "--out", root()));
        assertFalse(Files.exists(file("dev")));
    }

    @Test
    public void rejectsUnknownOptionsAndMissingValues() throws Exception {
        assertEquals(2, run("generate", "--env", "dev", "--colour", "red"));
        assertEquals(2, run("generate", "--env"));
        assertEquals(2, run("generate", "--env", "--force"));
    }

    @Test
    public void onAPosixFileSystemThePrivateKeyIsReadableByItsOwnerOnly() throws Exception {
        // Skipped where there are no POSIX permissions, such as on Windows.
        Assume.assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        generate("prod");
        assertEquals("rw-------", PosixFilePermissions.toString(
                Files.getPosixFilePermissions(file("prod", "signing-private.pem"))));

        // A private key file someone opened up to others is locked down again when the pair is replaced.
        Files.setPosixFilePermissions(file("prod", "signing-private.pem"), PosixFilePermissions.fromString("rw-r--r--"));
        assertEquals(err(), 0, run("generate", "--env", "prod", "--out", root(), "--force"));
        assertEquals("rw-------", PosixFilePermissions.toString(
                Files.getPosixFilePermissions(file("prod", "signing-private.pem"))));
    }

    @Test
    public void onAnAclFileSystemThePrivateKeyHasOneEntryForItsOwner() throws Exception {
        generate("prod");
        Path privateKey = file("prod", "signing-private.pem");
        // Runs where permissions are access lists rather than POSIX bits, such as on Windows.
        Assume.assumeTrue(Files.getFileAttributeView(privateKey, PosixFileAttributeView.class) == null);
        AclFileAttributeView view = Files.getFileAttributeView(privateKey, AclFileAttributeView.class);
        Assume.assumeTrue(view != null);

        assertEquals(1, view.getAcl().size());
        assertEquals(Files.getOwner(privateKey), view.getAcl().get(0).principal());
    }

    // ---- check ----

    @Test
    public void checkPassesOnAGeneratedPairByFolderAndByEnvironment() throws Exception {
        generate("prod");
        assertEquals(err(), 0, run("check", file("prod").toString()));
        assertTrue(out().contains("pair OK"));
        assertEquals(err(), 0, run("check", "--env", "prod", "--out", root()));
    }

    @Test
    public void checkPrintsTheSha256OfThePublicKeyBytes() throws Exception {
        generate("prod");
        byte[] der = Pem.decode(new String(Files.readAllBytes(file("prod", "signing-public.pem")), StandardCharsets.US_ASCII));
        String expected = String.format("%064x", new java.math.BigInteger(1, MessageDigest.getInstance("SHA-256").digest(der)));

        assertEquals(0, run("check", file("prod").toString()));
        assertTrue(out(), out().contains(expected));
    }

    @Test
    public void checkFailsWhenThePublicKeyIsFromAnotherPair() throws Exception {
        generate("one");
        generate("two");
        File mixed = tmp.newFolder("mixed");
        Files.copy(file("one", "signing-private.pem"), new File(mixed, "signing-private.pem").toPath());
        Files.copy(file("two", "signing-public.pem"), new File(mixed, "signing-public.pem").toPath());

        assertEquals(1, run("check", mixed.getAbsolutePath()));
        assertTrue(err(), err().contains("not a pair"));
    }

    @Test
    public void checkFailsOnAPkcs1PrivateKeyAndShowsTheConversion() throws Exception {
        generate("prod");
        Path privateFile = file("prod", "signing-private.pem");
        byte[] pkcs8 = Pem.decode(new String(Files.readAllBytes(privateFile), StandardCharsets.US_ASCII));
        Files.write(privateFile, Pem.encode("RSA PRIVATE KEY", pkcs1From(pkcs8)).getBytes(StandardCharsets.US_ASCII));

        assertEquals(1, run("check", file("prod").toString()));
        assertTrue(err(), err().contains("PKCS#1"));
        assertTrue(err(), err().contains("openssl pkcs8 -topk8"));
    }

    @Test
    public void checkAcceptsThePublicKeyAlone() throws Exception {
        generate("prod");
        Files.delete(file("prod", "signing-private.pem"));

        assertEquals(err(), 0, run("check", file("prod").toString()));
        assertTrue(out().contains("public key only"));
        assertFalse(out().contains("pair OK"));
    }

    @Test
    public void checkFailsWhenThePublicKeyIsMissing() throws Exception {
        generate("prod");
        Files.delete(file("prod", "signing-public.pem"));

        assertEquals(1, run("check", file("prod").toString()));
        assertTrue(err(), err().contains("Missing"));
    }

    @Test
    public void checkFailsOnTextThatIsNotPem() throws Exception {
        generate("prod");
        Files.write(file("prod", "signing-public.pem"), "not a key at all !!".getBytes(StandardCharsets.US_ASCII));

        assertEquals(1, run("check", file("prod").toString()));
    }

    @Test
    public void checkRejectsOptionsMeantForGenerate() throws Exception {
        assertEquals(2, run("check", root(), "--force"));
        assertEquals(2, run("check", root(), "--bits", "2048"));
        assertEquals(2, run("check", root(), "--days", "30"));
        assertEquals(2, run("check", root(), "--env", "prod"));
        assertEquals(2, run("check"));
    }

    // ---- expiry ----

    @Test
    public void generateWritesACertificateForThePublicKeyThatExpiresInFiveYears() throws Exception {
        assertEquals(err(), 0, run("generate", "--env", "prod", "--client", "acme", "--out", root()));

        Path certFile = file("prod", "acme", "signing-cert.pem");
        assertEquals("-----BEGIN CERTIFICATE-----", firstLine(certFile));
        X509Certificate certificate = certificate(certFile);
        byte[] publicKey = Pem.decode(new String(Files.readAllBytes(file("prod", "acme", "signing-public.pem")), StandardCharsets.US_ASCII));
        assertArrayEquals(publicKey, certificate.getPublicKey().getEncoded());
        assertTrue(certificate.getSubjectX500Principal().getName(), certificate.getSubjectX500Principal().getName().contains("CN=signing prod acme"));
        assertTrue(out(), out().contains("(1825 days left)"));
        assertTrue(out(), out().contains(certFile.toString()));
    }

    @Test
    public void daysSetsHowLongThePairIsValid() throws Exception {
        assertEquals(err(), 0, run("generate", "--env", "dev", "--days", "30", "--out", root()));
        assertTrue(out(), out().contains("(30 days left)"));
        long days = (certificate(file("dev", "signing-cert.pem")).getNotAfter().getTime() - System.currentTimeMillis()) / (24L * 60 * 60 * 1000);
        assertTrue("days " + days, days >= 29 && days <= 30);
    }

    @Test
    public void rejectsDaysThatAreNotAllowed() throws Exception {
        for (String bad : new String[] {"0", "-1", "abc", "3651", "99999"}) {
            assertEquals("days '" + bad + "'", 2, run("generate", "--env", "dev", "--days", bad, "--out", root()));
        }
        assertFalse(Files.exists(file("dev")));
    }

    @Test
    public void checkShowsTheExpiryAndIsQuietWhenItIsFarOff() throws Exception {
        generate("prod");

        assertEquals(err(), 0, run("check", file("prod").toString()));
        assertTrue(out(), out().contains("expires      "));
        assertTrue(out(), out().contains("(1825 days left)"));
        assertEquals("", err());
    }

    @Test
    public void checkWarnsWhenThirtyDaysOrFewerAreLeft() throws Exception {
        generate("prod");

        // 1825 - 1795 = 30 days left: the first day with a warning.
        assertEquals(err(), 0, runAt(daysFromNow(1795), "check", file("prod").toString()));
        assertTrue(out(), out().contains("(30 days left)"));
        assertTrue(err(), err().contains("warning: the key expires on"));
        assertTrue(err(), err().contains("in 30 days. Plan a new pair."));
    }

    @Test
    public void checkIsQuietWhenThirtyOneDaysAreLeft() throws Exception {
        generate("prod");

        // 1825 - 1794 = 31 days left: the last day without a warning.
        assertEquals(err(), 0, runAt(daysFromNow(1794), "check", file("prod").toString()));
        assertTrue(out(), out().contains("(31 days left)"));
        assertEquals("", err());
    }

    @Test
    public void checkFailsOnceTheKeyHasExpired() throws Exception {
        generate("prod");

        assertEquals(1, runAt(daysFromNow(1826), "check", file("prod").toString()));
        assertTrue(err(), err().contains("The key expired on"));
        assertTrue(err(), err().contains("Generate a new pair."));
    }

    @Test
    public void checkAcceptsAPairWithoutACertificateAndSaysTheExpiryIsUnknown() throws Exception {
        generate("prod");
        Files.delete(file("prod", "signing-cert.pem"));

        assertEquals(err(), 0, run("check", file("prod").toString()));
        assertTrue(out(), out().contains("expires      unknown"));
        assertTrue(out().contains("pair OK"));
        assertEquals("", err());
    }

    @Test
    public void checkReadsTheExpiryOnAHostThatHoldsOnlyThePublicKeyAndTheCertificate() throws Exception {
        generate("prod");
        Files.delete(file("prod", "signing-private.pem"));

        assertEquals(err(), 0, runAt(daysFromNow(1800), "check", file("prod").toString()));
        assertTrue(out(), out().contains("public key only"));
        assertTrue(err(), err().contains("warning: the key expires on"));
    }

    @Test
    public void checkFailsWhenTheCertificateIsForAnotherPublicKey() throws Exception {
        generate("one");
        generate("two");
        Files.copy(file("one", "signing-cert.pem"), file("two", "signing-cert.pem"), StandardCopyOption.REPLACE_EXISTING);

        assertEquals(1, run("check", file("two").toString()));
        assertTrue(err(), err().contains("different public key"));
    }

    @Test
    public void checkFailsOnACertificateThatIsNotPem() throws Exception {
        generate("prod");
        Files.write(file("prod", "signing-cert.pem"), "not a certificate !!".getBytes(StandardCharsets.US_ASCII));

        assertEquals(1, run("check", file("prod").toString()));
    }

    @Test
    public void theCertificateFileIsProtectedFromReplacementLikeTheKeys() throws Exception {
        generate("prod");
        Files.delete(file("prod", "signing-private.pem"));
        Files.delete(file("prod", "signing-public.pem"));

        assertEquals(1, run("generate", "--env", "prod", "--out", root()));
        assertTrue(err(), err().contains("signing-cert.pem already exists"));
    }

    @Test
    public void forceReplacesTheCertificateToo() throws Exception {
        generate("prod");
        byte[] before = Files.readAllBytes(file("prod", "signing-cert.pem"));

        assertEquals(err(), 0, run("generate", "--env", "prod", "--days", "60", "--out", root(), "--force"));
        assertFalse(Arrays.equals(before, Files.readAllBytes(file("prod", "signing-cert.pem"))));
        assertTrue(out(), out().contains("(60 days left)"));
    }

    @Test
    public void generateLeavesNoKeystoreBehind() throws Exception {
        int before = keystoreFolders();
        generate("prod");
        assertEquals(before, keystoreFolders());
    }

    // ---- the command line ----

    @Test
    public void noArgumentsAndUnknownCommandsAreUsageErrors() throws Exception {
        assertEquals(2, run());
        assertTrue(err().contains("Usage:"));
        assertEquals(2, run("make"));
    }

    @Test
    public void helpPrintsTheUsageAndSucceeds() throws Exception {
        assertEquals(0, run("help"));
        assertTrue(out().contains("signing-keys-tool generate"));
        assertEquals("", err());
    }

    @Test
    public void generateRejectsAFolderArgument() throws Exception {
        assertEquals(2, run("generate", root(), "--env", "dev"));
        assertNotEquals("", err());
    }

    /**
     * The PKCS#1 RSAPrivateKey inside a PKCS#8 structure, to make an old-style key file from a generated one:
     * SEQUENCE { INTEGER 0, SEQUENCE { rsaEncryption OID, NULL }, OCTET STRING { PKCS#1 key } }.
     * It relies on the fixed layout Java writes for an RSA key, which is all these tests need.
     */
    private static byte[] pkcs1From(byte[] pkcs8) {
        int pos = 1;                         // the outer SEQUENCE tag
        pos += lengthFieldSize(pkcs8, pos);  // its length
        pos += 3;                            // INTEGER 0: 02 01 00
        pos += 15;                           // 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00
        assertEquals("expected an OCTET STRING", 0x04, pkcs8[pos]);
        pos += 1;
        int length = readLength(pkcs8, pos);
        pos += lengthFieldSize(pkcs8, pos);
        return Arrays.copyOfRange(pkcs8, pos, pos + length);
    }

    /** How many bytes the DER length at pos takes: one for a short length, or one plus the count in its low bits. */
    private static int lengthFieldSize(byte[] b, int pos) {
        int first = b[pos] & 0xff;
        return first < 0x80 ? 1 : 1 + (first & 0x7f);
    }

    /** The DER length at pos, in its short or long form. */
    private static int readLength(byte[] b, int pos) {
        int first = b[pos] & 0xff;
        if (first < 0x80) {
            return first;
        }
        int length = 0;
        for (int i = 0; i < (first & 0x7f); i++) {
            length = (length << 8) | (b[pos + 1 + i] & 0xff);
        }
        return length;
    }
}
