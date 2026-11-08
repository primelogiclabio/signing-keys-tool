package io.primelogiclab.tools.signingkeystool;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Assume;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * Tests of generate --type openpgp and check on OpenPGP keys. The first part needs only the JDK. The second part
 * proves interoperability with GnuPG: it imports the key into a throwaway GNUPGHOME, checks the self-signature,
 * signs and verifies a file with it, and checks keys that gpg made. Those tests are skipped when gpg is not on the
 * PATH, unless the environment variable SIGNING_KEYS_REQUIRE_GPG is "true" (as in CI), when they fail instead.
 */
public class OpenPgpTest {

    private static final String PASSPHRASE = "correct horse battery staple";
    private static final String UID = "Example Releases <releases@example.com>";

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private final ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
    private final ByteArrayOutputStream errBytes = new ByteArrayOutputStream();
    /** How many times the tool asked for a passphrase. */
    private final AtomicInteger asked = new AtomicInteger();

    /** A passphrase source that hands out a fixed passphrase, or none for null. */
    private Passphrase source(String passphrase) {
        return confirm -> {
            asked.incrementAndGet();
            return passphrase == null ? null : passphrase.toCharArray();
        };
    }

    private int run(String passphrase, String... args) throws Exception {
        return runAt(Clock.systemUTC(), passphrase, args);
    }

    private int runAt(Clock clock, String passphrase, String... args) throws Exception {
        return SigningKeysTool.run(args, new PrintStream(outBytes, true, "UTF-8"),
                new PrintStream(errBytes, true, "UTF-8"), clock, source(passphrase));
    }

    private static Clock daysFromNow(long days) {
        return Clock.offset(Clock.systemUTC(), Duration.ofDays(days));
    }

    private String out() throws Exception {
        return new String(outBytes.toByteArray(), "UTF-8");
    }

    private String err() throws Exception {
        return new String(errBytes.toByteArray(), "UTF-8");
    }

    private void reset() {
        outBytes.reset();
        errBytes.reset();
        asked.set(0);
    }

    private String root() {
        return tmp.getRoot().getAbsolutePath();
    }

    private Path file(String env, String name) {
        return tmp.getRoot().toPath().resolve(env).resolve(name);
    }

    /** Makes a 3072-bit key (quicker than the default 4096) in env, valid for days, then clears the output. */
    private void generate(String env, int days) throws Exception {
        assertEquals(err(), 0, run(PASSPHRASE, "generate", "--type", "openpgp", "--env", env, "--out", root(),
                "--uid", UID, "--bits", "3072", "--days", String.valueOf(days)));
        reset();
    }

    /** The value printed after a label such as "fingerprint", from the output so far. */
    private String printed(String label) throws Exception {
        for (String line : out().split("\\r?\\n")) {
            String trimmed = line.trim();
            if (trimmed.startsWith(label + " ")) {
                return trimmed.substring(label.length()).trim();
            }
        }
        throw new AssertionError("no '" + label + "' line in:\n" + out());
    }

    private static String read(Path p) throws IOException {
        return new String(Files.readAllBytes(p), StandardCharsets.US_ASCII);
    }

    // ---- the format, without gpg ----

    @Test
    public void crc24MatchesTheOpenPgpCheckValue() {
        // The standard check value of CRC-24/OPENPGP over "123456789", and the initial value for no data.
        assertEquals(0x21CF02, OpenPgp.crc24("123456789".getBytes(StandardCharsets.US_ASCII)));
        assertEquals(0xB704CE, OpenPgp.crc24(new byte[0]));
    }

    @Test
    public void s2kCountsAreDecodedAsRfc4880Says() {
        assertEquals(65011712L, OpenPgp.s2kCount(0xFF));
        assertEquals(65536L, OpenPgp.s2kCount(0x60));
        assertEquals(1024L, OpenPgp.s2kCount(0x00));
    }

    @Test
    public void generateWritesArmoredPublicAndSecretKeys() throws Exception {
        assertEquals(err(), 0, run(PASSPHRASE, "generate", "--type", "openpgp", "--env", "release", "--out", root(),
                "--uid", UID, "--bits", "3072"));
        Path pub = file("release", "signing-openpgp-public.asc");
        Path sec = file("release", "signing-openpgp-secret.asc");
        assertTrue(read(pub).startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n"));
        assertTrue(read(pub).trim().endsWith("-----END PGP PUBLIC KEY BLOCK-----"));
        assertTrue(read(sec).startsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n"));
        assertTrue(out().contains("RSA 3072 bits, OpenPGP v4"));
        assertTrue(out().contains("user ID      " + UID));
        assertTrue(out().contains("pair OK"));
        assertTrue(out().contains("--send-keys " + printed("fingerprint")));
        assertEquals("asked once, with confirmation", 1, asked.get());
        // No PEM files: an OpenPGP key is its own thing.
        assertFalse(Files.exists(file("release", "signing-private.pem")));
    }

    @Test
    public void theDefaultSizeIs4096Bits() throws Exception {
        assertEquals(err(), 0, run(PASSPHRASE, "generate", "--type", "openpgp", "--env", "release", "--out", root(),
                "--uid", UID));
        assertTrue(out().contains("RSA 4096 bits"));
    }

    @Test
    public void theFingerprintIsTheSha1OfThePublicKeyPacket() throws Exception {
        assertEquals(err(), 0, run(PASSPHRASE, "generate", "--type", "openpgp", "--env", "release", "--out", root(),
                "--uid", UID, "--bits", "3072"));
        byte[] block = OpenPgp.dearmor(read(file("release", "signing-openpgp-public.asc"))).data;
        OpenPgp.Packet key = OpenPgp.packets(block).get(0);
        assertEquals(OpenPgp.TAG_PUBLIC_KEY, key.tag);
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(new byte[] {(byte) 0x99, (byte) (key.body.length >> 8), (byte) key.body.length});
        String expected = OpenPgp.hex(sha1.digest(key.body));
        assertEquals(expected, printed("fingerprint"));
        assertEquals(expected.substring(24), printed("key ID"));
    }

    @Test
    public void theSelfSignatureHasTheSubpacketsMavenCentralKeysNeed() throws Exception {
        generate("release", 365);
        List<OpenPgp.Packet> packets = OpenPgp.packets(
                OpenPgp.dearmor(read(file("release", "signing-openpgp-public.asc"))).data);
        assertEquals(3, packets.size());
        assertEquals(OpenPgp.TAG_USER_ID, packets.get(1).tag);
        assertEquals(UID, new String(packets.get(1).body, StandardCharsets.UTF_8));
        byte[] sig = packets.get(2).body;
        assertEquals(OpenPgp.TAG_SIGNATURE, packets.get(2).tag);
        assertEquals(4, sig[0]);
        assertEquals(OpenPgp.SIG_POSITIVE_CERTIFICATION, sig[1] & 0xFF);
        assertEquals(OpenPgp.ALGO_RSA, sig[2]);
        assertEquals(OpenPgp.HASH_SHA256, sig[3]);
        int hashedLength = ((sig[4] & 0xFF) << 8) | (sig[5] & 0xFF);
        List<Integer> types = new ArrayList<>();
        for (int i = 6; i < 6 + hashedLength; ) {
            int length = sig[i] & 0xFF;
            types.add(sig[i + 1] & 0x7F);
            if (sig[i + 1] == OpenPgp.SUB_KEY_EXPIRATION) {
                long seconds = ((sig[i + 2] & 0xFFL) << 24) | ((sig[i + 3] & 0xFF) << 16) | ((sig[i + 4] & 0xFF) << 8)
                        | (sig[i + 5] & 0xFF);
                assertEquals(365L * 24 * 60 * 60, seconds);
            }
            if (sig[i + 1] == OpenPgp.SUB_KEY_FLAGS) {
                assertEquals(OpenPgp.FLAGS_CERTIFY_AND_SIGN, sig[i + 2]);
            }
            i += 1 + length;
        }
        assertEquals(Arrays.asList(OpenPgp.SUB_CREATION_TIME, OpenPgp.SUB_KEY_EXPIRATION, OpenPgp.SUB_KEY_FLAGS,
                OpenPgp.SUB_PREFERRED_HASHES, OpenPgp.SUB_ISSUER_FINGERPRINT), types);
    }

    @Test
    public void theSecretKeyIsEncryptedWithAes256AndAnIteratedSha256S2k() throws Exception {
        generate("release", 365);
        OpenPgp.Packet secret = OpenPgp.packets(
                OpenPgp.dearmor(read(file("release", "signing-openpgp-secret.asc"))).data).get(0);
        assertEquals(OpenPgp.TAG_SECRET_KEY, secret.tag);
        OpenPgp.Key key = OpenPgp.read(OpenPgp.dearmor(read(file("release", "signing-openpgp-secret.asc"))).data);
        byte[] s = key.secretPart;
        assertEquals("S2K usage", 254, s[0] & 0xFF);
        assertEquals("AES-256", OpenPgp.AES256, s[1]);
        assertEquals("iterated and salted", 3, s[2]);
        assertEquals("SHA-256", OpenPgp.HASH_SHA256, s[3]);
        assertEquals("coded count", 0xFF, s[12] & 0xFF);
    }

    @Test
    public void thePassphraseIsNeverPrinted() throws Exception {
        generate("release", 365);
        assertEquals(err(), 0, run(PASSPHRASE, "check", "--type", "openpgp", "--env", "release", "--out", root()));
        assertEquals(1, run("wrong passphrase 42", "check", "--type", "openpgp", "--env", "release", "--out", root()));
        assertFalse(out().contains(PASSPHRASE) || err().contains(PASSPHRASE));
        assertFalse(out().contains("wrong passphrase 42") || err().contains("wrong passphrase 42"));
        assertFalse(read(file("release", "signing-openpgp-secret.asc")).contains(PASSPHRASE));
    }

    @Test
    public void withoutAPassphraseNothingIsWritten() throws Exception {
        assertEquals(1, run(null, "generate", "--type", "openpgp", "--env", "release", "--out", root(), "--uid", UID));
        assertTrue(err().contains(Passphrase.VARIABLE));
        assertEquals(1, run("", "generate", "--type", "openpgp", "--env", "release", "--out", root(), "--uid", UID));
        assertFalse(Files.exists(file("release", "signing-openpgp-public.asc")));
        assertFalse(Files.exists(file("release", "signing-openpgp-secret.asc")));
    }

    @Test
    public void refusesToReplaceTheKeyWithoutForceAndAsksNoPassphrase() throws Exception {
        generate("release", 365);
        String before = read(file("release", "signing-openpgp-secret.asc"));
        assertEquals(1, run(PASSPHRASE, "generate", "--type", "openpgp", "--env", "release", "--out", root(),
                "--uid", UID, "--bits", "3072"));
        assertTrue(err().contains("already exists"));
        assertEquals(0, asked.get());
        assertEquals(before, read(file("release", "signing-openpgp-secret.asc")));

        assertEquals(err(), 0, run(PASSPHRASE, "generate", "--type", "openpgp", "--env", "release", "--out", root(),
                "--uid", UID, "--bits", "3072", "--force"));
        assertNotEquals(before, read(file("release", "signing-openpgp-secret.asc")));
    }

    @Test
    public void commandLineErrors() throws Exception {
        String[] base = {"generate", "--type", "openpgp", "--env", "release", "--out", root()};
        assertEquals("--uid is required", 2, run(PASSPHRASE, base));
        assertEquals(2, run(PASSPHRASE, concat(base, "--uid", "no email here")));
        assertEquals(2, run(PASSPHRASE, concat(base, "--uid", "<releases@example.com>")));
        assertEquals(2, run(PASSPHRASE, concat(base, "--uid", "Bad\nName <a@example.com>")));
        assertEquals("2048 is too small for OpenPGP here", 2, run(PASSPHRASE, concat(base, "--uid", UID, "--bits", "2048")));
        assertEquals(2, run(PASSPHRASE, concat(base, "--uid", UID, "--days", "0")));
        assertEquals(2, run(PASSPHRASE, "generate", "--type", "gpg", "--env", "release", "--uid", UID));
        assertEquals("--uid is for openpgp only", 2, run(PASSPHRASE, "generate", "--env", "release", "--uid", UID));
        assertEquals(2, run(PASSPHRASE, "check", "--type", "openpgp", "--env", "release", "--uid", UID));
        assertEquals(0, asked.get());
        assertFalse(Files.exists(tmp.getRoot().toPath().resolve("release")));
    }

    private static String[] concat(String[] a, String... b) {
        String[] all = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, all, a.length, b.length);
        return all;
    }

    @Test
    public void onAPosixFileSystemTheSecretKeyIsReadableByItsOwnerOnly() throws Exception {
        Assume.assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        generate("release", 365);
        assertEquals("rw-------", PosixFilePermissions.toString(
                Files.getPosixFilePermissions(file("release", "signing-openpgp-secret.asc"))));
    }

    @Test
    public void onAnAclFileSystemTheSecretKeyHasOneEntryForItsOwner() throws Exception {
        generate("release", 365);
        Path secret = file("release", "signing-openpgp-secret.asc");
        Assume.assumeTrue(Files.getFileAttributeView(secret, PosixFileAttributeView.class) == null);
        AclFileAttributeView view = Files.getFileAttributeView(secret, AclFileAttributeView.class);
        Assume.assumeTrue(view != null);
        assertEquals(1, view.getAcl().size());
        assertEquals(Files.getOwner(secret), view.getAcl().get(0).principal());
    }

    // ---- check, without gpg ----

    @Test
    public void checkDecryptsTheSecretKeyWhenItHasThePassphrase() throws Exception {
        generate("release", 365);
        assertEquals(err(), 0, run(PASSPHRASE, "check", "--type", "openpgp", "--env", "release", "--out", root()));
        assertTrue(out().contains("pair OK"));
        assertTrue(out().contains("user ID      " + UID));
        assertTrue(printed("fingerprint").matches("[0-9A-F]{40}"));
        assertTrue(printed("expires").endsWith("(365 days left)"));
        assertEquals("", err());
    }

    @Test
    public void checkByFolderWorksToo() throws Exception {
        generate("release", 365);
        assertEquals(err(), 0, run(PASSPHRASE, "check", "--type", "openpgp", file("release", "x").getParent().toString()));
        assertTrue(out().contains("pair OK"));
    }

    @Test
    public void checkWithoutThePassphraseStillMatchesTheSecretKeyToThePublicKey() throws Exception {
        generate("release", 365);
        assertEquals(err(), 0, run(null, "check", "--type", "openpgp", "--env", "release", "--out", root()));
        assertTrue(out().contains("was not decrypted"));
    }

    @Test
    public void checkFailsOnAWrongPassphrase() throws Exception {
        generate("release", 365);
        assertEquals(1, run("not it", "check", "--type", "openpgp", "--env", "release", "--out", root()));
        assertTrue(err(), err().contains("passphrase is wrong"));
    }

    @Test
    public void checkAcceptsThePublicKeyAloneAndASingleFile() throws Exception {
        generate("release", 365);
        Files.delete(file("release", "signing-openpgp-secret.asc"));
        assertEquals(err(), 0, run(null, "check", "--type", "openpgp", "--env", "release", "--out", root()));
        assertTrue(out().contains("public key only"));
        reset();
        // A single .asc file needs no --type.
        assertEquals(err(), 0, run(null, "check", file("release", "signing-openpgp-public.asc").toString()));
        assertTrue(out().contains("user ID      " + UID));
    }

    @Test
    public void checkFailsWhenTheSecretKeyIsForAnotherKey() throws Exception {
        generate("a", 365);
        generate("b", 365);
        Files.copy(file("b", "signing-openpgp-secret.asc"), file("a", "signing-openpgp-secret.asc"),
                java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        assertEquals(1, run(PASSPHRASE, "check", "--type", "openpgp", "--env", "a", "--out", root()));
        assertTrue(err(), err().contains("is for key"));
    }

    @Test
    public void checkFailsWhenTheArmorWasDamaged() throws Exception {
        generate("release", 365);
        Path pub = file("release", "signing-openpgp-public.asc");
        String text = read(pub);
        int at = text.indexOf("\n\n") + 10;
        char c = text.charAt(at);
        Files.write(pub, (text.substring(0, at) + (c == 'A' ? 'B' : 'A') + text.substring(at + 1))
                .getBytes(StandardCharsets.US_ASCII));
        assertEquals(1, run(null, "check", "--type", "openpgp", "--env", "release", "--out", root()));
        assertTrue(err(), err().contains("CRC-24"));
    }

    @Test
    public void checkFailsWhenTheUserIdWasChangedEvenWithAFreshChecksum() throws Exception {
        generate("release", 365);
        Path pub = file("release", "signing-openpgp-public.asc");
        byte[] block = OpenPgp.dearmor(read(pub)).data;
        List<OpenPgp.Packet> packets = OpenPgp.packets(block);
        byte[] forged = OpenPgp.concat(OpenPgp.packet(packets.get(0).tag, packets.get(0).body),
                OpenPgp.packet(OpenPgp.TAG_USER_ID, "Someone Else <x@example.com>".getBytes(StandardCharsets.UTF_8)),
                OpenPgp.packet(packets.get(2).tag, packets.get(2).body));
        Files.write(pub, OpenPgp.armor(OpenPgp.PUBLIC_BLOCK, forged).getBytes(StandardCharsets.US_ASCII));
        assertEquals(1, run(null, "check", "--type", "openpgp", "--env", "release", "--out", root()));
        assertTrue(err(), err().contains("no user ID with a valid self-signature"));
    }

    @Test
    public void checkWarnsWhenThirtyDaysOrFewerAreLeft() throws Exception {
        generate("release", 60);
        assertEquals(err(), 0, runAt(daysFromNow(30), null, "check", "--type", "openpgp", "--env", "release",
                "--out", root()));
        assertTrue(out().contains("(30 days left)"));
        assertTrue(err(), err().startsWith("warning: the key expires on "));
    }

    @Test
    public void checkIsQuietWhenThirtyOneDaysAreLeft() throws Exception {
        generate("release", 60);
        assertEquals(err(), 0, runAt(daysFromNow(29), null, "check", "--type", "openpgp", "--env", "release",
                "--out", root()));
        assertTrue(out().contains("(31 days left)"));
        assertEquals("", err());
    }

    @Test
    public void checkFailsOnceTheKeyHasExpired() throws Exception {
        generate("release", 60);
        assertEquals(1, runAt(daysFromNow(61), null, "check", "--type", "openpgp", "--env", "release",
                "--out", root()));
        assertTrue(err(), err().contains("The key expired on"));
    }

    @Test
    public void theRsaPairIsStillTheDefault() throws Exception {
        assertEquals(err(), 0, run(null, "generate", "--env", "prod", "--out", root()));
        assertTrue(Files.exists(file("prod", "signing-private.pem")));
        assertEquals(0, asked.get());
        assertEquals(err(), 0, run(null, "check", "--type", "rsa", "--env", "prod", "--out", root()));
    }

    // ---- interoperability with GnuPG ----

    /** The gpg command, or a skipped test when there is none (a failure when SIGNING_KEYS_REQUIRE_GPG=true). */
    private static Gpg gpg() throws Exception {
        boolean required = "true".equalsIgnoreCase(System.getenv("SIGNING_KEYS_REQUIRE_GPG"));
        Gpg found = Gpg.find();
        if (found == null && required) {
            fail("gpg is not on the PATH, and SIGNING_KEYS_REQUIRE_GPG is true");
        }
        Assume.assumeTrue("gpg is not on the PATH", found != null);
        return found;
    }

    @Test
    public void gpgImportsTheKeyChecksTheSelfSignatureAndVerifiesASignatureMadeWithIt() throws Exception {
        Gpg gpg = gpg();
        generate("release", 365);
        assertEquals(err(), 0, run(null, "check", "--type", "openpgp", "--env", "release", "--out", root()));
        String fingerprint = printed("fingerprint");
        Path folder = file("release", "x").getParent();
        try (Gpg.Home home = gpg.home()) {
            home.ok(folder, null, "--import", "signing-openpgp-public.asc");

            String colons = home.ok(folder, null, "--with-colons", "--check-signatures", fingerprint);
            assertTrue(colons, colons.contains("fpr:::::::::" + fingerprint + ":"));
            assertTrue(colons, colons.contains("uid:") && colons.contains(UID));
            assertTrue("the self-signature checks: " + colons, colons.contains("sig:!:"));
            assertFalse(colons, colons.contains("sig:-:") || colons.contains("sig:%:"));
            String pub = line(colons, "pub:");
            String[] f = pub.split(":", -1);
            assertEquals("3072", f[2]);
            assertEquals("RSA", "1", f[3]);
            assertEquals("expires 365 days after creation", Long.parseLong(f[5]) + 365L * 24 * 60 * 60,
                    Long.parseLong(f[6]));
            assertTrue("can sign and certify: " + pub, f[11].contains("s") && f[11].contains("c"));

            home.ok(folder, PASSPHRASE, "--pinentry-mode", "loopback", "--passphrase-fd", "0",
                    "--import", "signing-openpgp-secret.asc");
            String secret = home.ok(folder, null, "--with-colons", "--list-secret-keys", fingerprint);
            assertTrue(secret, secret.startsWith("sec:") || secret.contains("\nsec:"));

            Files.write(folder.resolve("artifact.jar"), "pretend this is a jar".getBytes(StandardCharsets.UTF_8));
            home.ok(folder, PASSPHRASE, "--pinentry-mode", "loopback", "--passphrase-fd", "0",
                    "--local-user", fingerprint, "--armor", "--detach-sign", "--output", "artifact.jar.asc",
                    "artifact.jar");
            assertTrue(read(folder.resolve("artifact.jar.asc")).startsWith("-----BEGIN PGP SIGNATURE-----"));

            String status = home.ok(folder, null, "--status-fd", "1", "--verify", "artifact.jar.asc", "artifact.jar");
            assertTrue(status, status.contains("[GNUPG:] GOODSIG "));
            assertTrue(status, status.contains("[GNUPG:] VALIDSIG " + fingerprint + " "));

            // A changed file no longer verifies.
            Files.write(folder.resolve("artifact.jar"), "something else".getBytes(StandardCharsets.UTF_8));
            Gpg.Result bad = home.run(folder, null, "--status-fd", "1", "--verify", "artifact.jar.asc", "artifact.jar");
            assertNotEquals(bad.output, 0, bad.exit);
            assertTrue(bad.output, bad.output.contains("[GNUPG:] BADSIG "));
        }
    }

    @Test
    public void gpgSignsOnlyWithTheRightPassphrase() throws Exception {
        Gpg gpg = gpg();
        generate("release", 365);
        Path folder = file("release", "x").getParent();
        Files.write(folder.resolve("artifact.pom"), "<project/>".getBytes(StandardCharsets.UTF_8));
        try (Gpg.Home home = gpg.home()) {
            // gpg keeps the key protected as it is on import, and asks for the passphrase when it signs.
            home.ok(folder, null, "--import", "signing-openpgp-secret.asc");
            Gpg.Result wrong = home.run(folder, "not the passphrase", "--pinentry-mode", "loopback",
                    "--passphrase-fd", "0", "--armor", "--detach-sign", "--output", "wrong.asc", "artifact.pom");
            assertNotEquals(wrong.output, 0, wrong.exit);
            assertFalse(Files.exists(folder.resolve("wrong.asc")));
            home.ok(folder, PASSPHRASE, "--pinentry-mode", "loopback", "--passphrase-fd", "0", "--armor",
                    "--detach-sign", "--output", "artifact.pom.asc", "artifact.pom");
            home.ok(folder, null, "--verify", "artifact.pom.asc", "artifact.pom");
        }
    }

    @Test
    public void checkReadsKeysThatGpgMade() throws Exception {
        Gpg gpg = gpg();
        Path folder = tmp.newFolder("gpg").toPath();
        try (Gpg.Home home = gpg.home()) {
            home.ok(folder, "gpg made it", "--pinentry-mode", "loopback", "--passphrase-fd", "0",
                    "--quick-gen-key", "Gpg Made <gpg@example.com>", "rsa3072", "sign", "1y");
            home.ok(folder, null, "--armor", "--output", "made-public.asc", "--export", "gpg@example.com");
            home.ok(folder, "gpg made it", "--pinentry-mode", "loopback", "--passphrase-fd", "0", "--armor",
                    "--output", "made-secret.asc", "--export-secret-keys", "gpg@example.com");
            String fingerprint = line(home.ok(folder, null, "--with-colons", "--list-keys", "gpg@example.com"), "fpr:")
                    .split(":")[9];

            assertEquals(err(), 0, run(null, "check", folder.resolve("made-public.asc").toString()));
            assertEquals(fingerprint, printed("fingerprint"));
            assertTrue(out().contains("user ID      Gpg Made <gpg@example.com>"));
            assertTrue(printed("expires"), printed("expires").matches(".*\\((365|366) days left\\)"));
            reset();

            assertEquals(err(), 0, run("gpg made it", "check", folder.resolve("made-secret.asc").toString()));
            assertTrue(out().contains("pair OK"));
            reset();
            assertEquals(1, run("wrong", "check", folder.resolve("made-secret.asc").toString()));
        }
    }

    private static String line(String text, String prefix) {
        for (String l : text.split("\\r?\\n")) {
            if (l.startsWith(prefix)) {
                return l;
            }
        }
        throw new AssertionError("no " + prefix + " line in:\n" + text);
    }

    /**
     * Runs gpg in a throwaway home folder. On Windows the gpg of Git for Windows is an MSYS program: its agent
     * wants GNUPGHOME as /c/..., not C:\..., and every path must stay short, because the agent's socket lives in
     * the home folder and socket paths are limited to about 100 characters. So the home is a fresh folder right in
     * java.io.tmpdir, and file names are passed relative to the working folder.
     */
    private static final class Gpg {
        final String command;
        final boolean msys;

        private Gpg(String command, boolean msys) {
            this.command = command;
            this.msys = msys;
        }

        static Gpg find() {
            try {
                Process p = new ProcessBuilder("gpg", "--version").redirectErrorStream(true).start();
                p.getOutputStream().close();
                String version = readAll(p.getInputStream());
                if (!p.waitFor(60, TimeUnit.SECONDS) || p.exitValue() != 0) {
                    return null;
                }
                boolean windows = File.separatorChar == '\\';
                boolean msys = windows && version.contains("Home: /");
                return new Gpg("gpg", msys);
            } catch (IOException e) {
                return null;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return null;
            }
        }

        Home home() throws IOException {
            return new Home(Files.createTempDirectory(Paths.get(System.getProperty("java.io.tmpdir")), "skg"));
        }

        static final class Result {
            final int exit;
            final String output;

            Result(int exit, String output) {
                this.exit = exit;
                this.output = output;
            }
        }

        final class Home implements AutoCloseable {
            final Path dir;

            Home(Path dir) {
                this.dir = dir;
            }

            String gnupgHome() {
                String path = dir.toAbsolutePath().toString();
                if (msys && path.length() > 2 && path.charAt(1) == ':') {
                    return "/" + Character.toLowerCase(path.charAt(0)) + path.substring(2).replace('\\', '/');
                }
                return path;
            }

            /** Runs gpg --batch with the arguments in folder, writing stdin (a passphrase) when it is not null. */
            Result run(Path folder, String stdin, String... args) throws Exception {
                List<String> command = new ArrayList<>();
                command.add(Gpg.this.command);
                command.add("--batch");
                command.add("--no-tty");
                command.addAll(Arrays.asList(args));
                ProcessBuilder builder = new ProcessBuilder(command).directory(folder.toFile()).redirectErrorStream(true);
                builder.environment().put("GNUPGHOME", gnupgHome());
                builder.environment().put("LC_ALL", "C");
                Process p = builder.start();
                try (OutputStream in = p.getOutputStream()) {
                    if (stdin != null) {
                        in.write((stdin + "\n").getBytes(StandardCharsets.UTF_8));
                    }
                }
                String output = readAll(p.getInputStream());
                if (!p.waitFor(180, TimeUnit.SECONDS)) {
                    p.destroyForcibly();
                    throw new AssertionError("gpg did not finish: " + command);
                }
                return new Result(p.exitValue(), output);
            }

            /** Runs gpg and fails the test unless it exits 0. */
            String ok(Path folder, String stdin, String... args) throws Exception {
                Result r = run(folder, stdin, args);
                assertEquals("gpg " + String.join(" ", args) + "\n" + r.output, 0, r.exit);
                return r.output;
            }

            /** Stops the agent this home started, then deletes the home. */
            @Override
            public void close() throws Exception {
                try {
                    ProcessBuilder builder = new ProcessBuilder("gpgconf", "--kill", "all").redirectErrorStream(true);
                    builder.environment().put("GNUPGHOME", gnupgHome());
                    Process p = builder.start();
                    p.getOutputStream().close();
                    readAll(p.getInputStream());
                    p.waitFor(60, TimeUnit.SECONDS);
                } catch (IOException e) {
                    // no gpgconf: nothing to stop
                }
                deleteTree(dir);
            }
        }

        private static String readAll(InputStream in) throws IOException {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            for (int n; (n = in.read(buffer)) > 0; ) {
                bytes.write(buffer, 0, n);
            }
            return new String(bytes.toByteArray(), StandardCharsets.UTF_8);
        }

        /** Deletes a folder and everything in it, retrying a little because the agent may still be letting go. */
        private static void deleteTree(Path dir) throws Exception {
            for (int attempt = 0; ; attempt++) {
                try {
                    Files.walkFileTree(dir, new SimpleFileVisitor<Path>() {
                        @Override
                        public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                            Files.delete(file);
                            return FileVisitResult.CONTINUE;
                        }

                        @Override
                        public FileVisitResult postVisitDirectory(Path d, IOException e) throws IOException {
                            Files.delete(d);
                            return FileVisitResult.CONTINUE;
                        }
                    });
                    return;
                } catch (IOException e) {
                    if (attempt >= 10 || !Files.exists(dir)) {
                        if (Files.exists(dir)) {
                            System.err.println("could not delete " + dir + ": " + e);
                        }
                        return;
                    }
                    Thread.sleep(200);
                }
            }
        }
    }
}
