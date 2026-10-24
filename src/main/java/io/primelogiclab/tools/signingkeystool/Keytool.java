package io.primelogiclab.tools.signingkeystool;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Makes a key pair with a self-signed certificate by running the JDK's own keytool. The JDK has no public API
 * for building a certificate, and this tool has no dependencies, so keytool does the signing. The result is
 * read back with java.security.KeyStore; nothing of keytool's text output is parsed.
 *
 * The pair lives in a PKCS#12 keystore in a temporary folder for the length of the call. The keystore password
 * is random and goes to keytool in its environment, never on the command line, where other processes could see
 * it. The folder is deleted before the call returns, so the private key is left only in memory; a folder that
 * cannot be deleted is reported.
 */
final class Keytool {

    /** The keystore entry the pair is made under. It only exists inside the temporary keystore. */
    private static final String ALIAS = "signing";
    /** The environment variable that carries the keystore password to keytool (-storepass:env, -keypass:env). */
    private static final String PASSWORD_VARIABLE = "SIGNING_KEYS_PASSWORD";

    /** What keytool made, loaded into memory. */
    static final class Result {
        final PrivateKey privateKey;
        /** The self-signed certificate. Its public key is the pair's public key, and its notAfter is the expiry. */
        final X509Certificate certificate;

        Result(PrivateKey privateKey, X509Certificate certificate) {
            this.privateKey = privateKey;
            this.certificate = certificate;
        }
    }

    private Keytool() { }

    /**
     * Makes an RSA pair of the given size and a SHA256withRSA certificate for it, valid for the given number of
     * days from now, with CN=commonName as its subject. Warnings, such as a temporary folder that could not be
     * deleted, go to err.
     */
    static Result generate(int bits, int days, String commonName, PrintStream err) throws FailException {
        Path keytool = locate();
        Path folder = null;
        try {
            folder = Files.createTempDirectory("signing-keys-");
            Path keystore = folder.resolve("keystore.p12");
            String password = randomPassword();

            List<String> command = new ArrayList<String>(Arrays.asList(
                    keytool.toString(), "-genkeypair",
                    "-alias", ALIAS,
                    "-keyalg", "RSA",
                    "-keysize", String.valueOf(bits),
                    "-sigalg", "SHA256withRSA",
                    "-validity", String.valueOf(days),
                    "-dname", "CN=" + commonName,
                    "-storetype", "PKCS12",
                    "-keystore", keystore.toString(),
                    "-storepass:env", PASSWORD_VARIABLE,
                    "-keypass:env", PASSWORD_VARIABLE));
            // One stream for keytool's output and errors, read to the end before waitFor(), so a full pipe
            // can never block it.
            ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
            builder.environment().put(PASSWORD_VARIABLE, password);
            Process process = builder.start();
            // Nothing is typed in, so keytool cannot sit waiting on a prompt.
            process.getOutputStream().close();
            String output = new String(readAll(process.getInputStream()), StandardCharsets.UTF_8).trim();
            int exit = process.waitFor();
            if (exit != 0) {
                throw new FailException("keytool failed (exit " + exit + ")" + (output.isEmpty() ? "." : ": " + output));
            }

            KeyStore store = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(keystore)) {
                store.load(in, password.toCharArray());
            }
            PrivateKey privateKey = (PrivateKey) store.getKey(ALIAS, password.toCharArray());
            X509Certificate certificate = (X509Certificate) store.getCertificate(ALIAS);
            if (privateKey == null || certificate == null) {
                throw new FailException("keytool made a keystore without the key pair in it.");
            }
            return new Result(privateKey, certificate);
        } catch (IOException | GeneralSecurityException e) {
            throw new FailException("Could not make the key pair with keytool: " + e, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new FailException("Interrupted while keytool was running.", e);
        } finally {
            if (folder != null) {
                deleteQuietly(folder, err);
            }
        }
    }

    /**
     * keytool sits next to java in the JDK or JRE that is running this tool, so the same Java is used throughout.
     * A trimmed-down runtime may not have it, and generate then fails with this message.
     */
    private static Path locate() throws FailException {
        Path bin = Paths.get(System.getProperty("java.home"), "bin");
        for (String name : new String[] {"keytool", "keytool.exe"}) {
            Path candidate = bin.resolve(name);
            if (Files.isRegularFile(candidate)) {
                return candidate;
            }
        }
        throw new FailException("keytool not found in " + bin + ". Run this with a JDK.");
    }

    /** A random 160-bit password for the temporary keystore, in hex. It is used once and never stored. */
    private static String randomPassword() {
        return new BigInteger(160, new SecureRandom()).toString(16);
    }

    /** Reads a stream to the end. keytool's output is only kept for the error message when it fails. */
    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int n;
        while ((n = in.read(buffer)) >= 0) {
            bytes.write(buffer, 0, n);
        }
        return bytes.toByteArray();
    }

    /**
     * Deletes the temporary folder and the keystore in it. It never throws, so it cannot hide the real result of
     * generate(), but the keystore holds the private key, so a folder that cannot be deleted is reported on err
     * rather than ignored.
     */
    private static void deleteQuietly(Path folder, PrintStream err) {
        try {
            Files.walkFileTree(folder, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    Files.delete(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                    Files.delete(dir);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            err.println("warning: could not delete the temporary keystore in " + folder + " (" + e + "). It holds the"
                    + " private key, so delete it yourself.");
        }
    }
}
