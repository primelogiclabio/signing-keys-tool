package io.primelogiclab.tools.signingkeystool;

import java.util.Base64;

/**
 * Reads and writes PEM text: a block of DER bytes in base64, between a BEGIN line and an END line that name what
 * the bytes are (RFC 7468).
 */
final class Pem {

    private Pem() { }

    /** One PEM block: a BEGIN line, the base64 in lines of 64 characters, an END line. Lines end with LF. */
    static String encode(String label, byte[] der) {
        String base64 = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der);
        return "-----BEGIN " + label + "-----\n" + base64 + "\n-----END " + label + "-----\n";
    }

    /**
     * The DER bytes inside a PEM file, with LF or CRLF line endings. The label is ignored, as Java's key loaders
     * ignore it: what matters is the bytes, so a "RSA PRIVATE KEY" label does not make PKCS#1 bytes loadable.
     *
     * @throws IllegalArgumentException when what is left is not base64
     */
    static byte[] decode(String pem) {
        String base64 = pem.replaceAll("-----BEGIN (.*)-----", "")
                           .replaceAll("-----END (.*)-----", "")
                           .replaceAll("\\s", "");
        return Base64.getDecoder().decode(base64);
    }
}
