package io.primelogiclab.tools.signingkeystool;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * OpenPGP keys (RFC 4880, version 4 keys as RFC 9580 keeps them), built and read with the JDK alone.
 *
 * {@link #generate} makes an RSA primary key that can certify and sign, with one user ID and a positive
 * certification self-signature (type 0x13, SHA-256). The secret key is protected with a passphrase: S2K usage
 * 254, iterated and salted S2K with SHA-256, AES-256 in CFB mode, and a SHA-1 checksum. Both blocks are
 * ASCII-armored with a CRC-24 checksum, so {@code gpg --import} takes them as they are.
 *
 * {@link #read} parses a key block (made here or by GnuPG), checks the self-signatures with the key itself and
 * returns what check prints: the v4 fingerprint, the user IDs and the expiry. {@link Key#unlock} decrypts the
 * secret part with the passphrase.
 *
 * OpenPGP RSA signatures are PKCS#1 v1.5 over a DigestInfo, which is exactly what the JDK's SHA256withRSA makes,
 * so the JDK signs and verifies; only the bytes around it are built here.
 */
final class OpenPgp {

    static final int TAG_SIGNATURE = 2;
    static final int TAG_SECRET_KEY = 5;
    static final int TAG_PUBLIC_KEY = 6;
    static final int TAG_SECRET_SUBKEY = 7;
    static final int TAG_USER_ID = 13;
    static final int TAG_PUBLIC_SUBKEY = 14;

    /** Public-key algorithm 1: RSA (encrypt or sign). */
    static final int ALGO_RSA = 1;
    static final int HASH_SHA1 = 2;
    static final int HASH_SHA256 = 8;
    static final int HASH_SHA384 = 9;
    static final int HASH_SHA512 = 10;
    static final int HASH_SHA224 = 11;
    static final int AES128 = 7;
    static final int AES192 = 8;
    static final int AES256 = 9;

    static final int SIG_POSITIVE_CERTIFICATION = 0x13;
    static final int SIG_KEY_REVOCATION = 0x20;

    static final int SUB_CREATION_TIME = 2;
    static final int SUB_KEY_EXPIRATION = 9;
    static final int SUB_ISSUER = 16;
    static final int SUB_PREFERRED_HASHES = 21;
    static final int SUB_KEY_FLAGS = 27;
    static final int SUB_ISSUER_FINGERPRINT = 33;

    /** Key flags: 0x01 may certify other keys and its own user IDs, 0x02 may sign data. */
    static final int FLAGS_CERTIFY_AND_SIGN = 0x03;

    /** S2K usage 254: the secret part is encrypted, followed by a SHA-1 of the plain text. */
    private static final int S2K_USAGE_SHA1 = 254;
    /** S2K specifier 3: iterated and salted. */
    private static final int S2K_ITERATED_SALTED = 3;
    /** The coded S2K count 0xFF: 65,011,712 bytes are hashed, the most OpenPGP allows, as GnuPG does by default. */
    private static final int S2K_CODED_COUNT = 0xFF;

    static final String PUBLIC_BLOCK = "PGP PUBLIC KEY BLOCK";
    static final String SECRET_BLOCK = "PGP PRIVATE KEY BLOCK";

    private static final Pattern ARMOR = Pattern.compile(
            "-----BEGIN (PGP [A-Z ]+)-----\\r?\\n(.*?)\\r?\\n-----END \\1-----", Pattern.DOTALL);

    private OpenPgp() { }

    // ---- making a key ----

    /** A new key: the armored public block and the armored, passphrase-protected secret block. */
    static final class Generated {
        final String publicArmored;
        final String secretArmored;

        Generated(String publicArmored, String secretArmored) {
            this.publicArmored = publicArmored;
            this.secretArmored = secretArmored;
        }
    }

    /**
     * Makes an RSA key of the given size, created at {@code created} (seconds since 1970, UTC), that expires
     * {@code validSeconds} later, with one user ID and its self-signature. The secret key is encrypted with the
     * passphrase. The passphrase is not kept.
     */
    static Generated generate(int bits, String userId, long created, long validSeconds, char[] passphrase,
            SecureRandom random) throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(bits, random);
        KeyPair pair = generator.generateKeyPair();
        RSAPublicKey pub = (RSAPublicKey) pair.getPublic();
        RSAPrivateCrtKey priv = (RSAPrivateCrtKey) pair.getPrivate();

        byte[] publicBody = publicKeyBody(created, pub.getModulus(), pub.getPublicExponent());
        byte[] fingerprint = fingerprint(publicBody);
        byte[] uid = userId.getBytes(StandardCharsets.UTF_8);

        ByteArrayOutputStream hashed = new ByteArrayOutputStream();
        subpacket(hashed, SUB_CREATION_TIME, uint32(created));
        subpacket(hashed, SUB_KEY_EXPIRATION, uint32(validSeconds));
        subpacket(hashed, SUB_KEY_FLAGS, new byte[] {FLAGS_CERTIFY_AND_SIGN});
        subpacket(hashed, SUB_PREFERRED_HASHES, new byte[] {HASH_SHA512, HASH_SHA384, HASH_SHA256});
        subpacket(hashed, SUB_ISSUER_FINGERPRINT, concat(new byte[] {4}, fingerprint));
        ByteArrayOutputStream unhashed = new ByteArrayOutputStream();
        subpacket(unhashed, SUB_ISSUER, Arrays.copyOfRange(fingerprint, 12, 20));

        byte[] signature = certify(priv, publicBody, uid, hashed.toByteArray(), unhashed.toByteArray());

        // OpenPGP wants p < q and u = p^-1 mod q. The JDK's p and q come in either order.
        BigInteger p = priv.getPrimeP();
        BigInteger q = priv.getPrimeQ();
        if (p.compareTo(q) > 0) {
            BigInteger t = p;
            p = q;
            q = t;
        }
        BigInteger u = p.modInverse(q);
        byte[] plain = concat(mpi(priv.getPrivateExponent()), mpi(p), mpi(q), mpi(u));
        byte[] secretBody = concat(publicBody, protect(plain, passphrase, random));
        Arrays.fill(plain, (byte) 0);

        byte[] uidPacket = packet(TAG_USER_ID, uid);
        byte[] sigPacket = packet(TAG_SIGNATURE, signature);
        byte[] publicBlock = concat(packet(TAG_PUBLIC_KEY, publicBody), uidPacket, sigPacket);
        byte[] secretPacket = packet(TAG_SECRET_KEY, secretBody);
        byte[] secretBlock = concat(secretPacket, uidPacket, sigPacket);
        String secretArmored = armor(SECRET_BLOCK, secretBlock);
        Arrays.fill(secretBlock, (byte) 0);
        Arrays.fill(secretPacket, (byte) 0);
        Arrays.fill(secretBody, (byte) 0);
        return new Generated(armor(PUBLIC_BLOCK, publicBlock), secretArmored);
    }

    /** The body of a v4 RSA public-key packet: version, creation time, algorithm, n, e. */
    static byte[] publicKeyBody(long created, BigInteger n, BigInteger e) {
        return concat(new byte[] {4}, uint32(created), new byte[] {ALGO_RSA}, mpi(n), mpi(e));
    }

    /** The v4 fingerprint: SHA-1 of 0x99, the two-byte length and the public-key packet body. */
    static byte[] fingerprint(byte[] publicBody) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            sha1.update(keyHashPrefix(publicBody));
            return sha1.digest(publicBody);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-1 is missing from this JVM", e);
        }
    }

    /** A positive certification (0x13) of the user ID by the key, as the body of a v4 signature packet. */
    private static byte[] certify(PrivateKey key, byte[] publicBody, byte[] uid, byte[] hashedSubpackets,
            byte[] unhashedSubpackets) throws GeneralSecurityException {
        byte[] head = concat(new byte[] {4, SIG_POSITIVE_CERTIFICATION, ALGO_RSA, HASH_SHA256},
                uint16(hashedSubpackets.length), hashedSubpackets);
        byte[] toHash = concat(keyHashPrefix(publicBody), publicBody, uidHashPrefix(uid), uid, head, trailer(head));

        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(key);
        signer.update(toHash);
        byte[] rsa = signer.sign();
        byte[] left16 = Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(toHash), 2);
        return concat(head, uint16(unhashedSubpackets.length), unhashedSubpackets, left16,
                mpi(new BigInteger(1, rsa)));
    }

    /**
     * The secret part of a secret-key packet after the public fields: usage 254, AES-256, an iterated and salted
     * SHA-256 S2K, the IV, then the MPIs and their SHA-1 encrypted together in CFB mode.
     */
    private static byte[] protect(byte[] plain, char[] passphrase, SecureRandom random)
            throws GeneralSecurityException {
        byte[] salt = new byte[8];
        random.nextBytes(salt);
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        byte[] key = s2k(HASH_SHA256, salt, s2kCount(S2K_CODED_COUNT), passphrase, 32);
        byte[] withChecksum = concat(plain, MessageDigest.getInstance("SHA-1").digest(plain));
        try {
            Cipher aes = Cipher.getInstance("AES/CFB/NoPadding");
            aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            byte[] encrypted = aes.doFinal(withChecksum);
            return concat(new byte[] {(byte) S2K_USAGE_SHA1, AES256, S2K_ITERATED_SALTED, HASH_SHA256}, salt,
                    new byte[] {(byte) S2K_CODED_COUNT}, iv, encrypted);
        } finally {
            Arrays.fill(key, (byte) 0);
            Arrays.fill(withChecksum, (byte) 0);
        }
    }

    // ---- reading a key ----

    /** A primary key, its user IDs and what its self-signatures say. */
    static final class Key {
        /** The body of the public-key packet (or the public fields of the secret-key packet). */
        final byte[] publicBody;
        final long created;
        final BigInteger n;
        final BigInteger e;
        /** The user IDs that carry a valid self-signature, in file order. */
        final List<String> userIds;
        /** Seconds after creation when the key expires, from the newest valid self-signature; 0 means never. */
        final long validSeconds;
        /** True when a valid key revocation signature is present. */
        final boolean revoked;
        /** The secret fields after the public ones, or null for a public key. */
        final byte[] secretPart;

        Key(byte[] publicBody, long created, BigInteger n, BigInteger e, List<String> userIds, long validSeconds,
                boolean revoked, byte[] secretPart) {
            this.publicBody = publicBody;
            this.created = created;
            this.n = n;
            this.e = e;
            this.userIds = userIds;
            this.validSeconds = validSeconds;
            this.revoked = revoked;
            this.secretPart = secretPart;
        }

        byte[] fingerprint() {
            return OpenPgp.fingerprint(publicBody);
        }

        /** The fingerprint as 40 uppercase hex characters, as {@code gpg --with-colons} prints it. */
        String fingerprintHex() {
            return hex(fingerprint());
        }

        /** The key ID: the last 8 bytes of the fingerprint, as 16 uppercase hex characters. */
        String keyId() {
            return fingerprintHex().substring(24);
        }

        int bits() {
            return n.bitLength();
        }

        boolean isSecret() {
            return secretPart != null;
        }

        PublicKey publicKey() throws GeneralSecurityException {
            return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
        }

        /**
         * Decrypts the secret part with the passphrase and returns the private key.
         *
         * @throws FailException when the passphrase is wrong or the protection is one this tool does not read
         */
        PrivateKey unlock(char[] passphrase) throws FailException {
            if (secretPart == null) {
                throw new IllegalStateException("not a secret key");
            }
            try {
                return unprotect(this, passphrase);
            } catch (GeneralSecurityException | RuntimeException ex) {
                throw new FailException("Cannot decrypt the secret key: " + ex.getMessage(), ex);
            }
        }
    }

    /**
     * Reads the first primary key in a block of packets. The user IDs and the expiry are taken only from
     * self-signatures that verify with the key, so a block that was changed after it was made does not pass.
     *
     * @throws FailException when there is no RSA v4 primary key, or no user ID with a valid self-signature
     */
    static Key read(byte[] block) throws FailException {
        List<Packet> packets = packets(block);
        if (packets.isEmpty() || (packets.get(0).tag != TAG_PUBLIC_KEY && packets.get(0).tag != TAG_SECRET_KEY)) {
            throw new FailException("it does not start with an OpenPGP public or secret key packet");
        }
        Packet primary = packets.get(0);
        ByteBuffer in = ByteBuffer.wrap(primary.body);
        int version = in.get() & 0xFF;
        if (version != 4) {
            throw new FailException("the key is OpenPGP version " + version + "; this tool reads version 4 keys");
        }
        long created = in.getInt() & 0xFFFFFFFFL;
        int algorithm = in.get() & 0xFF;
        if (algorithm != ALGO_RSA) {
            throw new FailException("the key's algorithm is " + algorithm + ", not RSA (1); this tool reads RSA keys");
        }
        BigInteger n = readMpi(in);
        BigInteger e = readMpi(in);
        byte[] publicBody = Arrays.copyOf(primary.body, in.position());
        byte[] secretPart = primary.tag == TAG_SECRET_KEY
                ? Arrays.copyOfRange(primary.body, in.position(), primary.body.length) : null;
        PublicKey verifyKey;
        try {
            verifyKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
        } catch (GeneralSecurityException ex) {
            throw new FailException("the RSA public key does not load: " + ex, ex);
        }
        int modulusBytes = (n.bitLength() + 7) / 8;

        List<String> userIds = new ArrayList<>();
        long newest = -1;
        long validSeconds = 0;
        boolean revoked = false;
        byte[] currentUid = null;
        for (int i = 1; i < packets.size(); i++) {
            Packet p = packets.get(i);
            if (p.tag == TAG_PUBLIC_SUBKEY || p.tag == TAG_SECRET_SUBKEY) {
                break; // what follows belongs to subkeys
            }
            if (p.tag == TAG_USER_ID) {
                currentUid = p.body;
            } else if (p.tag == TAG_SIGNATURE) {
                Sig sig = Sig.parse(p.body);
                if (sig == null) {
                    continue;
                }
                if (sig.type == SIG_KEY_REVOCATION && currentUid == null) {
                    if (sig.verify(verifyKey, modulusBytes, concat(keyHashPrefix(publicBody), publicBody))) {
                        revoked = true;
                    }
                } else if (sig.type >= 0x10 && sig.type <= 0x13 && currentUid != null) {
                    byte[] material = concat(keyHashPrefix(publicBody), publicBody, uidHashPrefix(currentUid),
                            currentUid);
                    if (sig.verify(verifyKey, modulusBytes, material)) {
                        String uid = new String(currentUid, StandardCharsets.UTF_8);
                        if (!userIds.contains(uid)) {
                            userIds.add(uid);
                        }
                        if (sig.created >= newest) {
                            newest = sig.created;
                            validSeconds = sig.keyExpiration;
                        }
                    }
                }
            }
        }
        if (userIds.isEmpty()) {
            throw new FailException("it has no user ID with a valid self-signature from the key");
        }
        return new Key(publicBody, created, n, e, userIds, validSeconds, revoked, secretPart);
    }

    /** The parts of a v4 signature that read() needs. */
    private static final class Sig {
        int type;
        int hashAlgorithm;
        /** Version through the hashed subpackets: what the hash covers before the trailer. */
        byte[] head;
        byte[] left16;
        BigInteger value;
        long created;
        long keyExpiration;

        /** The signature, or null when it is not a v4 RSA signature (those are skipped, not failed). */
        static Sig parse(byte[] body) throws FailException {
            try {
                ByteBuffer in = ByteBuffer.wrap(body);
                if ((in.get() & 0xFF) != 4) {
                    return null;
                }
                Sig s = new Sig();
                s.type = in.get() & 0xFF;
                int algorithm = in.get() & 0xFF;
                s.hashAlgorithm = in.get() & 0xFF;
                int hashedLength = in.getShort() & 0xFFFF;
                byte[] hashed = new byte[hashedLength];
                in.get(hashed);
                s.head = Arrays.copyOf(body, 6 + hashedLength);
                int unhashedLength = in.getShort() & 0xFFFF;
                in.position(in.position() + unhashedLength);
                s.left16 = new byte[2];
                in.get(s.left16);
                if (algorithm != ALGO_RSA) {
                    return null;
                }
                s.value = readMpi(in);
                ByteBuffer sub = ByteBuffer.wrap(hashed);
                while (sub.hasRemaining()) {
                    int length = subpacketLength(sub);
                    int type = sub.get() & 0x7F;
                    byte[] data = new byte[length - 1];
                    sub.get(data);
                    if (type == SUB_CREATION_TIME && data.length == 4) {
                        s.created = ByteBuffer.wrap(data).getInt() & 0xFFFFFFFFL;
                    } else if (type == SUB_KEY_EXPIRATION && data.length == 4) {
                        s.keyExpiration = ByteBuffer.wrap(data).getInt() & 0xFFFFFFFFL;
                    }
                }
                return s;
            } catch (RuntimeException e) {
                throw new FailException("a signature packet is damaged", e);
            }
        }

        /** True when the signature over material, this head and the trailer verifies with the key. */
        boolean verify(PublicKey key, int modulusBytes, byte[] material) {
            String name = jdkSignatureName(hashAlgorithm);
            if (name == null) {
                return false;
            }
            try {
                byte[] toHash = concat(material, head, trailer(head));
                byte[] digest = MessageDigest.getInstance(digestName(hashAlgorithm)).digest(toHash);
                if (digest[0] != left16[0] || digest[1] != left16[1]) {
                    return false;
                }
                Signature verifier = Signature.getInstance(name);
                verifier.initVerify(key);
                verifier.update(toHash);
                return verifier.verify(leftPad(value.toByteArray(), modulusBytes));
            } catch (GeneralSecurityException | IllegalArgumentException e) {
                return false;
            }
        }
    }

    /** The JDK name for RSA with an OpenPGP hash algorithm, or null for one this tool does not check. */
    private static String jdkSignatureName(int hashAlgorithm) {
        switch (hashAlgorithm) {
            case HASH_SHA1: return "SHA1withRSA";
            case HASH_SHA224: return "SHA224withRSA";
            case HASH_SHA256: return "SHA256withRSA";
            case HASH_SHA384: return "SHA384withRSA";
            case HASH_SHA512: return "SHA512withRSA";
            default: return null;
        }
    }

    /** The JDK digest name for an OpenPGP hash algorithm. */
    private static String digestName(int hashAlgorithm) throws GeneralSecurityException {
        switch (hashAlgorithm) {
            case HASH_SHA1: return "SHA-1";
            case HASH_SHA224: return "SHA-224";
            case HASH_SHA256: return "SHA-256";
            case HASH_SHA384: return "SHA-384";
            case HASH_SHA512: return "SHA-512";
            default: throw new GeneralSecurityException("hash algorithm " + hashAlgorithm + " is not supported");
        }
    }

    /** Decrypts a secret part protected with usage 254 (or not protected at all, usage 0). */
    private static PrivateKey unprotect(Key key, char[] passphrase) throws GeneralSecurityException {
        ByteBuffer in = ByteBuffer.wrap(key.secretPart);
        int usage = in.get() & 0xFF;
        byte[] plain;
        if (usage == 0) {
            plain = Arrays.copyOfRange(key.secretPart, 1, key.secretPart.length);
        } else if (usage == S2K_USAGE_SHA1) {
            int cipher = in.get() & 0xFF;
            int keyLength;
            switch (cipher) {
                case AES128: keyLength = 16; break;
                case AES192: keyLength = 24; break;
                case AES256: keyLength = 32; break;
                default: throw new GeneralSecurityException("cipher " + cipher + " is not supported (only AES)");
            }
            int specifier = in.get() & 0xFF;
            int hash = in.get() & 0xFF;
            byte[] salt = new byte[0];
            long count = 0;
            if (specifier == 1 || specifier == S2K_ITERATED_SALTED) {
                salt = new byte[8];
                in.get(salt);
            } else if (specifier != 0) {
                throw new GeneralSecurityException("S2K type " + specifier + " is not supported");
            }
            if (specifier == S2K_ITERATED_SALTED) {
                count = s2kCount(in.get() & 0xFF);
            }
            byte[] iv = new byte[16];
            in.get(iv);
            byte[] encrypted = new byte[in.remaining()];
            in.get(encrypted);
            byte[] aesKey = s2k(hash, salt, count, passphrase, keyLength);
            try {
                Cipher aes = Cipher.getInstance("AES/CFB/NoPadding");
                aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new IvParameterSpec(iv));
                byte[] withChecksum = aes.doFinal(encrypted);
                if (withChecksum.length < 20) {
                    throw new GeneralSecurityException("the secret part is too short");
                }
                plain = Arrays.copyOf(withChecksum, withChecksum.length - 20);
                byte[] checksum = Arrays.copyOfRange(withChecksum, withChecksum.length - 20, withChecksum.length);
                Arrays.fill(withChecksum, (byte) 0);
                if (!MessageDigest.isEqual(checksum, MessageDigest.getInstance("SHA-1").digest(plain))) {
                    Arrays.fill(plain, (byte) 0);
                    throw new GeneralSecurityException("the passphrase is wrong (the SHA-1 checksum does not match)");
                }
            } finally {
                Arrays.fill(aesKey, (byte) 0);
            }
        } else {
            throw new GeneralSecurityException("S2K usage " + usage + " is not supported (only 254 and 0)");
        }
        try {
            ByteBuffer mpis = ByteBuffer.wrap(plain);
            BigInteger d = readMpi(mpis);
            BigInteger p = readMpi(mpis);
            BigInteger q = readMpi(mpis);
            if (!p.multiply(q).equals(key.n)) {
                throw new GeneralSecurityException("the secret primes do not belong to the public key");
            }
            BigInteger one = BigInteger.ONE;
            return KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateCrtKeySpec(key.n, key.e, d, p, q,
                    d.mod(p.subtract(one)), d.mod(q.subtract(one)), q.modInverse(p)));
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    // ---- S2K ----

    /** The number of bytes an iterated S2K hashes, from its one-byte code (RFC 4880 3.7.1.3). */
    static long s2kCount(int coded) {
        return (16L + (coded & 15)) << ((coded >> 4) + 6);
    }

    /**
     * The string-to-key function (RFC 4880 3.7): hashes the salt and the UTF-8 passphrase, over and over until
     * {@code count} bytes have gone in (0 means once), with as many hash contexts as the key needs, each but the
     * first started with that many zero bytes.
     */
    static byte[] s2k(int hashAlgorithm, byte[] salt, long count, char[] passphrase, int keyLength)
            throws GeneralSecurityException {
        ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(passphrase));
        byte[] pass = new byte[encoded.remaining()];
        encoded.get(pass);
        Arrays.fill(encoded.array(), (byte) 0);
        byte[] data = concat(salt, pass);
        Arrays.fill(pass, (byte) 0);
        long total = Math.max(count, data.length);
        // A buffer of the data repeated, so the hash is fed in large chunks.
        int copies = Math.max(1, 65536 / Math.max(1, data.length));
        byte[] repeated = new byte[copies * data.length];
        for (int i = 0; i < copies; i++) {
            System.arraycopy(data, 0, repeated, i * data.length, data.length);
        }
        try {
            byte[] key = new byte[keyLength];
            int filled = 0;
            for (int context = 0; filled < keyLength; context++) {
                MessageDigest md = MessageDigest.getInstance(digestName(hashAlgorithm));
                md.update(new byte[context]);
                long left = total;
                while (left > 0) {
                    int n = (int) Math.min(left, repeated.length);
                    md.update(repeated, 0, n);
                    left -= n;
                }
                byte[] digest = md.digest();
                int take = Math.min(digest.length, keyLength - filled);
                System.arraycopy(digest, 0, key, filled, take);
                filled += take;
                Arrays.fill(digest, (byte) 0);
            }
            return key;
        } finally {
            Arrays.fill(data, (byte) 0);
            Arrays.fill(repeated, (byte) 0);
        }
    }

    // ---- armor ----

    /** ASCII armor (RFC 4880 6.2): BEGIN line, empty line, base64 in lines of 64, "=" and the CRC-24, END line. */
    static String armor(String type, byte[] data) {
        String base64 = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(data);
        int crc = crc24(data);
        String checksum = Base64.getEncoder().encodeToString(
                new byte[] {(byte) (crc >> 16), (byte) (crc >> 8), (byte) crc});
        return "-----BEGIN " + type + "-----\n\n" + base64 + "\n=" + checksum + "\n-----END " + type + "-----\n";
    }

    /** The first armored block in a text: its type (such as "PGP PUBLIC KEY BLOCK") and its bytes. */
    static final class Armored {
        final String type;
        final byte[] data;

        Armored(String type, byte[] data) {
            this.type = type;
            this.data = data;
        }
    }

    /**
     * Reads the first armored block. Header lines are skipped. The CRC-24 is checked when it is there.
     *
     * @throws IllegalArgumentException when there is no block, the base64 is broken or the CRC does not match
     */
    static Armored dearmor(String text) {
        Matcher m = ARMOR.matcher(text);
        if (!m.find()) {
            throw new IllegalArgumentException("no -----BEGIN PGP ...----- block was found");
        }
        String[] lines = m.group(2).split("\\r?\\n", -1);
        int i = 0;
        // Header lines ("Key: value") run until the first empty line. Some writers leave the empty line out.
        if (lines.length > 0 && lines[0].contains(": ")) {
            while (i < lines.length && !lines[i].trim().isEmpty()) {
                i++;
            }
        }
        StringBuilder base64 = new StringBuilder();
        String checksum = null;
        for (; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.startsWith("=") && line.length() == 5) {
                checksum = line.substring(1);
                break;
            }
            base64.append(line);
        }
        byte[] data = Base64.getDecoder().decode(base64.toString());
        if (checksum != null) {
            byte[] c = Base64.getDecoder().decode(checksum);
            int expected = ((c[0] & 0xFF) << 16) | ((c[1] & 0xFF) << 8) | (c[2] & 0xFF);
            if (expected != crc24(data)) {
                throw new IllegalArgumentException("the CRC-24 checksum does not match: the file was changed or damaged");
            }
        }
        return new Armored(m.group(1), data);
    }

    /** CRC-24 as RFC 4880 6.1 defines it. */
    static int crc24(byte[] data) {
        int crc = 0xB704CE;
        for (byte b : data) {
            crc ^= (b & 0xFF) << 16;
            for (int i = 0; i < 8; i++) {
                crc <<= 1;
                if ((crc & 0x1000000) != 0) {
                    crc ^= 0x1864CFB;
                }
            }
        }
        return crc & 0xFFFFFF;
    }

    // ---- packets ----

    /** One packet: its tag and body. */
    static final class Packet {
        final int tag;
        final byte[] body;

        Packet(int tag, byte[] body) {
            this.tag = tag;
            this.body = body;
        }
    }

    /** A packet in the new format (RFC 4880 4.2.2), with a one-, two- or five-octet length. */
    static byte[] packet(int tag, byte[] body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xC0 | tag);
        int length = body.length;
        if (length < 192) {
            out.write(length);
        } else if (length < 8384) {
            out.write(((length - 192) >> 8) + 192);
            out.write((length - 192) & 0xFF);
        } else {
            out.write(0xFF);
            out.write(uint32(length), 0, 4);
        }
        out.write(body, 0, body.length);
        return out.toByteArray();
    }

    /** Splits a block into packets, in the old or the new format. Partial lengths are refused: keys never use them. */
    static List<Packet> packets(byte[] data) throws FailException {
        List<Packet> list = new ArrayList<>();
        ByteBuffer in = ByteBuffer.wrap(data);
        try {
            while (in.hasRemaining()) {
                int first = in.get() & 0xFF;
                if ((first & 0x80) == 0) {
                    throw new FailException("it is not OpenPGP data (bad packet header)");
                }
                int tag;
                long length;
                if ((first & 0x40) != 0) {
                    tag = first & 0x3F;
                    int l = in.get() & 0xFF;
                    if (l < 192) {
                        length = l;
                    } else if (l < 224) {
                        length = ((l - 192) << 8) + (in.get() & 0xFF) + 192;
                    } else if (l == 255) {
                        length = in.getInt() & 0xFFFFFFFFL;
                    } else {
                        throw new FailException("it uses partial packet lengths, which key blocks do not");
                    }
                } else {
                    tag = (first >> 2) & 0x0F;
                    switch (first & 3) {
                        case 0: length = in.get() & 0xFF; break;
                        case 1: length = in.getShort() & 0xFFFF; break;
                        case 2: length = in.getInt() & 0xFFFFFFFFL; break;
                        default: length = in.remaining();
                    }
                }
                if (length > in.remaining()) {
                    throw new FailException("a packet is cut short: the data was truncated");
                }
                byte[] body = new byte[(int) length];
                in.get(body);
                list.add(new Packet(tag, body));
            }
        } catch (java.nio.BufferUnderflowException e) {
            throw new FailException("a packet header is cut short: the data was truncated", e);
        }
        return list;
    }

    /** One signature subpacket with a one-octet length (all of ours are shorter than 192 bytes). */
    private static void subpacket(ByteArrayOutputStream out, int type, byte[] data) {
        out.write(data.length + 1);
        out.write(type);
        out.write(data, 0, data.length);
    }

    /** Reads a subpacket length (RFC 4880 5.2.3.1). */
    private static int subpacketLength(ByteBuffer in) {
        int l = in.get() & 0xFF;
        if (l < 192) {
            return l;
        }
        if (l < 255) {
            return ((l - 192) << 8) + (in.get() & 0xFF) + 192;
        }
        return in.getInt();
    }

    /** A multiprecision integer: the bit count in two octets, then the big-endian bytes without leading zeros. */
    static byte[] mpi(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return concat(uint16(value.bitLength()), bytes);
    }

    private static BigInteger readMpi(ByteBuffer in) {
        int bits = in.getShort() & 0xFFFF;
        byte[] bytes = new byte[(bits + 7) / 8];
        in.get(bytes);
        return new BigInteger(1, bytes);
    }

    /** What goes before a key in a signature hash: 0x99 and the two-octet length of the body. */
    private static byte[] keyHashPrefix(byte[] publicBody) {
        return concat(new byte[] {(byte) 0x99}, uint16(publicBody.length));
    }

    /** What goes before a user ID in a certification hash: 0xB4 and the four-octet length. */
    private static byte[] uidHashPrefix(byte[] uid) {
        return concat(new byte[] {(byte) 0xB4}, uint32(uid.length));
    }

    /** The v4 signature trailer: 0x04, 0xFF and the four-octet length of the hashed head. */
    private static byte[] trailer(byte[] head) {
        return concat(new byte[] {4, (byte) 0xFF}, uint32(head.length));
    }

    private static byte[] leftPad(byte[] bytes, int length) {
        if (bytes.length > length && bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, bytes.length - length, bytes.length);
        }
        if (bytes.length >= length) {
            return bytes;
        }
        byte[] padded = new byte[length];
        System.arraycopy(bytes, 0, padded, length - bytes.length, bytes.length);
        return padded;
    }

    static byte[] uint16(int value) {
        return new byte[] {(byte) (value >> 8), (byte) value};
    }

    static byte[] uint32(long value) {
        return new byte[] {(byte) (value >> 24), (byte) (value >> 16), (byte) (value >> 8), (byte) value};
    }

    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.write(part, 0, part.length);
        }
        return out.toByteArray();
    }

    static String hex(byte[] bytes) {
        StringBuilder s = new StringBuilder();
        for (byte b : bytes) {
            s.append(String.format("%02X", b & 0xFF));
        }
        return s.toString();
    }
}
