/**
 * signing-keys-tool: a command-line tool that creates and checks RSA key pairs for digital signatures (SHA256withRSA,
 * the RS256 of JWTs), one pair per environment or client, using only the JDK.
 *
 * {@link io.primelogiclab.tools.signingkeystool.SigningKeysTool} is the entry point and reads the command line.
 * KeyFiles writes and checks one pair on disk, Keytool runs the JDK's keytool to make the pair and its
 * self-signed certificate, and Pem reads and writes the PEM text the files are stored in.
 */
package io.primelogiclab.tools.signingkeystool;
