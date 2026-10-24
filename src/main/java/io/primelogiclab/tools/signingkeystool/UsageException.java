package io.primelogiclab.tools.signingkeystool;

/**
 * The command line is wrong: an unknown command or option, a missing value, or a value that is not allowed.
 * Nothing has been read or written. The tool prints the message and the usage text, and exits with 2.
 */
final class UsageException extends Exception {

    private static final long serialVersionUID = 1L;

    UsageException(String message) {
        super(message);
    }
}
