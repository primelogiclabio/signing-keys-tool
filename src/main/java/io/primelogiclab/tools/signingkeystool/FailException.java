package io.primelogiclab.tools.signingkeystool;

/**
 * The command line is right but the work failed: a file already exists, a key does not load, the two keys are not
 * a pair, the key has expired, or keytool failed. The tool prints the message and exits with 1.
 */
final class FailException extends Exception {

    private static final long serialVersionUID = 1L;

    FailException(String message) {
        super(message);
    }

    FailException(String message, Throwable cause) {
        super(message, cause);
    }
}
