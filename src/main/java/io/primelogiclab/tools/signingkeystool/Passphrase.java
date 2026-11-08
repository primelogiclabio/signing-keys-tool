package io.primelogiclab.tools.signingkeystool;

import java.io.Console;
import java.util.Arrays;

/**
 * Where the passphrase of an OpenPGP secret key comes from. Never from the command line, where other processes
 * and the shell history could see it: from the environment variable {@link #VARIABLE}, or else typed at a
 * console prompt that does not echo. The tool never prints it.
 */
interface Passphrase {

    /** The environment variable that holds the passphrase, for scripts and CI. */
    String VARIABLE = "SIGNING_KEYS_PASSPHRASE";

    /**
     * The passphrase, or null when there is none to be had (no variable and no console). The caller clears the
     * array when done.
     *
     * @param confirm true when a new passphrase is being set, so a typed one is asked for twice
     * @throws FailException when the two typed copies differ
     */
    char[] get(boolean confirm) throws FailException;

    /** The environment variable, else the console. */
    Passphrase DEFAULT = confirm -> {
        String fromEnvironment = System.getenv(VARIABLE);
        if (fromEnvironment != null && !fromEnvironment.isEmpty()) {
            return fromEnvironment.toCharArray();
        }
        Console console = System.console();
        if (console == null) {
            return null;
        }
        char[] first = console.readPassword("Passphrase for the OpenPGP secret key: ");
        if (first == null) {
            return null;
        }
        if (confirm) {
            char[] second = console.readPassword("Type it again: ");
            boolean same = Arrays.equals(first, second);
            if (second != null) {
                Arrays.fill(second, '\0');
            }
            if (!same) {
                Arrays.fill(first, '\0');
                throw new FailException("The two passphrases differ. Nothing was written.");
            }
        }
        return first;
    };
}
