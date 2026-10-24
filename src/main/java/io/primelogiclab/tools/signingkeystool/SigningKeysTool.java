package io.primelogiclab.tools.signingkeystool;

import java.io.PrintStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Clock;

/**
 * The command line of signing-keys-tool, which creates and checks RSA key pairs for digital signatures
 * (SHA256withRSA, the RS256 of JWTs), one pair per environment or client. It uses only the JDK, so there is
 * nothing else to install.
 *
 * The commands: generate writes a new pair ({@link KeyFiles#generate}), check reads a pair back
 * ({@link KeyFiles#check}), and help prints {@link #USAGE}.
 *
 * Exit codes: 0 done, 1 the work failed (a file exists, a key does not load, the pair does not match, the
 * key has expired), 2 the command line is wrong.
 */
public final class SigningKeysTool {

    /** The folder inside java.io.tmpdir that pairs go to when --out is not given. */
    private static final String DEFAULT_OUT_NAME = "signing-keys";

    /** Where pairs go when --out is not given: signing-keys, inside java.io.tmpdir. Fine for a trial, not for real keys. */
    private static Path defaultOut() {
        return Paths.get(System.getProperty("java.io.tmpdir")).resolve(DEFAULT_OUT_NAME);
    }

    /** The help text. help prints it, and so does every command-line error, after the message. */
    static final String USAGE =
            "signing-keys-tool: creates and checks RSA key pairs for digital signatures (SHA256withRSA, the RS256 of JWTs).\n"
            + "\n"
            + "Usage:\n"
            + "  signing-keys-tool generate --env <environment> [--client <client>] [--out <folder>]\n"
            + "                             [--name <file prefix>] [--bits 2048|3072|4096] [--days <days>] [--force]\n"
            + "  signing-keys-tool check <folder> [--name <file prefix>]\n"
            + "  signing-keys-tool check --env <environment> [--client <client>] [--out <folder>]\n"
            + "                          [--name <file prefix>]\n"
            + "  signing-keys-tool help\n"
            + "\n"
            + "generate writes <out>/<environment>[/<client>]/<name>-private.pem, <name>-public.pem and <name>-cert.pem,\n"
            + "then reads them back and checks them. It refuses to replace files that exist unless you give --force.\n"
            + "The certificate is self-signed and holds the expiry. It is made with the keytool of the Java that runs this.\n"
            + "  --env     the environment the pair is for, such as dev, qa or prod (required)\n"
            + "  --client  the client the pair is for, when each client has its own pair\n"
            + "  --out     where to write, default: signing-keys in the Java temp folder (java.io.tmpdir)\n"
            + "  --name    the start of the file names, default: signing\n"
            + "  --bits    the key size, default: 2048\n"
            + "  --days    how long the pair is valid, 1 to 3650, default: 1825 (5 years)\n"
            + "\n"
            + "check reads <name>-public.pem and, if they are there, <name>-private.pem and <name>-cert.pem, the way a\n"
            + "verifying app would. With both keys it signs a test string and checks it, and prints 'pair OK'. With the\n"
            + "public key alone, as on an app that only verifies signatures, it prints the fingerprint so you can compare\n"
            + "it with the signer's. With the certificate it prints the expiry, warns when 30 days or fewer are left and\n"
            + "fails when the key has expired.\n"
            + "\n"
            + "The private key is PKCS#8 (-----BEGIN PRIVATE KEY-----) with no password. The public key is X.509\n"
            + "(-----BEGIN PUBLIC KEY-----). Exit codes: 0 done, 1 failed, 2 wrong command line.\n";

    private SigningKeysTool() { }

    /**
     * Runs one command and exits with its code: 0 done, 1 failed, 2 wrong command line.
     *
     * @param args the command (generate, check or help) followed by its options
     */
    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    /** Runs one command with the real clock. Separate from main() so the tests can call it and read what it printed. */
    static int run(String[] args, PrintStream out, PrintStream err) {
        return run(args, out, err, Clock.systemUTC());
    }

    /**
     * Runs one command and returns its exit code instead of exiting. Results go to out; errors and warnings go
     * to err. The clock is what "now" means when check decides whether a key has expired, so tests can move it.
     */
    static int run(String[] args, PrintStream out, PrintStream err, Clock clock) {
        try {
            if (args.length == 0) {
                throw new UsageException("Give a command: generate, check or help.");
            }
            String command = args[0];
            switch (command) {
                case "help":
                case "--help":
                case "-h":
                    out.print(USAGE);
                    return 0;
                case "generate":
                    generate(options(args), out, err, clock);
                    return 0;
                case "check":
                    check(options(args), out, err, clock);
                    return 0;
                default:
                    throw new UsageException("Unknown command '" + command + "'.");
            }
        } catch (UsageException e) {
            err.println("error: " + e.getMessage());
            err.println();
            err.print(USAGE);
            return 2;
        } catch (FailException e) {
            err.println("error: " + e.getMessage());
            return 1;
        }
    }

    /**
     * The generate command. Checks every option before anything is made, then makes the pair with
     * {@link KeyFiles#generate} and prints where the files went, the fingerprint and the expiry. The
     * certificate's common name is {@code <name> <env> [<client>]}, so the certificate says what it is for.
     */
    private static void generate(Options o, PrintStream out, PrintStream err, Clock clock)
            throws UsageException, FailException {
        if (o.folder != null) {
            throw new UsageException("generate does not take a folder. Use --out, --env and --client.");
        }
        String name = o.name == null ? KeyFiles.DEFAULT_NAME : o.name;
        KeyFiles.requireSafeName("--name", name);
        Path folder = keyFolder(o);
        int bits = KeyFiles.DEFAULT_BITS;
        if (o.bits != null) {
            try {
                bits = Integer.parseInt(o.bits);
            } catch (NumberFormatException e) {
                throw new UsageException("--bits '" + o.bits + "' is not a number. Use 2048, 3072 or 4096.");
            }
            if (!KeyFiles.isAllowedBits(bits)) {
                throw new UsageException("--bits " + bits + " is not allowed. Use 2048, 3072 or 4096.");
            }
        }

        int days = KeyFiles.DEFAULT_DAYS;
        if (o.days != null) {
            try {
                days = Integer.parseInt(o.days);
            } catch (NumberFormatException e) {
                throw new UsageException("--days '" + o.days + "' is not a number. Use 1 to " + KeyFiles.MAX_DAYS + ".");
            }
            if (!KeyFiles.isAllowedDays(days)) {
                throw new UsageException("--days " + days + " is not allowed. Use 1 to " + KeyFiles.MAX_DAYS + ".");
            }
        }

        KeyFiles files = new KeyFiles(folder, name, err, clock);
        String subject = name + " " + o.env + (o.client == null ? "" : " " + o.client);
        KeyFiles.Report report = files.generate(bits, days, subject, o.force);

        out.println("Created the " + name + " key pair for " + o.env + (o.client == null ? "" : " / " + o.client));
        out.println("  private key  " + files.privateFile());
        out.println("  public key   " + files.publicFile());
        out.println("  certificate  " + files.certFile());
        out.println("  key          RSA " + report.bits + " bits (SHA256withRSA / RS256)");
        out.println("  fingerprint  SHA-256 of the public key: " + report.fingerprint);
        out.println("  expires      " + expiry(report, name));
        out.println("  check        pair OK");
        out.println();
        out.println("The private key goes only to the app that signs. Every app that verifies signatures gets the");
        out.println("public key only. Keep the private key out of source control. Keep the certificate beside the");
        out.println("public key, so 'check' can warn there before the key expires.");
    }

    /**
     * The check command. Finds the folder, either given directly or built from --env, --client and --out, reads
     * the pair with {@link KeyFiles#check} and prints what it found. An expiry 30 days away or closer is a warning
     * on err, not a failure, so the exit code stays 0 until the key has actually expired.
     */
    private static void check(Options o, PrintStream out, PrintStream err, Clock clock)
            throws UsageException, FailException {
        if (o.bits != null || o.days != null || o.force) {
            throw new UsageException("--bits, --days and --force are for generate only.");
        }
        String name = o.name == null ? KeyFiles.DEFAULT_NAME : o.name;
        KeyFiles.requireSafeName("--name", name);
        Path folder;
        if (o.folder != null) {
            if (o.env != null || o.client != null || o.out != null) {
                throw new UsageException("Give either a folder or --env (with --client and --out), not both.");
            }
            folder = Paths.get(o.folder).toAbsolutePath().normalize();
        } else {
            folder = keyFolder(o);
        }

        KeyFiles files = new KeyFiles(folder, name, err, clock);
        KeyFiles.Report report = files.check();

        out.println("Checked " + folder);
        out.println("  public key   RSA " + report.bits + " bits (SHA256withRSA / RS256)");
        out.println("  fingerprint  SHA-256 of the public key: " + report.fingerprint);
        out.println("  expires      " + expiry(report, name));
        out.println("  check        " + (report.pairChecked
                ? "pair OK"
                : "public key only. There is no " + name + "-private.pem here, so no pair was checked."));
        if (report.expiresSoon()) {
            err.println("warning: the key expires on " + KeyFiles.date(report.notAfter) + ", in " + report.daysLeft
                    + (report.daysLeft == 1 ? " day" : " days") + ". Plan a new pair.");
        }
    }

    /** The expiry line: the date and the days left, or "unknown" when the folder has no certificate. */
    private static String expiry(KeyFiles.Report report, String name) {
        if (report.notAfter == null) {
            return "unknown. There is no " + name + "-cert.pem here, so the expiry is not known.";
        }
        return KeyFiles.date(report.notAfter) + " (" + report.daysLeft + (report.daysLeft == 1 ? " day" : " days")
                + " left)";
    }

    /**
     * The folder for a pair, {@code <out>/<env>[/<client>]}, as an absolute path. Each part is checked first,
     * because it becomes a folder name and must not lead out of {@code <out>}.
     */
    private static Path keyFolder(Options o) throws UsageException {
        if (o.env == null) {
            throw new UsageException("--env is required. Name the environment this pair is for, such as dev, qa or prod.");
        }
        KeyFiles.requireSafeName("--env", o.env);
        Path folder = (o.out == null ? defaultOut() : Paths.get(o.out)).resolve(o.env);
        if (o.client != null) {
            KeyFiles.requireSafeName("--client", o.client);
            folder = folder.resolve(o.client);
        }
        return folder.toAbsolutePath().normalize();
    }

    /**
     * The options after the command word, as given. Numbers stay text until the command that uses them checks
     * them, so the error can quote what was typed. A null field means the option was not given.
     */
    private static final class Options {
        String env;
        String client;
        String out;
        String name;
        String bits;
        String days;
        boolean force;
        /** The one argument that is not an option: the folder for check. */
        String folder;
    }

    /** Reads the options after the command word. Anything that does not start with "--" is the folder. */
    private static Options options(String[] args) throws UsageException {
        Options o = new Options();
        for (int i = 1; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "--env":
                    o.env = value(args, ++i, arg);
                    break;
                case "--client":
                    o.client = value(args, ++i, arg);
                    break;
                case "--out":
                    o.out = value(args, ++i, arg);
                    break;
                case "--name":
                    o.name = value(args, ++i, arg);
                    break;
                case "--bits":
                    o.bits = value(args, ++i, arg);
                    break;
                case "--days":
                    o.days = value(args, ++i, arg);
                    break;
                case "--force":
                    o.force = true;
                    break;
                default:
                    if (arg.startsWith("--")) {
                        throw new UsageException("Unknown option '" + arg + "'.");
                    }
                    if (o.folder != null) {
                        throw new UsageException("Only one folder can be given, but there are two: '" + o.folder + "' and '" + arg + "'.");
                    }
                    o.folder = arg;
            }
        }
        return o;
    }

    /**
     * The value that follows an option. A missing value is a usage error, and so is another option in its place,
     * so "--env --force" does not create an environment called "--force".
     */
    private static String value(String[] args, int index, String option) throws UsageException {
        if (index >= args.length || args[index].startsWith("--")) {
            throw new UsageException(option + " needs a value.");
        }
        return args[index];
    }
}
