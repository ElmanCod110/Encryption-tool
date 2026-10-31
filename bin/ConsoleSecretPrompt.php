<?php
declare(strict_types=1);

/**
 * Local CLI-only hidden secret input. Prefer environment variables for
 * non-interactive automation; never pass credentials as command-line arguments.
 */
final class ConsoleSecretPrompt
{
    public static function read(string $prompt, string $environmentName): string
    {
        $environmentValue = getenv($environmentName);
        if ($environmentValue !== false) {
            putenv($environmentName);
            return $environmentValue;
        }

        if (PHP_OS_FAMILY === 'Windows') {
            return self::readWindows($prompt);
        }

        $tty = @fopen('/dev/tty', 'r+');
        if (!is_resource($tty)) {
            throw new RuntimeException('No interactive terminal. Set ' . $environmentName . ' in the process environment.');
        }
        $stateLines = [];
        $stateStatus = 0;
        exec('stty -g < /dev/tty 2>/dev/null', $stateLines, $stateStatus);
        $state = $stateStatus === 0 ? trim(implode("\n", $stateLines)) : '';
        if ($state === '') {
            fclose($tty);
            throw new RuntimeException('Unable to protect terminal input. Set ' . $environmentName . ' in the process environment.');
        }

        $status = 0;
        exec('stty -echo < /dev/tty 2>/dev/null', $unused, $status);
        if ($status !== 0) {
            fclose($tty);
            throw new RuntimeException('Unable to disable terminal echo for secret input.');
        }

        fwrite(STDERR, $prompt . ': ');
        try {
            $line = fgets($tty);
            if (!is_string($line)) throw new RuntimeException('Unable to read secret input.');
            $secret = rtrim($line, "\r\n");
            sodium_memzero($line);
            return $secret;
        } finally {
            exec('stty ' . escapeshellarg($state) . ' < /dev/tty 2>/dev/null', $unused, $restoreStatus);
            fwrite(STDERR, "\n");
            fclose($tty);
            if ($restoreStatus !== 0) {
                fwrite(STDERR, "Warning: terminal echo restoration failed; run 'stty echo' in the terminal.\n");
            }
        }
    }

    private static function readWindows(string $prompt): string
    {
        $safePrompt = str_replace("'", "''", $prompt);
        $script = '$secure = Read-Host -Prompt \''
            . $safePrompt
            . '\' -AsSecureString; $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure); '
            . 'try { [Console]::WriteLine([Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)) } '
            . 'finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }';
        $command = 'powershell.exe -NoLogo -NoProfile -Command ' . escapeshellarg($script);
        $output = [];
        $status = 0;
        exec($command, $output, $status);
        if ($status !== 0) throw new RuntimeException('Hidden secret prompt failed; set the matching environment variable instead.');
        $secret = rtrim(implode("\n", $output), "\r\n");
        foreach ($output as &$line) { if ($line !== '') sodium_memzero($line); }
        unset($line);
        return $secret;
    }
}
