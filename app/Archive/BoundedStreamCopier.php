<?php
declare(strict_types=1);

namespace SecurePackage\Archive;

use RuntimeException;

/**
 * Copies one archive entry while enforcing limits against bytes actually streamed.
 * ZIP central-directory sizes are treated as hints, never as the only safety boundary.
 */
final class BoundedStreamCopier
{
    private const CHUNK_BYTES = 1024 * 1024;

    /**
     * @param resource $source
     * @param resource $destination
     */
    public function copy($source, $destination, int $maxFileBytes, int $maxTotalBytes): int
    {
        if (!is_resource($source) || !is_resource($destination)) {
            throw new RuntimeException('Invalid archive stream.');
        }
        if ($maxFileBytes < 0 || $maxTotalBytes < 0) {
            throw new RuntimeException('Invalid archive extraction limit.');
        }

        $copied = 0;
        while (!feof($source)) {
            $remainingFile = $maxFileBytes - $copied;
            $remainingTotal = $maxTotalBytes - $copied;
            $readLength = max(1, min(self::CHUNK_BYTES, $remainingFile + 1, $remainingTotal + 1));
            $chunk = fread($source, $readLength);
            if ($chunk === false) {
                throw new RuntimeException('Unable to read archive content.');
            }
            if ($chunk === '') {
                if (feof($source)) {
                    break;
                }
                throw new ArchiveProcessingException('Archive stream stopped unexpectedly.');
            }

            $length = strlen($chunk);
            if ($copied + $length > $maxFileBytes || $copied + $length > $maxTotalBytes) {
                throw new ArchiveProcessingException('Archive extraction limit exceeded.');
            }

            $offset = 0;
            while ($offset < $length) {
                $written = fwrite($destination, substr($chunk, $offset));
                if ($written === false || $written === 0) {
                    throw new RuntimeException('Unable to write extracted content.');
                }
                $offset += $written;
            }
            $copied += $length;
        }

        return $copied;
    }
}
