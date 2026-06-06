<?php

declare(strict_types=1);

namespace Kduma\PCF\Storage;

use Kduma\PCF\PcfException;

/**
 * Byte store backed by a seekable PHP stream resource (e.g. a file opened with
 * fopen). The analogue of the reference implementation's `std::fs::File`.
 */
final class StreamStorage implements StorageInterface
{
    /** @var resource */
    private $stream;

    private bool $ownsStream;

    /**
     * @param resource $stream A seekable stream opened for reading (and writing,
     *                         if the container will be modified).
     */
    public function __construct($stream, bool $ownsStream = false)
    {
        if (!\is_resource($stream)) {
            throw PcfException::io('StreamStorage requires a valid stream resource');
        }
        $this->stream = $stream;
        $this->ownsStream = $ownsStream;
    }

    /**
     * Open a file path as a stream store. Use mode "r" for read-only,
     * "c+"/"r+" for read-write.
     */
    public static function fromFile(string $path, string $mode = 'c+'): self
    {
        $stream = @fopen($path, $mode);
        if ($stream === false) {
            throw PcfException::io("could not open file: {$path}");
        }

        return new self($stream, true);
    }

    public function readAt(int $offset, int $length): string
    {
        if ($length === 0) {
            return '';
        }
        if (@fseek($this->stream, $offset) !== 0) {
            throw PcfException::io("seek failed at offset {$offset}");
        }
        $data = '';
        $remaining = $length;
        while ($remaining > 0) {
            $chunk = fread($this->stream, $remaining);
            if ($chunk === false || $chunk === '') {
                break;
            }
            $data .= $chunk;
            $remaining -= \strlen($chunk);
        }
        if (\strlen($data) !== $length) {
            throw PcfException::io('short read: requested range past end of stream');
        }

        return $data;
    }

    public function writeAt(int $offset, string $data): void
    {
        if ($data === '') {
            return;
        }
        if (@fseek($this->stream, $offset) !== 0) {
            throw PcfException::io("seek failed at offset {$offset}");
        }
        $written = fwrite($this->stream, $data);
        if ($written === false || $written !== \strlen($data)) {
            throw PcfException::io('short write to stream');
        }
        fflush($this->stream);
    }

    public function size(): int
    {
        $stat = fstat($this->stream);
        if ($stat === false) {
            throw PcfException::io('could not stat stream');
        }

        return $stat['size'];
    }

    public function __destruct()
    {
        if ($this->ownsStream && \is_resource($this->stream)) {
            fclose($this->stream);
        }
    }
}
