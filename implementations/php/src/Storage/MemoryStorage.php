<?php

declare(strict_types=1);

namespace Kduma\PCF\Storage;

use Kduma\PCF\PcfException;

/**
 * In-memory byte store backed by a PHP string. The analogue of the reference
 * implementation's `Cursor<Vec<u8>>`: ideal for building containers in memory,
 * tests, and producing the canonical compacted image.
 */
final class MemoryStorage implements StorageInterface
{
    public function __construct(private string $buffer = '')
    {
    }

    public function readAt(int $offset, int $length): string
    {
        if ($length === 0) {
            return '';
        }
        if ($offset < 0 || $offset + $length > \strlen($this->buffer)) {
            throw PcfException::io('short read: requested range past end of buffer');
        }

        return substr($this->buffer, $offset, $length);
    }

    public function writeAt(int $offset, string $data): void
    {
        if ($data === '') {
            return;
        }
        $size = \strlen($this->buffer);
        if ($offset > $size) {
            // Zero-fill the gap so writes past the end behave like a sparse file.
            $this->buffer .= str_repeat("\x00", $offset - $size);
        }
        $this->buffer = substr_replace($this->buffer, $data, $offset, \strlen($data));
    }

    public function size(): int
    {
        return \strlen($this->buffer);
    }

    /** The raw bytes held by this store. */
    public function getContents(): string
    {
        return $this->buffer;
    }
}
