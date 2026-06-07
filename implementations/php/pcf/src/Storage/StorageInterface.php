<?php

declare(strict_types=1);

namespace Kduma\PCF\Storage;

/**
 * A random-access byte store backing a {@see \Kduma\PCF\Container}.
 *
 * This is the PHP analogue of the reference implementation's
 * `Read + Write + Seek` bound: the container reads and writes fixed-size fields
 * at absolute offsets and never relies on a streaming cursor. Writing past the
 * current end of the store extends it (any gap is zero-filled).
 */
interface StorageInterface
{
    /**
     * Read exactly $length bytes starting at absolute offset $offset.
     *
     * @throws \Kduma\PCF\PcfException if fewer than $length bytes are available.
     */
    public function readAt(int $offset, int $length): string;

    /** Write $data at absolute offset $offset, extending the store as needed. */
    public function writeAt(int $offset, string $data): void;

    /** Current size of the store, in bytes. */
    public function size(): int;
}
