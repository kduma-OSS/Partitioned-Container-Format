<?php

declare(strict_types=1);

namespace Kduma\PCFDCP;

/** Static helpers for walking and reconstructing Fragment Tables. */
final class FragmentTable
{
    private function __construct()
    {
    }

    /**
     * Walk an inner partition's Fragment Table chain starting at arena-relative
     * $firstOff, returning its entries in logical order.
     *
     * @return FragmentEntry[]
     */
    public static function walk(string $arena, int $firstOff): array
    {
        $out = [];
        $off = $firstOff;
        $len = \strlen($arena);
        $budget = intdiv($len, Consts::FRAGTABLE_HEADER_SIZE) + 1;
        while ($off !== Consts::ARENA_NONE) {
            if ($budget === 0) {
                throw PcfDcpException::offsetOutOfRange();
            }
            --$budget;
            if ($off + Consts::FRAGTABLE_HEADER_SIZE > $len) {
                throw PcfDcpException::offsetOutOfRange();
            }
            $h = FragTableHeader::fromBytes($arena, $off);
            $eo = $off + Consts::FRAGTABLE_HEADER_SIZE;
            for ($i = 0; $i < $h->fragmentCount; ++$i) {
                if ($eo + Consts::FRAGMENT_ENTRY_SIZE > $len) {
                    throw PcfDcpException::offsetOutOfRange();
                }
                $out[] = FragmentEntry::fromBytes($arena, $eo);
                $eo += Consts::FRAGMENT_ENTRY_SIZE;
            }
            $off = $h->nextFragtableOffset;
        }

        return $out;
    }

    /**
     * Reconstruct the logical content from Fragment Entries (spec Section 8.3):
     * concatenate the bytes of the DATA extents in order.
     *
     * @param FragmentEntry[] $frags
     */
    public static function reconstruct(string $arena, array $frags, int $arenaUsed): string
    {
        $len = \strlen($arena);
        $out = '';
        foreach ($frags as $f) {
            if (!$f->isData()) {
                throw PcfDcpException::badFragmentKind($f->kind);
            }
            $end = $f->extentOffset + $f->extentLength;
            if ($end > $arenaUsed || $end > $len) {
                throw PcfDcpException::offsetOutOfRange();
            }
            $out .= substr($arena, $f->extentOffset, $f->extentLength);
        }

        return $out;
    }
}
