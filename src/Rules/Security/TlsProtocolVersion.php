<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

/**
 * The TLS version names a server can report, IN ORDER — and the order is the whole point.
 *
 * ## Why this is not a string comparison
 *
 * `'TLSv1.10' < 'TLSv1.2'` is true in every string comparison there is, because `1` sorts before `2`
 * one character at a time. A rule that compared names would rank a hypothetical TLS 1.10 below the
 * floor and report a server that is stricter than required — the worst kind of false positive, one
 * that tells somebody to weaken their configuration.
 *
 * ## Why the list is short, and why it is still a list
 *
 * PostgreSQL declares this parameter as an ENUM, and the enum's declared order IS this order.
 * Measured on 18.4 rather than remembered:
 *
 *     name                      vartype  enumvals
 *     ssl_min_protocol_version  enum     {TLSv1,TLSv1.1,TLSv1.2,TLSv1.3}
 *
 * So the name `TLSv1.10` cannot occur: the server rejects a value outside its enum at startup, and a
 * reader would never see it. That makes the sorting trap unreachable through PostgreSQL today —
 * which is an argument for writing the comparison correctly and NOT for skipping it, because the
 * unreachability is a property of one server's parameter validation rather than of this package. The
 * MySQL side reads `tls_version`, a comma-separated LIST whose members are spelled differently
 * again, and any future member arrives here as a name this class has to place.
 *
 * An unknown name is therefore `null` rather than a guess. A rule that cannot place a value has not
 * measured it, and the honest answer is `undetermined` with a reason — never a comparison against a
 * position nobody established.
 */
final readonly class TlsProtocolVersion
{
    /**
     * Oldest first. The index IS the rank; nothing else about this list is load-bearing.
     *
     * @var list<string>
     */
    public const array ORDER = [
        'TLSv1',
        'TLSv1.1',
        'TLSv1.2',
        'TLSv1.3',
    ];

    /**
     * Where a reported name sits in that order, or null when this class cannot place it.
     *
     * Case and surrounding space are normalized because the value can arrive from a configuration
     * file as well as from the catalog, and `tlsv1.2` is the same server setting written by a
     * different hand. Nothing else is normalized: `TLS1.2` is a name this class has not measured,
     * and treating it as a synonym would be exactly the guess the class exists to refuse.
     */
    public static function rank(string $name): ?int
    {
        $normalized = strtolower(trim($name));

        foreach (self::ORDER as $index => $candidate) {
            if (strtolower($candidate) === $normalized) {
                return $index;
            }
        }

        return null;
    }

    /**
     * Is `$value` older than `$floor`? Null when either name could not be placed.
     *
     * Three-valued on purpose. A boolean would have to answer false for "I could not tell", and
     * false here means "this server is fine" — the silent green this package refuses.
     */
    public static function isBelow(string $value, string $floor): ?bool
    {
        $left = self::rank($value);
        $right = self::rank($floor);

        if ($left === null || $right === null) {
            return null;
        }

        return $left < $right;
    }
}
