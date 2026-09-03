<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use RuntimeException;

/**
 * The bundled SARIF version/schema artifact could not be read as written.
 *
 * Thrown rather than defaulted, and that is the whole point. The pair it holds is what a SARIF
 * document DECLARES ITSELF to be — a consumer's validator resolves the schema from it and a security
 * tab decides how to read the file. Falling back to a hard-coded pair would let a broken installation
 * publish a document claiming a version nobody shipped, which is a lie with the shape of a success.
 *
 * The same rule every other bundled read in this package follows: a missing artifact is a broken
 * installation, not a state to guess around.
 */
final class UnreadableSarifSchema extends RuntimeException
{
    public static function at(string $path): self
    {
        return new self(
            "The SARIF schema artifact \"{$path}\" is missing or does not declare both `sarif_version` and `schema_url`."
        );
    }
}
