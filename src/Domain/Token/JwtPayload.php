<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use function json_decode;
use function json_encode;
use const JSON_PRESERVE_ZERO_FRACTION;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;
use JsonException;
use stdClass;

/**
 * RFC 7519 §3
 */
final readonly class JwtPayload
{
    /**
     * An empty claims set is "{}", which json_encode() would write as "[]".
     *
     * @param array<string, mixed> $claims
     */
    public static function encode(array $claims): string
    {
        if ($claims === []) {
            return '{}';
        }

        return json_encode($claims, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
    }

    /**
     * RFC 7519 §4.1.3, §7.2
     *
     * Decoded into arrays, a JSON object whose keys are "0", "1"… is a list: an "aud" that is an object is handed over
     * as the object it is, which no reading of an audience takes.
     *
     * @param int<1, max> $maxDepth
     *
     * @throws JsonException when the payload is no JSON, or is nested deeper than $maxDepth
     *
     * @return array<array-key, mixed>|null null when the payload is no JSON object
     */
    public static function decode(string $payload, int $maxDepth): ?array
    {
        $object = json_decode($payload, false, $maxDepth, JSON_THROW_ON_ERROR);
        if (! $object instanceof stdClass) {
            return null;
        }
        $claims = (array) json_decode($payload, true, $maxDepth, JSON_THROW_ON_ERROR);
        if (isset($object->aud) && $object->aud instanceof stdClass) {
            $claims['aud'] = $object->aud;
        }

        return $claims;
    }
}
