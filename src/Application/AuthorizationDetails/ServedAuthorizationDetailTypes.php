<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\AuthorizationDetails;

use function array_is_list;
use function array_keys;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetail;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetailTypeInterface;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\AuthorizationDetailsReaderInterface;
use Beffroi\Oidc\Port\ServedAuthorizationDetailTypesInterface;
use function implode;
use function is_array;
use function is_string;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use JsonException;
use function sprintf;

/**
 * Types are read when asked, not at construction: a client registration asks them while clients are being built.
 */
final readonly class ServedAuthorizationDetailTypes implements AuthorizationDetailsReaderInterface, ServedAuthorizationDetailTypesInterface
{
    /**
     * Deep enough for a member object holding a list of scalars; deeper was not asked for here.
     */
    private const int MAX_DEPTH = 6;

    /**
     * @param iterable<AuthorizationDetailTypeInterface> $types
     */
    public function __construct(
        private iterable $types,
    ) {
    }

    public function servedAuthorizationDetailTypes(): array
    {
        return array_keys($this->wired());
    }

    public function fromJson(string $json): AuthorizationDetails
    {
        try {
            $decoded = json_decode($json, true, self::MAX_DEPTH, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException('An authorization_details parameter is valid JSON (RFC 9396 section 2).', previous: $exception);
        }

        return $this->fromClaim($decoded);
    }

    public function fromClaim(mixed $claim): AuthorizationDetails
    {
        if (! is_array($claim) || ! array_is_list($claim)) {
            throw new InvalidArgumentException('An authorization_details is a JSON array of objects (RFC 9396 section 2).');
        }
        $wired = $this->wired();
        $details = [];
        foreach ($claim as $object) {
            if (! is_array($object) || array_is_list($object) && $object !== []) {
                throw new InvalidArgumentException('Every element of an authorization_details is a JSON object (RFC 9396 section 2).');
            }
            $name = $object[AuthorizationDetail::TYPE] ?? null;
            if (! is_string($name) || $name === '') {
                throw new InvalidArgumentException('Every element of an authorization_details names its type in a "type" member (RFC 9396 section 2).');
            }
            $type = $wired[$name] ?? throw new InvalidArgumentException(sprintf(
                'The authorization detail type "%s" is not one this provider serves; it serves %s.',
                $name,
                $wired === [] ? 'none' : implode(', ', array_keys($wired)),
            ));
            unset($object[AuthorizationDetail::TYPE]);
            $details[] = $type->of(self::members($name, $object));
        }

        return new AuthorizationDetails($details);
    }

    /**
     * json_decode() turns a member name made of digits into an integer key, which names no member.
     *
     * @param array<array-key, mixed> $members
     *
     * @throws InvalidArgumentException
     *
     * @return array<string, mixed>
     */
    private static function members(string $type, array $members): array
    {
        $named = [];
        foreach ($members as $name => $value) {
            if (! is_string($name)) {
                throw new InvalidArgumentException(sprintf(
                    'The members of an authorization detail of the type "%s" are named, and a name made of digits is not a name (RFC 9396 section 2).',
                    $type,
                ));
            }
            $named[$name] = $value;
        }

        return $named;
    }

    /**
     * @throws InvalidArgumentException when two wired types answer for one "type"
     *
     * @return array<non-empty-string, AuthorizationDetailTypeInterface> by type name
     */
    private function wired(): array
    {
        $wired = [];
        foreach ($this->types as $type) {
            $name = $type->type();
            if (isset($wired[$name])) {
                throw new InvalidArgumentException(sprintf('Two classes answer for the authorization detail type "%s".', $name));
            }
            $wired[$name] = $type;
        }

        return $wired;
    }
}
