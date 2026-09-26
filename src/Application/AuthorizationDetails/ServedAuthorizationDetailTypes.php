<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\AuthorizationDetails;

use function array_is_list;
use function array_keys;
use Heidi\Oidc\Domain\AuthorizationDetails\AuthorizationDetail;
use Heidi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Heidi\Oidc\Domain\AuthorizationDetails\AuthorizationDetailTypeInterface;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Port\AuthorizationDetailsReaderInterface;
use Heidi\Oidc\Port\ServedAuthorizationDetailTypesInterface;
use function implode;
use function is_array;
use function is_string;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use JsonException;
use function sprintf;

/**
 * The types of authorization detail the wiring gave the provider, the one source of truth over them
 * (issue #98): reading an "authorization_details" asks them which type each object names, a client
 * registration asks them what a client may name, and the discovery document announces what they hold.
 *
 * A request naming a type nobody wired is refused rather than served: a detail this provider cannot
 * describe is a detail it cannot show a user, and agreeing to something nobody can read is the one thing
 * a consent must never be (RFC 9396 §5).
 *
 * The list is read when a question is asked of it and never at construction, because a client
 * registration asks it what a client may name while the clients are themselves being built.
 */
final readonly class ServedAuthorizationDetailTypes implements AuthorizationDetailsReaderInterface, ServedAuthorizationDetailTypesInterface
{
    /**
     * The array, one object of it, a member holding an object, one of its members holding a list, and a
     * scalar inside that, as json_decode() counts. Deeper than that was not asked for here.
     */
    private const int MAX_DEPTH = 6;

    /**
     * @param iterable<AuthorizationDetailTypeInterface> $types each answering for its own "type"; none is a provider that serves no rich authorization request
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
     * The members of one object, "type" already removed: named, each one once. A member name made of
     * digits became an integer key when it was decoded, and it names no member, exactly as a claim name
     * made of digits names no claim (OIDC Core §5.5).
     *
     * @param array<array-key, mixed> $members
     *
     * @throws InvalidArgumentException when a member is not named
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
     * @return array<non-empty-string, AuthorizationDetailTypeInterface> by the name each type gives itself
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
