<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

use function array_is_list;
use function array_key_exists;
use function count;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function is_array;
use function is_bool;
use function is_float;
use function is_int;
use function is_string;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use JsonException;
use function sprintf;

/**
 * The "claims" parameter of an authorization request (OIDC Core §5.5): a JSON object whose "userinfo"
 * and "id_token" members list the claims the client wants in each place, each either null or an object
 * of §5.5.1. Members that are not understood are ignored, as the specification requires; a member that
 * is understood but malformed is refused, because nothing is guessed on the client's behalf.
 */
final readonly class ClaimsRequest
{
    /**
     * The defined structure nests four containers (the object, a member, a claim, the "values" list) and
     * json_decode() counts the scalar inside the last one as a fifth level. Deeper JSON is not a claims
     * request.
     */
    private const int MAX_DEPTH = 5;

    /**
     * @param array<string, ClaimRequest> $userinfo claims requested from the UserInfo endpoint, by name
     * @param array<string, ClaimRequest> $idToken claims requested in the ID token, by name
     */
    public function __construct(
        public array $userinfo = [],
        public array $idToken = [],
    ) {
    }

    /**
     * @throws InvalidArgumentException when the JSON is not a claims request
     */
    public static function fromJson(string $json): self
    {
        try {
            $decoded = json_decode($json, true, self::MAX_DEPTH, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException('The claims request is not valid JSON.', previous: $exception);
        }
        // an empty object and an empty list decode alike; both ask for nothing
        if (! is_array($decoded) || ($decoded !== [] && array_is_list($decoded))) {
            throw new InvalidArgumentException('The claims request must be a JSON object (OIDC Core §5.5).');
        }

        return new self(self::member($decoded, 'userinfo'), self::member($decoded, 'id_token'));
    }

    public function isEmpty(): bool
    {
        return $this->userinfo === [] && $this->idToken === [];
    }

    /**
     * @param array<array-key, mixed> $decoded
     *
     * @return array<string, ClaimRequest>
     */
    private static function member(array $decoded, string $name): array
    {
        if (! array_key_exists($name, $decoded) || $decoded[$name] === null) {
            return [];
        }
        $member = $decoded[$name];
        if (! is_array($member) || ($member !== [] && array_is_list($member))) {
            throw new InvalidArgumentException(sprintf('The "%s" member of a claims request must be a JSON object (OIDC Core §5.5).', $name));
        }
        $claims = [];
        foreach ($member as $claim => $request) {
            // a name made of digits only became an integer key when the JSON was decoded; it names no claim
            if (! is_string($claim) || $claim === '') {
                throw new InvalidArgumentException(sprintf('A claim name in "%s" must be a non-empty string that is not a number.', $name));
            }
            $claims[$claim] = self::claim($name, $claim, $request);
        }

        return $claims;
    }

    private static function claim(string $member, string $claim, mixed $request): ClaimRequest
    {
        if ($request === null) {
            return new ClaimRequest();
        }
        if (! is_array($request) || ($request !== [] && array_is_list($request))) {
            throw new InvalidArgumentException(sprintf('The claim "%s" in "%s" must be null or a JSON object (OIDC Core §5.5.1).', $claim, $member));
        }
        $essential = $request['essential'] ?? false;
        if (! is_bool($essential)) {
            throw new InvalidArgumentException(sprintf('The "essential" member of the claim "%s" in "%s" must be a JSON boolean (OIDC Core §5.5.1).', $claim, $member));
        }
        $value = $request['value'] ?? null;
        if ($value !== null && ! self::isScalar($value)) {
            throw new InvalidArgumentException(sprintf('The "value" member of the claim "%s" in "%s" must be a JSON string, number or boolean (OIDC Core §5.5.1).', $claim, $member));
        }
        $values = null;
        if (($request['values'] ?? null) !== null) {
            if (! is_array($request['values']) || ! array_is_list($request['values']) || count($request['values']) === 0) {
                throw new InvalidArgumentException(sprintf('The "values" member of the claim "%s" in "%s" must be a non-empty JSON array (OIDC Core §5.5.1).', $claim, $member));
            }
            $values = [];
            foreach ($request['values'] as $candidate) {
                if (! self::isScalar($candidate)) {
                    throw new InvalidArgumentException(sprintf('The "values" member of the claim "%s" in "%s" must list JSON strings, numbers or booleans (OIDC Core §5.5.1).', $claim, $member));
                }
                $values[] = $candidate;
            }
        }

        return new ClaimRequest($essential, $value, $values);
    }

    /**
     * @phpstan-assert-if-true string|int|float|bool $value
     */
    private static function isScalar(mixed $value): bool
    {
        return is_string($value) || is_int($value) || is_float($value) || is_bool($value);
    }
}
