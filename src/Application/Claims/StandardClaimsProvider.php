<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Claims;

use function array_filter;
use function array_keys;
use Heidi\Core\Domain\Identity\Address;
use Heidi\Core\Domain\Identity\User;
use Heidi\Oidc\Port\ClaimsProviderInterface;
use function in_array;

/**
 * The standard claims of OIDC Core §5.1, read from the user of the core. The four scopes of §5.4 each
 * stand for a fixed set of them; a claim asked for by name (§5.5) is served whether or not its scope
 * was, because §5.5 exists to ask for less than a scope, and the "value" and "values" members of a
 * request (§5.5.1) are not looked at: the provider says what it knows, the client checks what it got.
 *
 * Claims about an absent attribute are left out, "email_verified" and "phone_number_verified" included:
 * a verification flag is only meaningful next to the value it qualifies. When the value is there, the
 * flag is there too, true or false, as a JSON boolean and never as a string (architecture §9). A
 * deployment that wants claims of its own chains another provider; this one knows the standard ones.
 */
final readonly class StandardClaimsProvider implements ClaimsProviderInterface
{
    /**
     * OIDC Core §5.4, in the order of §5.1.
     *
     * @var array<string, list<string>>
     */
    private const array SCOPES = [
        'profile' => ['name', 'family_name', 'given_name', 'middle_name', 'nickname', 'preferred_username', 'profile', 'picture', 'website', 'gender', 'birthdate', 'zoneinfo', 'locale', 'updated_at'],
        'email' => ['email', 'email_verified'],
        'address' => ['address'],
        'phone' => ['phone_number', 'phone_number_verified'],
    ];

    public function claims(User $user, array $scopes, array $requested): array
    {
        $due = array_keys($requested);
        foreach ($scopes as $scope) {
            $due = [...$due, ...self::SCOPES[$scope->value] ?? []];
        }

        $claims = [];
        foreach (self::valuesOf($user) as $name => $value) {
            if (in_array($name, $due, true) && $value !== null) {
                $claims[$name] = $value;
            }
        }

        return $claims;
    }

    /**
     * Every standard claim the user could carry, null when the attribute is absent, in the order of
     * OIDC Core §5.1 so that a response reads like the specification.
     *
     * @return array<string, mixed>
     */
    private static function valuesOf(User $user): array
    {
        $profile = $user->profile;

        return [
            'name' => $profile->name,
            'given_name' => $profile->givenName,
            'family_name' => $profile->familyName,
            'middle_name' => $profile->middleName,
            'nickname' => $profile->nickname,
            'preferred_username' => $profile->preferredUsername,
            'profile' => $profile->profileUrl,
            'picture' => $profile->pictureUrl,
            'website' => $profile->websiteUrl,
            'email' => $user->email?->value,
            'email_verified' => $user->email === null ? null : $user->emailVerified,
            'gender' => $profile->gender,
            'birthdate' => $profile->birthdate,
            'zoneinfo' => $profile->zoneinfo,
            'locale' => $profile->locale,
            'phone_number' => $user->phoneNumber,
            'phone_number_verified' => $user->phoneNumber === null ? null : $user->phoneNumberVerified,
            'address' => self::address($user->address),
            'updated_at' => $user->updatedAt->getTimestamp(),
        ];
    }

    /**
     * OIDC Core §5.1.1: a JSON object with the members that have a value; no member, no claim.
     *
     * @return array<string, string>|null
     */
    private static function address(?Address $address): ?array
    {
        if ($address === null) {
            return null;
        }
        $members = array_filter([
            'formatted' => $address->formatted,
            'street_address' => $address->streetAddress,
            'locality' => $address->locality,
            'region' => $address->region,
            'postal_code' => $address->postalCode,
            'country' => $address->country,
        ], static fn (?string $member): bool => $member !== null);

        return $members === [] ? null : $members;
    }
}
