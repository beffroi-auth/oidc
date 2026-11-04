<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Claims;

use function array_filter;
use function array_keys;
use function array_map;
use function array_merge;
use function array_values;
use Beffroi\Core\Domain\Identity\Address;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Port\ClaimsProviderInterface;
use function in_array;

/**
 * OIDC Core §5.1, §5.4, §5.5
 *
 * A claim asked for by name is served whatever the scopes: ClaimsAskedByName held it to the registered ones.
 */
final readonly class StandardClaimsProvider implements ClaimsProviderInterface
{
    /**
     * OIDC Core §5.4
     *
     * @var array<string, list<string>>
     */
    private const array SCOPES = [
        'profile' => [
            'name',
            'family_name',
            'given_name',
            'middle_name',
            'nickname',
            'preferred_username',
            'profile',
            'picture',
            'website',
            'gender',
            'birthdate',
            'zoneinfo',
            'locale',
            'updated_at',
        ],
        'email' => ['email', 'email_verified'],
        'address' => ['address'],
        'phone' => ['phone_number', 'phone_number_verified'],
    ];

    public function claims(User $user, ?Scopes $scopes, array $requested): array
    {
        $due = [...array_keys($requested), ...($scopes === null ? [] : $this->claimsOf($scopes))];

        $claims = [];
        foreach (self::valuesOf($user) as $name => $value) {
            if (in_array($name, $due, true) && $value !== null) {
                $claims[$name] = $value;
            }
        }

        return $claims;
    }

    public function claimsOf(Scopes $scopes): array
    {
        $claims = [];
        foreach ($scopes->all as $scope) {
            $claims = [...$claims, ...(self::SCOPES[$scope->value] ?? [])];
        }

        return $claims;
    }

    public function supportedScopes(): array
    {
        return array_map(static fn (string $scope): Scope => new Scope($scope), array_keys(self::SCOPES));
    }

    public function supportedClaims(): array
    {
        return array_merge(...array_values(self::SCOPES));
    }

    /**
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
     * OIDC Core §5.1.1
     *
     * @return array<string, string>|null
     */
    private static function address(?Address $address): ?array
    {
        if ($address === null) {
            return null;
        }
        $members = array_filter(
            [
                'formatted' => $address->formatted,
                'street_address' => $address->streetAddress,
                'locality' => $address->locality,
                'region' => $address->region,
                'postal_code' => $address->postalCode,
                'country' => $address->country,
            ],
            static fn (?string $member): bool => $member !== null,
        );

        return $members === [] ? null : $members;
    }
}
