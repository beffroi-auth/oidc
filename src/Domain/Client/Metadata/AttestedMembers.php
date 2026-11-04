<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Metadata;

use function array_diff_key;
use function array_flip;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;

/**
 * RFC 7591 §2.3, §3.1.1
 */
final readonly class AttestedMembers implements ClientMetadataSourceInterface
{
    /**
     * RFC 7519 §4.1
     *
     * @var list<string>
     */
    private const array ABOUT_THE_STATEMENT = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'];

    /**
     * @var array<string, mixed>
     */
    private array $members;

    /**
     * @param array<string, mixed> $claims the claims of the verified statement
     *
     * @throws InvalidClientMetadataException
     */
    public function __construct(array $claims)
    {
        $this->members = array_diff_key($claims, array_flip(self::ABOUT_THE_STATEMENT));
        MembersOfTheDeployment::refuseIn($this);
    }

    public function source(): string
    {
        return 'the software statement its issuer signed';
    }

    public function members(): array
    {
        return $this->members;
    }
}
