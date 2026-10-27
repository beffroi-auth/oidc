<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Core\Domain\Key\OpenedSigningKeyInterface;
use Beffroi\Oidc\Exception\LogicException;

/**
 * What the access token of a response needs from outside the provider, read before it is struck (architecture §4.6):
 * the key of the tenant it is signed with, opened by the KMS, for a shape that signs it, and nothing for a shape that
 * is a reference to a record the provider keeps. Whoever spends something on the way to a token opens the key first,
 * and striking the token then asks nothing of the KMS.
 */
final readonly class AddressedAccessToken
{
    /**
     * @param OpenedSigningKeyInterface|null $signingKey the key of the tenant the token is signed with, opened, null for a shape that signs nothing
     */
    public function __construct(
        private ?OpenedSigningKeyInterface $signingKey = null,
    ) {
    }

    /**
     * @throws LogicException when the shape signs nothing, so that no key of the tenant was opened for the token
     *
     * @return OpenedSigningKeyInterface the key of the tenant the token is signed with, opened
     */
    public function signingKey(): OpenedSigningKeyInterface
    {
        return $this->signingKey ?? throw new LogicException('An access token whose shape signs nothing is signed with no key.');
    }
}
