<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Core\Domain\Key\OpenedSigningKeyInterface;
use Beffroi\Oidc\Exception\LogicException;

/**
 * What the access token of a response needs from outside the provider, read before it is struck (architecture §4.6):
 * the key of the tenant it is signed with, opened by the KMS, for a shape that signs it, and nothing for a shape that
 * is a reference to a record the provider keeps; and the person a token whose subject the client named is about,
 * sealed under the KMS of the tenant, for a shape that carries it sealed (issue #641). Whoever spends something on
 * the way to a token addresses it first, and striking the token then asks nothing of the KMS.
 */
final readonly class AddressedAccessToken
{
    /**
     * @param OpenedSigningKeyInterface|null $signingKey the key of the tenant the token is signed with, opened, null for a shape that signs nothing
     * @param string|null $person the person the token is about, sealed as its claim carries it, null for a token that carries none
     */
    public function __construct(
        private ?OpenedSigningKeyInterface $signingKey = null,
        private ?string $person = null,
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

    /**
     * @throws LogicException when the person was not sealed when the token was addressed
     *
     * @return string the person the token is about, sealed as its claim carries it
     */
    public function person(): string
    {
        return (
            $this->person ?? throw new LogicException('The person this access token is about was not sealed when it was addressed, before the grant spent what the request presented (architecture section 4.6).')
        );
    }
}
