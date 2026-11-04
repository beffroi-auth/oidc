<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Core\Domain\Key\OpenedSigningKeyInterface;
use Beffroi\Oidc\Domain\Claims\OpenedSubjectIdentifierInterface;
use Beffroi\Oidc\Exception\LogicException;

/**
 * What the access token of a response needs from outside the provider, read before it is struck.
 */
final readonly class AddressedAccessToken
{
    /**
     * @param string|null $person sealed, as the token's claim carries it
     */
    public function __construct(
        private ?OpenedSigningKeyInterface $signingKey = null,
        private ?string $person = null,
        private ?OpenedSubjectIdentifierInterface $subjectIdentifier = null,
    ) {
    }

    /**
     * @throws LogicException
     */
    public function signingKey(): OpenedSigningKeyInterface
    {
        return $this->signingKey ?? throw new LogicException('An access token whose shape signs nothing is signed with no key.');
    }

    /**
     * @throws LogicException
     *
     * @return string sealed, as the token's claim carries it
     */
    public function person(): string
    {
        return (
            $this->person ?? throw new LogicException('The person this access token is about was not sealed when it was addressed, before the grant spent what the request presented (architecture section 4.6).')
        );
    }

    /**
     * @throws LogicException
     */
    public function subjectIdentifier(): OpenedSubjectIdentifierInterface
    {
        return $this->subjectIdentifier ?? throw new LogicException('An access token whose shape names nobody in it assigns no "sub".');
    }
}
