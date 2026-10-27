<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Core\Domain\Key\OpenedSigningKeyInterface;
use Beffroi\Oidc\Domain\Claims\OpenedSubjectIdentifierInterface;
use Beffroi\Oidc\Exception\LogicException;

/**
 * What the access token of a response needs from outside the provider, read before it is struck (architecture §4.6):
 * the key of the tenant it is signed with, opened by the KMS, and the kind of "sub" its client registered, opened,
 * whose pairwise kind computes the "sub" with a salt of the tenant the KMS opens (OIDC Core §8.1), for a shape that
 * signs the token and names the person in it; nothing for a shape that is a reference to a record the provider
 * keeps. Whoever spends something on the way to a token opens them first, and striking the token then asks nothing
 * of the KMS.
 */
final readonly class AddressedAccessToken
{
    /**
     * @param OpenedSigningKeyInterface|null $signingKey the key of the tenant the token is signed with, opened, null for a shape that signs nothing
     * @param OpenedSubjectIdentifierInterface|null $subjectIdentifier the kind of "sub" the client registered, opened, null for a shape that names nobody in the token
     */
    public function __construct(
        private ?OpenedSigningKeyInterface $signingKey = null,
        private ?OpenedSubjectIdentifierInterface $subjectIdentifier = null,
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
     * @throws LogicException when the shape names nobody in the token, so that no kind of "sub" was opened for it
     *
     * @return OpenedSubjectIdentifierInterface the kind of "sub" the client registered, opened
     */
    public function subjectIdentifier(): OpenedSubjectIdentifierInterface
    {
        return $this->subjectIdentifier ?? throw new LogicException('An access token whose shape names nobody in it assigns no "sub".');
    }
}
