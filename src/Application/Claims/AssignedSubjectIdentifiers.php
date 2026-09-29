<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Claims;

use function array_key_first;
use function array_keys;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Identity\User;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientRegistration;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Port\AssignedSubjectTypesInterface;
use Heidi\Oidc\Port\PresentedSubjectReaderInterface;
use Heidi\Oidc\Port\SubjectIdentifierKindInterface;
use Heidi\Oidc\Port\SubjectIdentifierResolverInterface;
use function implode;
use function sprintf;

/**
 * The kinds of "sub" the wiring gave the provider, in the order they are wired. The one source of truth over
 * them (OIDC Core §8): the discovery document announces this list, a registration reads it to know what a
 * client may name, and both ways of a "sub" go through it, out to the client and back from it.
 *
 * It demands no kind in particular, so a deployment that wires one boots, and it refuses two resolvers of
 * the same kind, which is a wiring where the identifier a client receives depends on an order nobody wrote
 * down. The first wired kind is the one a client that registers none takes, as the first wired shape is the
 * shape its access tokens take.
 *
 * The list is read when a question is asked of it and never at construction, because a client registration
 * asks it what a client may name while the clients are themselves being built.
 */
final readonly class AssignedSubjectIdentifiers implements AssignedSubjectTypesInterface, PresentedSubjectReaderInterface, SubjectIdentifierResolverInterface
{
    /**
     * @param iterable<SubjectIdentifierKindInterface> $kinds at least one, each naming the kind it assigns
     */
    public function __construct(
        private iterable $kinds,
    ) {
    }

    public function assignedSubjectTypes(): array
    {
        return array_keys($this->wired());
    }

    public function assertAssignable(ClientRegistration $registration): void
    {
        $this->of($registration)->assertAssignable($registration);
    }

    public function resolve(User $user, Client $client): Subject
    {
        return $this->of($client->registration)->resolve($user, $client);
    }

    public function findUser(Client $client, Subject $subject): ?User
    {
        return $this->of($client->registration)->findUser($client, $subject);
    }

    /**
     * The kind the client registered says who assigns its identifier, and that resolver alone assigns it;
     * a client that registered none takes the first wired kind.
     *
     * @throws InvalidArgumentException when the wiring does not hold together, or no longer holds the kind
     *                                  this client registered
     */
    private function of(ClientRegistration $registration): SubjectIdentifierKindInterface
    {
        $wired = $this->wired();
        $name = $registration->subjectType ?? array_key_first($wired);

        return $wired[$name] ?? throw new InvalidArgumentException(sprintf(
            'No resolver assigns a "%s" subject identifier; the wired kinds are %s.',
            $name,
            implode(', ', array_keys($wired)),
        ));
    }

    /**
     * @throws InvalidArgumentException
     *
     * @return non-empty-array<non-empty-string, SubjectIdentifierKindInterface> by the name each resolver gives its kind
     */
    private function wired(): array
    {
        $wired = [];
        foreach ($this->kinds as $kind) {
            $name = $kind->subjectType();
            if (isset($wired[$name])) {
                throw new InvalidArgumentException(sprintf('Two resolvers assign a "%s" subject identifier.', $name));
            }
            $wired[$name] = $kind;
        }
        if ($wired === []) {
            throw new InvalidArgumentException('A provider assigns its subject identifiers in at least one kind.');
        }

        return $wired;
    }
}
