<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Claims;

use function array_key_first;
use function array_keys;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Claims\OpenedSubjectIdentifierInterface;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\AssignedSubjectTypesInterface;
use Beffroi\Oidc\Port\PresentedSubjectReaderInterface;
use Beffroi\Oidc\Port\SubjectIdentifierKindInterface;
use Beffroi\Oidc\Port\SubjectIdentifierOpenerInterface;
use Beffroi\Oidc\Port\SubjectIdentifierResolverInterface;
use function implode;
use function sprintf;

/**
 * OIDC Core §8
 *
 * Kinds are read when asked, not at construction: a client registration asks them while clients are being built.
 */
final readonly class AssignedSubjectIdentifiers implements
    AssignedSubjectTypesInterface,
    PresentedSubjectReaderInterface,
    SubjectIdentifierOpenerInterface,
    SubjectIdentifierResolverInterface
{
    /**
     * @param iterable<SubjectIdentifierKindInterface> $kinds at least one
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

    public function open(Client $client): OpenedSubjectIdentifierInterface
    {
        return $this->of($client->registration)->open($client);
    }

    public function findUser(Client $client, Subject $subject): ?User
    {
        return $this->of($client->registration)->findUser($client, $subject);
    }

    /**
     * @throws InvalidArgumentException
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
     * @return non-empty-array<non-empty-string, SubjectIdentifierKindInterface> by subject type
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
