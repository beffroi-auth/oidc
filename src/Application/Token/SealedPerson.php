<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use Beffroi\Core\Domain\Encoding\Base64Url;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Port\SecretSealerInterface;
use Beffroi\Oidc\Exception\InvalidTokenException;
use function is_string;

/**
 * Sealed under the KMS of the tenant: in the clear, the account's subject would link the person across pairwise
 * sectors (OIDC Core §8.1).
 */
final readonly class SealedPerson
{
    public function __construct(
        private SecretSealerInterface $sealer,
    ) {
    }

    /**
     * @throws KmsUnavailableException
     * @throws RuntimeException
     */
    public function claim(Tenant $tenant, Subject $person): string
    {
        return Base64Url::encode($this->sealer->seal($tenant, $person->value));
    }

    /**
     * @throws InvalidTokenException when the claim is not an envelope this provider sealed for this tenant
     * @throws KmsUnavailableException
     */
    public function of(Tenant $tenant, mixed $claim): ?Subject
    {
        if ($claim === null) {
            return null;
        }
        if (! is_string($claim)) {
            throw InvalidTokenException::notIssuedHere();
        }
        $sealed = Base64Url::decode($claim);
        if ($sealed === null || $sealed === '') {
            throw InvalidTokenException::notIssuedHere();
        }

        try {
            return new Subject($this->sealer->unseal($tenant, $sealed));
        } catch (InvalidArgumentException|RuntimeException $exception) {
            throw InvalidTokenException::notIssuedHere($exception);
        }
    }
}
