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
 * The person a self-contained access token is about, as the claim that carries it and as the subject that
 * claim is read back to (issue #641, architecture §4.6): the way a token whose subject a client named says
 * who it is about, where there is no record to say it.
 *
 * **It is sealed under the KMS of the tenant**, as a shared secret of a user is (architecture §3.3), and
 * what that buys is the one thing a claim in the clear could not: the name the account carries is the name
 * that links a person across sectors, which is what a pairwise kind exists to keep from a client
 * (OIDC Core §8.1), so a token that carried it would hand it to every holder. Sealed, it is read by this
 * provider and by nobody else, and the holder of the token learns from it exactly what it learned before,
 * nothing.
 *
 * It is a use case and not a pair of methods on the token because reading it back names the sealer the
 * wiring holds, as reading a password hash back names its algorithm (StoredPasswordHash): the issuer and
 * the verifier of the shape are handed the same object, so what one writes is what the other reads.
 *
 * What it is not is a claim a resource server is held to (RFC 9068 §2.2): the claims of §2.2 are the ones
 * they were, this one is a private claim of the provider (RFC 7519 §4.3), and a resource server verifying
 * offline reads it as it reads anything it was not given a meaning for.
 */
final readonly class SealedPerson
{
    public function __construct(
        private SecretSealerInterface $sealer,
    ) {
    }

    /**
     * @throws KmsUnavailableException when the KMS of the tenant does not answer or refuses to seal
     * @throws RuntimeException when the envelope cannot be made for another reason
     *
     * @return string the envelope in base64url, which is what a claim of a JWT carries
     */
    public function claim(Tenant $tenant, Subject $person): string
    {
        return Base64Url::encode($this->sealer->seal($tenant, $person->value));
    }

    /**
     * The person the claim names, null when the token carries none, which is what a token nothing resolved
     * a person for says: a token a client holds for itself is about nobody (RFC 6749 §4.4), and a token
     * somebody signed in for says who it is about in its "sub", for the client it was written for.
     *
     * A claim this provider did not write there is refused rather than read as saying nobody: what it holds
     * is an envelope of this use and of this tenant or it is not one of ours, and the token it came in was
     * then not issued here either.
     *
     * @throws InvalidTokenException when the claim is not an envelope this provider sealed for this tenant
     * @throws KmsUnavailableException when the KMS of the tenant does not answer
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
