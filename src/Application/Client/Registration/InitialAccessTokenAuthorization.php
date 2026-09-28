<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Registration;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Registration\RegistrationRequest;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Exception\UnauthorizedRegistrationException;
use Heidi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use function preg_match;
use Psr\Clock\ClockInterface;

/**
 * The mode decision 0009 builds first: a registration is authorised by an initial access token the
 * tenant issued, named, limited in number and duration, and can take back (RFC 7591 §1.2). It is the
 * mode a real ecosystem of relying parties uses inside an organisation, a credential handed to the team
 * that integrates.
 *
 * The token is presented as a bearer credential and compared with `hash_equals()` through the digest the
 * store keeps, so that whoever holds the store holds no token. It is spent in the same request as the
 * registration it authorises, before the metadata of that registration is read: a token worth one client
 * registers one, whether what followed it was written or refused on its metadata.
 *
 * It reads nothing of the body, so it puts nothing in front of it: an initial access token says who may
 * register, never what is registered.
 */
final readonly class InitialAccessTokenAuthorization implements RegistrationAuthorizationInterface
{
    /**
     * The name a registration policy names this mode by (decision 0009).
     */
    public const string MODE = 'initial_access_token';

    /**
     * RFC 6750 §2.1 and RFC 9110 §11.6.1: the scheme is compared without regard to case, and what
     * follows it is the credential. A credential of another shape is a credential this provider never
     * drew, and it is refused where one it never drew is.
     */
    private const string CREDENTIALS = '/^Bearer[ ]+([^ ]+)$/i';

    public function __construct(
        private InitialAccessTokenRepositoryInterface $tokens,
        private ClockInterface $clock,
    ) {
    }

    public function name(): string
    {
        return self::MODE;
    }

    public function authorize(Tenant $tenant, RegistrationRequest $request): array
    {
        $presented = self::presented($request->authorizationHeader);
        if ($presented === null) {
            throw new UnauthorizedRegistrationException();
        }
        $now = $this->clock->now();
        $digest = DrawnSecret::digestOf($presented);
        $token = $this->tokens->findByDigest($tenant, $digest);
        if ($token === null || ! $token->matches($digest) || ! $token->belongsTo($tenant) || ! $token->authorisesARegistration($now)) {
            throw new UnauthorizedRegistrationException();
        }
        if (! $this->tokens->spend($token, $now)) {
            throw new UnauthorizedRegistrationException();
        }

        return [];
    }

    private static function presented(?string $header): ?string
    {
        if ($header === null || preg_match(self::CREDENTIALS, $header, $credentials) !== 1) {
            return null;
        }

        return $credentials[1];
    }
}
