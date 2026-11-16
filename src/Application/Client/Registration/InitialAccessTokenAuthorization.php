<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Beffroi\Oidc\Domain\Client\Registration\RegistrationRequest;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\UnauthorizedRegistrationException;
use Beffroi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use function preg_match;
use Psr\Clock\ClockInterface;

/**
 * RFC 7591 §1.2
 */
final readonly class InitialAccessTokenAuthorization implements RegistrationAuthorizationInterface
{
    public const string MODE = 'initial_access_token';

    /**
     * RFC 6750 §2.1, RFC 9110 §11.6.1
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

    public function authorize(Tenant $tenant, RegistrationRequest $request, ClientRegistrationPolicy $policy): AuthorizedRegistration
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

        return new AuthorizedRegistration(granted: $token->granted, administration: $token->administration);
    }

    private static function presented(?string $header): ?string
    {
        if ($header === null || preg_match(self::CREDENTIALS, $header, $credentials) !== 1) {
            return null;
        }

        return $credentials[1];
    }
}
