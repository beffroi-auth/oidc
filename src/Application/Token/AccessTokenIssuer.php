<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use function array_keys;
use function array_map;
use DateTimeImmutable;
use Heidi\Oidc\Domain\Client\AccessTokenFormat;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Port\AccessTokenIssuerInterface;
use function implode;
use function sprintf;

/**
 * Mints the access token in the shape the client is registered for (architecture §4.6): one issuer per
 * AccessTokenFormat, the signed JWT of RFC 9068 and the opaque reference today, whatever comes next
 * (a COSE or a PASETO token) as one more case and one more entry. The grants and the token issuer do not
 * know which shape; the registration of the client does, and nothing global overrides it.
 */
final readonly class AccessTokenIssuer implements AccessTokenIssuerInterface
{
    /**
     * @var array<string, AccessTokenIssuerInterface> by format value
     */
    private array $issuers;

    /**
     * @param array<string, AccessTokenIssuerInterface> $issuers keyed by the value of the AccessTokenFormat each one writes; every format has one, no key is unknown
     */
    public function __construct(array $issuers)
    {
        foreach (array_keys($issuers) as $format) {
            if (AccessTokenFormat::tryFrom($format) === null) {
                throw new InvalidArgumentException(sprintf('"%s" is not an access token format; the formats are %s.', $format, implode(', ', array_map(static fn (AccessTokenFormat $known): string => $known->value, AccessTokenFormat::cases()))));
            }
        }
        foreach (AccessTokenFormat::cases() as $format) {
            if (! isset($issuers[$format->value])) {
                throw new InvalidArgumentException(sprintf('No issuer writes access tokens in the "%s" format.', $format->value));
            }
        }
        $this->issuers = $issuers;
    }

    public function issue(GrantedAuthorization $authorization, DateTimeImmutable $now): AccessToken
    {
        return $this->issuers[$authorization->client->accessTokenFormat->value]->issue($authorization, $now);
    }
}
