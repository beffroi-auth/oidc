<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use function sprintf;

/**
 * A request that presents no bearer credential this endpoint would act on (RFC 6750 §3.1): the initial
 * access token a registration is authorised by (RFC 7591 §1.2), the registration access token a client
 * reads itself with (RFC 7592 §2.3).
 *
 * Both are `invalid_token` and a 401 carrying the challenge an endpoint that reads such a credential owes,
 * and both read the same whatever gave them away: whoever does not hold the credential learns nothing
 * about the one they presented (decision 0006). What differs between them is the one sentence each says,
 * which is what tells a caller which credential the endpoint wanted.
 */
abstract class UnauthorizedBearerRequestException extends OAuth2Exception
{
    /**
     * RFC 6750 §1.2: how such a credential is presented, and therefore how one should have been.
     */
    public const string SCHEME = 'Bearer';

    public function __construct(string $description)
    {
        parent::__construct('invalid_token', $description, 401, false);
    }

    /**
     * RFC 6750 §3: an endpoint that reads a bearer credential says on every 401 what would have been read.
     * The descriptions of this package carry no double quote nor backslash and need no escaping.
     */
    public function challenge(): string
    {
        return sprintf('%s error="%s", error_description="%s"', self::SCHEME, $this->error, $this->errorDescription);
    }
}
