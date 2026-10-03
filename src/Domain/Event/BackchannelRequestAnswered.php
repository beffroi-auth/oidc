<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\ClientUri;
use SensitiveParameter;

/**
 * A backchannel authentication request has been answered by the user it named, and the client that made
 * it registered to be told (CIBA Core §10.2). Carrying that word to the endpoint it registered is the
 * integration's, asynchronously (architecture §5.6): a client that does not answer the call holds no
 * approval up, and it would find the same answer by polling.
 *
 * It is raised whether the user said yes or no: what the client is told is that the request is over, and
 * what it is over with it reads at the token endpoint, which is the only place this provider hands a
 * token out.
 *
 * The identifier and the token of the call travel with it, because the provider keeps neither in a shape
 * it could read back twice without asking the KMS again, and because what is on its way to one client is
 * of no use to anybody else.
 */
final readonly class BackchannelRequestAnswered implements ConcernsAClientInterface
{
    /**
     * The name of the act, which is what the journal writes down (issue #454).
     */
    public const string NAME = 'backchannel_request.answered';

    /**
     * @param ClientUri $notificationEndpoint where the client registered to be called (§7.1)
     * @param string $authRequestId the identifier of the request, which is the whole body of that call (§10.2)
     * @param string $notificationToken what the client sent with its request so that it recognises the call
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $clientId,
        public ClientUri $notificationEndpoint,
        #[SensitiveParameter]
        public string $authRequestId,
        #[SensitiveParameter]
        public string $notificationToken,
        public RequestContext $context,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }
}
