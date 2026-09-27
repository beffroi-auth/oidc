<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Authorization;

use Heidi\Oidc\Application\Request\RequestParameters;
use Heidi\Oidc\Domain\Authorization\ResponseModeNames;
use Heidi\Oidc\Exception\UnsupportedResponseModeException;
use function is_string;
use Heidi\Oidc\Port\ServedResponseModesInterface;

/**
 * The mode the answer of an authorization request is delivered in (OAuth 2.0 Multiple Response Type
 * Encoding Practices §2.1), which is the one parameter both stages of the request read: the first to know
 * how anything reaches the client at all, the second to refuse a mode it cannot deliver.
 *
 * It is asked of the wiring and never of a name written here (ServedResponseModesInterface, §4.2): the
 * alias of JARM §2.1 is resolved before anything is asked of it, so that what is kept is the mode that
 * delivers.
 */
final readonly class RequestedResponseMode
{
    public function __construct(
        private ServedResponseModesInterface $responseModes,
    ) {
    }

    /**
     * The mode the answer will use, read with the redirect URI because it says how anything reaches the
     * client, a refusal of the second stage as well as a code (OIDC Core §3.1.2.6). It refuses nothing,
     * the failures of that stage being pages: what the provider cannot answer as it was asked falls back
     * to a mode the integration wired, so that the refusal the second stage throws reaches the client in
     * a mode the endpoint can actually deliver.
     *
     * The fallback is the wiring's and not a name written here: a deployment that answers in "form_post"
     * and wires no "query" would otherwise refuse its own requests in a mode it has no way of delivering.
     *
     * @param array<string, mixed> $parameters
     */
    public function of(array $parameters): string
    {
        $requested = $parameters['response_mode'] ?? null;
        $mode = is_string($requested) ? $this->named($requested) : $this->named(ResponseModeNames::DEFAULT);

        return $mode ?? $this->responseModes->servedResponseModes()[0];
    }

    /**
     * The second stage asks for what the first established: a request that names a mode names the one
     * that will be delivered, or it asks for something this provider does not serve.
     *
     * @throws UnsupportedResponseModeException
     */
    public function assertItIsTheOneDelivered(RequestParameters $request, string $delivered): void
    {
        $requested = $request->optional('response_mode');
        if ($requested !== null && $this->named($requested) !== $delivered) {
            throw new UnsupportedResponseModeException('The requested response mode is not supported.');
        }
    }

    /**
     * The wired mode a named one is answered in, or nothing when the provider answers in no such mode.
     */
    private function named(string $requested): ?string
    {
        return $this->responseModes->responseModeNamed($requested);
    }
}
