<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Domain\Authorization\ResponseModeNames;
use Beffroi\Oidc\Exception\UnsupportedResponseModeException;
use function is_string;
use Beffroi\Oidc\Port\ServedResponseModesInterface;

/**
 * OAuth 2.0 Multiple Response Type Encoding Practices §2.1
 */
final readonly class RequestedResponseMode
{
    public function __construct(
        private ServedResponseModesInterface $responseModes,
    ) {
    }

    /**
     * An unserved mode falls back to the first wired one, which delivers the second stage's refusal.
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
     * @throws UnsupportedResponseModeException
     */
    public function assertItIsTheOneDelivered(RequestParameters $request, string $delivered): void
    {
        $requested = $request->optional('response_mode');
        if ($requested !== null && $this->named($requested) !== $delivered) {
            throw new UnsupportedResponseModeException('The requested response mode is not supported.');
        }
    }

    private function named(string $requested): ?string
    {
        return $this->responseModes->responseModeNamed($requested);
    }
}
