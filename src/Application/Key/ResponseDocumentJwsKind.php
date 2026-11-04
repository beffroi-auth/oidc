<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Key;

use DateInterval;
use Beffroi\Core\Domain\Key\KeyUse;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\KeyBoundArtifactInterface;
use Beffroi\Oidc\Application\Authorization\ResponseDocumentIssuer;
use Beffroi\Oidc\Port\ServedResponseModesInterface;

final readonly class ResponseDocumentJwsKind implements KeyBoundArtifactInterface
{
    public function __construct(
        private ResponseDocumentIssuer $issuer,
        private ServedResponseModesInterface $responseModes,
    ) {
    }

    public function keyUse(): KeyUse
    {
        return KeyUse::Signature;
    }

    public function longestLifetime(Tenant $tenant): ?DateInterval
    {
        return $this->responseModes->signsAnyAnswer() ? $this->issuer->lifetime : null;
    }
}
