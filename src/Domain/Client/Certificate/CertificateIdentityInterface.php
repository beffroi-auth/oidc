<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Certificate;

/**
 * RFC 8705 §2.1.2
 */
interface CertificateIdentityInterface
{
    /**
     * @return non-empty-string
     */
    public function name(): string;

    public function matches(CertificateSubject $subject): bool;
}
