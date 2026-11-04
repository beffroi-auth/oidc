<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

final readonly class ResponseModeNames
{
    /**
     * RFC 6749 §4.1.2, Multiple Response Type Encoding Practices §2.1
     */
    public const string DEFAULT = 'query';

    /**
     * JARM §2.1
     */
    public const string ALIAS = 'jwt';
}
