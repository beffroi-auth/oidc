<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Ciba;

use Beffroi\Oidc\Exception\InvalidArgumentException;
use function preg_match;
use SensitiveParameter;
use function sprintf;
use function strlen;

/**
 * CIBA Core §7.1, §10.2, RFC 6750 §2.1
 */
final readonly class ClientNotificationToken
{
    /**
     * RFC 6750 §2.1
     */
    private const string PATTERN = '/^[A-Za-z0-9\-._~+\/]+=*$/D';

    /**
     * 128 bits of entropy (CIBA Core §7.1) take at least 22 characters of base64url.
     */
    public const int MIN_LENGTH = 22;

    public const int MAX_LENGTH = 1024;

    /**
     * @throws InvalidArgumentException
     */
    public function __construct(
        #[SensitiveParameter]
        public string $value,
    ) {
        if (strlen($value) < self::MIN_LENGTH || strlen($value) > self::MAX_LENGTH) {
            throw new InvalidArgumentException(sprintf(
                'A client notification token is between %d and %d characters, carrying at least 128 bits of entropy (CIBA Core section 7.1).',
                self::MIN_LENGTH,
                self::MAX_LENGTH,
            ));
        }
        if (preg_match(self::PATTERN, $value) !== 1) {
            throw new InvalidArgumentException('A client notification token is a bearer token, as RFC 6750 section 2.1 writes one.');
        }
    }
}
