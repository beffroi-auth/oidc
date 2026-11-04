<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Registration;

use Beffroi\Oidc\Exception\UnreadableClientMetadataException;
use function preg_replace;
use function str_replace;

/**
 * RFC 7591 §3.2.2
 */
final readonly class RegistrationErrorResponse
{
    public const string CONTENT_TYPE = 'application/json';

    public const int STATUS_CODE = 400;

    /**
     * RFC 6749 §5.2
     */
    private const string OUTSIDE_ASCII = '/[^\x20-\x7E]/u';

    public function __construct(
        public string $error,
        public string $errorDescription,
    ) {
    }

    public static function fromException(UnreadableClientMetadataException $exception): self
    {
        return new self($exception->error, self::readable($exception->getMessage()));
    }

    /**
     * @return non-empty-array<string, string>
     */
    public function parameters(): array
    {
        return [
            'error' => $this->error,
            'error_description' => $this->errorDescription,
        ];
    }

    private static function readable(string $message): string
    {
        return (string) preg_replace(self::OUTSIDE_ASCII, '', str_replace('§', 'section ', $message));
    }
}
