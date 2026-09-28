<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client\Registration;

use Heidi\Oidc\Exception\UnreadableClientMetadataException;
use function preg_replace;
use function str_replace;

/**
 * A refusal of the registration endpoint (RFC 7591 §3.2.2): a 400, the error code the refusal answers
 * for, and the human-readable description that says which member did not hold.
 *
 * The code is the one the refusal names itself by, one class per code of §3.2.2, and the description is
 * the message that refusal carries: what a deployment reads when a declaration stops its boot is what a
 * client reads in its "error_description", the two being the same refusal of the same member read by the
 * same reader.
 *
 * §3.2.2 asks for ASCII, so the section sign of a message written for a log becomes the word every
 * description this provider sends already spells (OAuth2Exception), and whatever else is left outside
 * printable ASCII is dropped: a message naming a member a client sent carries what that client wrote,
 * and what a client wrote is not what decides the shape of an answer.
 */
final readonly class RegistrationErrorResponse
{
    public const string CONTENT_TYPE = 'application/json';

    public const int STATUS_CODE = 400;

    /**
     * What is left of a description: printable ASCII, as RFC 6749 §5.2 asks of one at every other
     * endpoint.
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
