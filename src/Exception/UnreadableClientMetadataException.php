<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use Throwable;

/**
 * The metadata of a registration does not hold together (RFC 7591 §2). What the reader of that metadata
 * raises, whatever the member and whatever the source: what each caller does with it is its own, a boot that
 * stops for a declaration of the deployment and a 400 of RFC 7591 §3.2.2 for a client that registered itself,
 * and the reader knows neither.
 *
 * There is one subclass per error code of §3.2.2, each naming its own, as every other exception of this
 * package that answers for an error code of a specification does (OAuth2Exception). A caller that owes an
 * answer reads the code; a caller that owes a stopped boot catches this one and reads nothing.
 *
 * It carries what such an answer is written from beside the code: the member that does not hold and where the
 * value of it came from. The message names the member too, a boot having nothing else to go on.
 */
abstract class UnreadableClientMetadataException extends InvalidArgumentException
{
    /**
     * @param non-empty-string $error the code of RFC 7591 §3.2.2 the endpoint answers with, named by the subclass
     * @param string|null $member the member that does not hold; null when what does not hold is a rule between several of them, which the message names
     * @param string|null $source where the value came from (ClientMetadataSourceInterface); null when no source carried it and what does not hold is what the registration is left with
     */
    public function __construct(
        public readonly string $error,
        public readonly ?string $member,
        public readonly ?string $source,
        string $message,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }
}
