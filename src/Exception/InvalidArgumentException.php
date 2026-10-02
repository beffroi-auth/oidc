<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

/**
 * An argument of this package is not one. Not final: the refusal of a client registration is one of these
 * and carries what an answer of RFC 7591 §3.2.2 is written from (UnreadableClientMetadataException), so
 * that whoever expects a refusal of an argument still gets one.
 */
class InvalidArgumentException extends \InvalidArgumentException implements ExceptionInterface
{
}
