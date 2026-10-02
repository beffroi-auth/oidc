<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

/**
 * The two names of a response mode the specifications fix rather than the wiring (OAuth 2.0 Multiple
 * Response Type Encoding Practices §2.1, JARM §2.1). Every other name is a name a way of answering gives
 * itself, and what the provider serves is that wired list (ServedResponseModesInterface): there is no
 * enumeration of modes anywhere, because a mode the provider gains is a class that delivers it.
 *
 * These two are here because neither belongs to a way of answering. The default is the mode the "code"
 * response type answers in when the request asks for none, which is a rule of the specification and not
 * of a deployment; the alias delivers nothing at all and names the signed mode a response type defaults
 * to, which is resolved against what the wiring serves. They are written once, read by the request that
 * carries a mode, by the parser that resolves one and by the document that announces them.
 */
final readonly class ResponseModeNames
{
    /**
     * RFC 6749 §4.1.2, Multiple Response Type Encoding Practices §2.1: the parameters in the query of the
     * redirect URI, which is what the "code" response type answers in unless the request asks otherwise.
     */
    public const string DEFAULT = 'query';

    /**
     * JARM §2.1: "jwt" names no delivery of its own, it names the signed mode the response type defaults
     * to. No way of answering answers to this name; the wiring says which of its signed modes does.
     */
    public const string ALIAS = 'jwt';
}
