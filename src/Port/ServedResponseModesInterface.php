<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

/**
 * The response modes the authorization endpoint can actually answer in (OAuth 2.0 Multiple Response Type
 * Encoding Practices §2.1); the integration wires one way of answering per mode, so it says. What the
 * discovery document announces, what the parser accepts and what a request that asks for nothing takes
 * read this one source, so that the document and the endpoint cannot disagree (issue #98).
 *
 * A mode is a name here and never a case of an enumeration: a mode the provider gains is a way of
 * answering added to the wiring, and nothing of this module is edited for it.
 */
interface ServedResponseModesInterface
{
    /**
     * @return non-empty-list<string> the names the wired ways of answering give themselves, in the order
     *                               they are wired; the first is what a request the provider cannot
     *                               answer as it asked falls back to
     */
    public function servedResponseModes(): array;

    /**
     * The wired mode a requested name is answered in, null for a name nothing wired answers. The alias of
     * JARM §2.1 is resolved here, against what the wiring serves, because that is what knows which of its
     * signed modes the alias names.
     */
    public function responseModeNamed(string $requested): ?string;

    /**
     * Whether any wired mode delivers a document the tenant signs rather than a list of parameters
     * (JARM §2). Three things read it, the alias the document announces, the algorithms it announces
     * beside it and the retirement window of the key that signs one (issue #155), and they cannot be
     * allowed to disagree.
     */
    public function signsAnyAnswer(): bool;
}
