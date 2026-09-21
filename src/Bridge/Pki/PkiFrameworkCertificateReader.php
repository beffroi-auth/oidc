<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\Pki;

use function array_map;
use function array_values;
use Heidi\Oidc\Domain\Client\Certificate\CertificateSubject;
use Heidi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Heidi\Oidc\Exception\UnreadableCertificateException;
use Heidi\Oidc\Port\CertificateReaderInterface;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;
use SpomkyLabs\Pki\X509\GeneralName\IPAddress;
use Throwable;

/**
 * Reads a certificate with pki-framework (docs/09-briques.md), which parses ASN.1 and writes a
 * distinguished name the way RFC 4514 says to. Nothing here takes a name apart with a regular
 * expression: a distinguished name is a structure, not a string, and the string is only how it is
 * written down to be compared with what a client registered (RFC 8705 §2.1.2).
 *
 * Only the leaf is read, and nothing of it is trusted beyond what it says: the chain, the validity and
 * the revocation are the edge's to judge before the request reaches the provider
 * (docs/mtls-at-the-edge.md).
 */
final readonly class PkiFrameworkCertificateReader implements CertificateReaderInterface
{
    public function subjectOf(ClientCertificate $certificate): CertificateSubject
    {
        try {
            $read = Certificate::fromDER($certificate->der);
        } catch (Throwable $exception) {
            throw new UnreadableCertificateException('The certificate presented is not an X.509 certificate.', 0, $exception);
        }
        $tbs = $read->tbsCertificate();
        $extensions = $tbs->extensions();
        $names = $extensions->hasSubjectAlternativeName() ? $extensions->subjectAlternativeName()
            ->names() : null;

        return new CertificateSubject(
            $tbs->subject()
                ->toString(),
            self::entriesOf($names, GeneralName::TAG_DNS_NAME),
            self::entriesOf($names, GeneralName::TAG_URI),
            self::addressesOf($names),
            self::entriesOf($names, GeneralName::TAG_RFC822_NAME),
        );
    }

    public function distinguishedName(string $value): string
    {
        try {
            return Name::fromString($value)->toString();
        } catch (Throwable $exception) {
            throw new UnreadableCertificateException('The value is not a distinguished name of RFC 4514.', 0, $exception);
        }
    }

    /**
     * @return list<string>
     */
    private static function entriesOf(?GeneralNames $names, int $tag): array
    {
        if ($names === null || ! $names->has($tag)) {
            return [];
        }

        return array_values(array_map(static fn (GeneralName $name): string => $name->string(), $names->allOf($tag)));
    }

    /**
     * RFC 5280 §4.2.1.6: an iPAddress entry is four or sixteen octets, which pki-framework writes back
     * as the address it stands for. An entry carrying a mask is a name constraint and not an address,
     * and names no client.
     *
     * @return list<string>
     */
    private static function addressesOf(?GeneralNames $names): array
    {
        if ($names === null || ! $names->has(GeneralName::TAG_IP_ADDRESS)) {
            return [];
        }
        $addresses = [];
        foreach ($names->allOf(GeneralName::TAG_IP_ADDRESS) as $name) {
            if ($name instanceof IPAddress && ! $name->hasMask()) {
                $addresses[] = $name->address();
            }
        }

        return $addresses;
    }
}
