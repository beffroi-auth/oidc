<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\Pki;

use function array_map;
use function array_values;
use Beffroi\Oidc\Domain\Client\Certificate\CertificateSubject;
use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Exception\UnreadableCertificateException;
use Beffroi\Oidc\Port\CertificateReaderInterface;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;
use SpomkyLabs\Pki\X509\GeneralName\IPAddress;
use Throwable;

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
        $names = $extensions->hasSubjectAlternativeName()
            ? $extensions->subjectAlternativeName()->names()
            : null;

        return new CertificateSubject(
            $tbs->subject()->toString(),
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
     * RFC 5280 §4.2.1.6
     *
     * An entry carrying a mask is a name constraint, not an address, and names no client.
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
