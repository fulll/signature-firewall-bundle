<?php

namespace IED\SignatureFirewallBundle\Security;

use Symfony\Component\HttpFoundation\Request;

class RequestSignatureValidator
{
    private $hashAlgorithm;
    private $criteria = [];

    const CRITERION_SCHEME = 'scheme';
    const CRITERION_METHOD = 'method';
    const CRITERION_HOST = 'host';
    const CRITERION_PATH_INFO = 'path_info';
    const CRITERION_CONTENT = 'content';
    const CRITERION_QUERY_STRING = 'query_string';

    public function __construct(array $criteria, $hashAlgorithm = 'sha256')
    {
        $this->criteria      = $criteria;
        $this->hashAlgorithm = $hashAlgorithm;
    }

    public function validate($hash, Request $request)
    {
        $parts = [];
            foreach ($this->criteria as $criterion) {
                switch($criterion) {
                    case static::CRITERION_SCHEME:
                        $parts[] = $request->getScheme();
                        break;
                    case static::CRITERION_METHOD:
                        $parts[] = $request->getMethod();
                        break;
                    case static::CRITERION_HOST:
                        $parts[] = $request->getHost();
                        break;
                    case static::CRITERION_PATH_INFO:
                        $parts[] = $request->getPathInfo();
                        break;
                    case static::CRITERION_CONTENT:
                        $parts[] = $request->getContent();
                        break;
                    case static::CRITERION_QUERY_STRING:
                        $parts[] = $request->getQueryString();
                        break;
                    default:
                        throw new \InvalidArgumentException(sprintf('Unknown “%s“ credential', $credential));
                        break;
                }
            }

        return $hash == hash($this->hashAlgorithm, implode(',', $parts));
    }

    public static function getCriteria()
    {
        return [
            static::CRITERION_SCHEME,
            static::CRITERION_METHOD,
            static::CRITERION_HOST,
            static::CRITERION_PATH_INFO,
            static::CRITERION_CONTENT,
            static::CRITERION_QUERY_STRING,
        ];
    }

}
