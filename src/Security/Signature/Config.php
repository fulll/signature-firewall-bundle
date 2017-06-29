<?php

namespace IED\SignatureFirewallBundle\Security\Signature;

use Symfony\Component\HttpFoundation\Request;

class Config
{
    private $algorithm;
    private $criteria = [];

    const CRITERION_SCHEME = 'scheme';
    const CRITERION_METHOD = 'method';
    const CRITERION_HOST = 'host';
    const CRITERION_PATH_INFO = 'path_info';
    const CRITERION_CONTENT = 'content';
    const CRITERION_QUERY_STRING = 'query_string';

    public function __construct(array $criteria, $algorithm = 'sha256')
    {
        $this->criteria  = $criteria;
        $this->algorithm = $algorithm;
    }

    public function getCriteria()
    {
        return $this->criteria;
    }

    public function getAlgorithm()
    {
        return $this->algorithm;
    }

    public static function getAvailableCriteria()
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
