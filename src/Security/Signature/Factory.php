<?php

namespace IED\SignatureFirewallBundle\Security\Signature;

use Symfony\Component\HttpFoundation\Request;
use Psr\Http\Message\RequestInterface;

class Factory
{
    public static function createFromSymfonyRequest(Config $config, Request $request)
    {
        $parts = [];

        foreach ($config->getCriteria() as $criterion) {
            switch($criterion) {
                case Config::CRITERION_SCHEME:
                    $parts[] = $request->getScheme();
                    break;
                case Config::CRITERION_METHOD:
                    $parts[] = $request->getMethod();
                    break;
                case Config::CRITERION_HOST:
                    $parts[] = $request->getHost();
                    break;
                case Config::CRITERION_PATH_INFO:
                    $parts[] = $request->getPathInfo();
                    break;
                case Config::CRITERION_CONTENT:
                    $parts[] = $request->getContent();
                    break;
                case Config::CRITERION_QUERY_STRING:
                    // we can't use $request->getQueryString() because query string is normalized.
                    $parts[] = http_build_query($request->query->all(), null, '&');
                    break;
                default:
                    throw new \InvalidArgumentException(sprintf('Unknown “%s“ credential', $credential));
                    break;
            }
        }

        return static::hashCriteriaParts($parts, $config->getAlgorithm());
    }

    public static function createFromPsr7Request(Config $config, RequestInterface $request)
    {
        $parts = [];

        foreach ($config->getCriteria() as $criterion) {
            switch($criterion) {
                case Config::CRITERION_SCHEME:
                    $parts[] = $request->getUri()->getScheme();
                    break;
                case Config::CRITERION_METHOD:
                    $parts[] = $request->getMethod();
                    break;
                case Config::CRITERION_HOST:
                    $parts[] = $request->getUri()->getHost();
                    break;
                case Config::CRITERION_PATH_INFO:
                    $parts[] = $request->getUri()->getPath();
                    break;
                case Config::CRITERION_CONTENT:
                    $parts[] = (string) $request->getBody();
                    break;
                case Config::CRITERION_QUERY_STRING:
                    $parts[] = $request->getUri()->getQuery();
                    break;
                default:
                    throw new \InvalidArgumentException(sprintf('Unknown “%s“ credential', $credential));
                    break;
            }
        }

        return static::hashCriteriaParts($parts, $config->getAlgorithm());
    }

    private static function hashCriteriaParts(array $parts, $algorithm)
    {
        return hash($algorithm, implode(',', $parts));
    }
}
