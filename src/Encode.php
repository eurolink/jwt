<?php
/*
 * This file is part of the JWT package.
 *
 * (c) Eurolink <info@eurolink.co>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Eurolink\JWT;

/**
 * Converts and signs claims as a token.
 *
 * @author Eurolink <info@eurolink.co>
 */
class Encode extends JWT
{
    private $options;

    private $claims;
    private $token;

    /**
     * Converts and signs a PHP object or array into a JWT string.
     *
     * @param array     $claims     List of claims.
     * @param array     $options    Options for the JWT.
     * @param array     $options    Additional fields to attach to the head.
     *
     * @return string A signed JWT
     */
    public function __construct(array $claims, array $options = array())
    {
        if ( ! isset($options['alg'])) {
            $options['alg'] = 'HS256';
        }

        $this->options = $options;
        $this->claims = $claims;
    }

    /**
     *
     */
    public function signToken()
    {
        $options = $this->options;
        $claims = $this->claims;

        $alg = $options['alg'];
        $key = $options['key'];

        $header = array(
            'typ' => 'JWT',
            'alg' => $alg
        );

        if (isset($options['kid'])) {
            $header['kid'] = $options['kid'];
        }

        if (isset($options['head']) && is_array($options['head'])) {
            $header = array_merge($options['head'], $header);
        }

        $segments = [];

        $segments[] = parent::urlSafeBase64Encode(parent::jsonEncode($header));
        $segments[] = parent::urlSafeBase64Encode(parent::jsonEncode($claims));

        $signingInput = implode('.', $segments);

        $signature = parent::sign($signingInput, $key, $alg);

        $segments[] = parent::urlSafeBase64Encode($signature);

        $this->token = implode('.', $segments);
    }

    /**
     *
     */
    public function getToken()
    {
        $this->signToken();

        return $this->token;
    }
}