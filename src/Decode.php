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
 *
 *
 * @author Eurolink <info@eurolink.co>
 */
class Decode extends JWT
{
    private $options;

    private $claims;
    private $token;

    /**
     * Decodes a JWT string into a PHP object.
     *
     * @param string    $jwt        The JWT
     * @param array     $options    Options for the JWT.
     *
     * @return object The JWT's payload as a PHP object
     */
    public function __construct($token, array $options = array())
    {
        if ( ! isset($options['key']) || empty($options['key'])) {
            throw new Exception\InvalidKey('Key may not be empty');
        }

        // when checking nbf, iat or expiration times,
        // we want to provide some extra leeway time to
        // account for clock skew.
        if ( ! isset($options['leeway'])) {
            $options['leeway'] = 0;
        }

        $this->options = $options;
        $this->token = $token;
    }

    public function verifyClaims()
    {
        $token = $this->token;

        $segments = explode('.', $token);

        if (count($segments) != 3) {
            throw new Exception\InvalidToken('Wrong number of segments');
        }

        list($headBase64, $bodyBase64, $cryptoBase64) = $segments;

        $header = parent::jsonDecode(parent::urlSafeBase64Decode($headBase64));

        if (is_null($header)) {
            throw new Exception\InvalidHeader('Invalid header encoding');
        }

        $claims = parent::jsonDecode(parent::urlSafeBase64Decode($bodyBase64));

        if (is_null($claims)) {
            throw new Exception\InvalidClaims('Invalid claims encoding');
        }

        $sig = parent::urlSafeBase64Decode($cryptoBase64);

        if (empty($header->alg)) {
            throw new Exception\InvalidAlgorithm('Empty algorithm');
        }

        if (empty(parent::$supportedAlgorithms[$header->alg])) {
            throw new Exception\InvalidAlgorithm('Algorithm not supported');
        }

        if (   ! isset($this->options['algorithms'])
            || ! is_array($this->options['algorithms'])
            || ! in_array($header->alg, $this->options['algorithms'])) {
            throw new Exception\InvalidAlgorithm('Algorithm not allowed');
        }

        $key = $this->options['key'];

        if (is_array($key) || $key instanceof \ArrayAccess) {
            if (isset($header->kid)) {
                $key = $key[$header->kid];
            } else {
                throw new Exception\InvalidKey(
                    '"kid" empty, unable to lookup correct key'
                );
            }
        }

        // check the signature.
        $msg = $headBase64 . '.' . $bodyBase64;
        if ( ! parent::verify($msg, $sig, $key, $header->alg)) {
            throw new Exception\InvalidSignature(
                'Signature verification failed'
            );
        }

        $leeway = $this->options['leeway'];

        // iso date format.
        $dtf = \DateTime::ISO8601;

        // check if the nbf if it is defined. This is the time that the
        // token can actually be used. If it's not yet that time, abort.
        if (isset($claims->nbf) && $claims->nbf > (time() + $leeway)) {
            throw new Exception\InvalidNotBeforeClaim(
                'Cannot handle token prior to ' . date($dtf, $claims->nbf)
            );
        }

        // check that this token has been created before 'now'. This prevents
        // using tokens that have been created for later use (and haven't
        // correctly used the nbf claim).
        if (isset($claims->iat) && $claims->iat > (time() + $leeway)) {
            throw new Exception\InvalidIssuedAtClaim(
                'Cannot handle token prior to ' . date($dtf, $claims->iat)
            );
        }

        // check if this token has expired.
        if (isset($claims->exp) && (time() - $leeway) >= $claims->exp) {
            throw new Exception\ExpiredToken('Expired token');
        }

        $this->header = $header;
        $this->claims = $claims;
    }

    /**
     *
     */
    public function getToken()
    {
        return $this->token;
    }

    /**
     *
     */
    public function getHeader()
    {
        return $this->header;
    }

    /**
     *
     */
    public function getClaims()
    {
        $this->verifyClaims();

        return $this->claims;
    }
}