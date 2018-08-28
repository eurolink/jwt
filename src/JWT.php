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
 * JSON Web Token implementation, based on the IETF draft specificaiton:
 * http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-06
 *
 * @author Eurolink <info@eurolink.co>
 */
class JWT
{
    public static $supportedAlgorithms = [
        'HS256' => ['hash_hmac', 'SHA256'],
        'HS512' => ['hash_hmac', 'SHA512'],
        'HS384' => ['hash_hmac', 'SHA384'],
        'RS256' => ['openssl', 'SHA256'],
    ];

    /**
     * Decodes a JWT string into a PHP object.
     *
     * @param string            $jwt            The JWT
     * @param string|array|null $key            The key, or map of keys.
     *                                          If the algorithm used is asymmetric, this is the public key
     * @param array             $allowed_algs   List of supported verification algorithms
     *                                          Supported algorithms are 'HS256', 'HS384', 'HS512' and 'RS256'
     *
     * @return object The JWT's payload as a PHP object
     *
     * @throws DomainException              Algorithm was not provided
     * @throws UnexpectedValueException     Provided JWT was invalid
     * @throws SignatureInvalidException    Provided JWT was invalid because the signature verification failed
     * @throws BeforeValidException         Provided JWT is trying to be used before it's eligible as defined by 'nbf'
     * @throws BeforeValidException         Provided JWT is trying to be used before it's been created as defined by 'iat'
     * @throws ExpiredException             Provided JWT has since expired, as defined by the 'exp' claim
     *
     * @uses jsonDecode
     * @uses urlsafeB64Decode
     */
    public static function decode($token, $key, array $allowedAlgorithms = array())
    {
        $options = [
            'key' => $key,
            'algorithms' => $allowedAlgorithms
        ];

        $jwt = new Decode($token, $options);

        return $jwt->getClaims();
    }

    /**
     * Converts and signs a PHP object or array into a JWT string.
     *
     * @param object|array  $payload    PHP object or array
     * @param string        $key        The secret key.
     *                                  If the algorithm used is asymmetric, this is the private key
     * @param string        $alg        The signing algorithm.
     *                                  Supported algorithms are 'HS256', 'HS384', 'HS512' and 'RS256'
     * @param array         $head       An array with header elements to attach
     *
     * @return string A signed JWT
     *
     * @uses jsonEncode
     * @uses urlsafeB64Encode
     */
    public static function encode($payload, $key, $alg = 'HS256', $keyId = null, $head = null)
    {
        $options = [
            'key'  => $key,
            'alg'  => $alg,
            'kid'  => $keyId,
            'head' => $head
        ];

        $jwt = new Encode($payload, $options);

        return $jwt->getToken();
    }

    /**
     * Sign a string with a given key and algorithm.
     *
     * @param string            $msg    The message to sign
     * @param string|resource   $key    The secret key
     * @param string            $alg    The signing algorithm.
     *                                  Supported algorithms are 'HS256', 'HS384', 'HS512' and 'RS256'
     *
     * @return string An encrypted message
     */
    public static function sign($msg, $key, $alg = 'HS256')
    {
        if (empty(self::$supportedAlgorithms[$alg])) {
            throw new Exception\InvalidAlgorithm('Algorithm not supported');
        }

        list($function, $algorithm) = self::$supportedAlgorithms[$alg];

        switch($function) {
            case 'hash_hmac':
                return hash_hmac($algorithm, $msg, $key, true);
            case 'openssl':
                $signature = '';
                $success = openssl_sign($msg, $signature, $key, $algorithm);
                if ( ! $success) {
                    throw new Exception\InvalidCrypto('OpenSSL unable to sign data');
                } else {
                    return $signature;
                }
        }
    }

    /**
     * Verify a signature with the message, key and method. Not all methods
     * are symmetric, so we must have a separate verify and sign method.
     *
     * @param string            $msg        The original message (header and body)
     * @param string            $signature  The original signature
     * @param string|resource   $key        For HS*, a string key works. for RS*, must be a resource of an openssl public key
     * @param string            $alg        The algorithm
     *
     * @return bool
     */
    public static function verify($msg, $signature, $key, $alg)
    {
        if (empty(self::$supportedAlgorithms[$alg])) {
            throw new Exception\InvalidAlgorithm('Algorithm not supported');
        }

        list($function, $algorithm) = self::$supportedAlgorithms[$alg];

        switch($function) {
            case 'openssl':
                $success = openssl_verify($msg, $signature, $key, $algorithm);

                if ( ! $success) {
                    throw new Exception\InvalidCrypto(
                        'OpenSSL unable to verify data: ' . openssl_error_string()
                    );
                } else {
                    return $signature;
                }
            case 'hash_hmac':
            default:
                $hash = hash_hmac($algorithm, $msg, $key, true);

                if (function_exists('hash_equals')) {
                    return hash_equals($signature, $hash);
                }

                $len = min(self::safeStrlen($signature), self::safeStrlen($hash));

                $status = 0;
                for ($i = 0; $i < $len; $i++) {
                    $status |= (ord($signature[$i]) ^ ord($hash[$i]));
                }

                $status |= (self::safeStrlen($signature) ^ self::safeStrlen($hash));

                return ($status === 0);
        }
    }

    /**
     * Helper method to create a JSON error.
     *
     * @param int $errno An error number from json_last_error()
     *
     * @return void
     */
    protected static function jsonError($errno)
    {
        $messages = [
            JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON'
        ];

        throw new Exception\InvalidJson(
            isset($messages[$errno])
            ? $messages[$errno]
            : 'Unknown JSON error: ' . $errno
        );
    }

    /**
     * Get the number of bytes in cryptographic strings.
     *
     * @param string
     *
     * @return int
     */
    private static function safeStrlen($str)
    {
        return  (function_exists('mb_strlen') ? mb_strlen($str, '8bit') : strlen($str));
    }

    /**
     * Decode a JSON string into a PHP object.
     *
     * @param string $input JSON string
     *
     * @return object Object representation of JSON string
     */
    public static function jsonDecode($input)
    {
        if (version_compare(PHP_VERSION, '5.4.0', '>=')
            && ! (defined('JSON_C_VERSION') && PHP_INT_SIZE > 4)) {
            // In PHP >=5.4.0, json_decode() accepts an options parameter,
            // that allows you to specify that large ints (like Steam
            // Transaction IDs) should be treated as strings, rather than
            // the PHP default behaviour of converting them to floats.
            $obj = json_decode($input, false, 512, JSON_BIGINT_AS_STRING);
        } else {
            // Not all servers will support that, however, so for older
            // versions we must manually detect large ints in the JSON
            // string and quote them (thus converting them to strings)
            // before decoding, hence the preg_replace() call.
            $maxIntegerLength = strlen((string) PHP_INT_MAX) - 1;
            $pattern = '/:\s*(-?\d{' . $maxIntegerLength . ',})/';
            $jsonWithoutBigIntegers = preg_replace($pattern, ': "$1"', $input);
            $obj = json_decode($jsonWithoutBigIntegers);
        }

        if (function_exists('json_last_error') && $errno = json_last_error()) {
            self::jsonError($errno);
        } elseif ($obj === null && $input !== 'null') {
            throw new Exception\InvalidJson('Null result with non-null input');
        }

        return $obj;
    }

    /**
     * Decode a string with URL-safe Base64.
     *
     * @param string $input A Base64 encoded string
     *
     * @return string A decoded string
     */
    public static function urlSafeBase64Decode($input)
    {
        $remainder = strlen($input) % 4;
        $str = str_pad(strtr($input, '-_', '+/'), $remainder, '=', STR_PAD_RIGHT);
        return base64_decode($str);
    }

    /**
     * Encode a PHP object into a JSON string.
     *
     * @param object|array $input A PHP object or array
     *
     * @return string JSON representation of the PHP object or array
     *
     * @throws DomainException Provided object could not be encoded to valid JSON
     */
    public static function jsonEncode($input)
    {
        $json = json_encode($input);

        if (function_exists('json_last_error') && $errno = json_last_error()) {
            self::jsonError($errno);
        } elseif ($json === 'null' && $input !== null) {
            throw new Exception\InvalidJson('Null result with non-null input');
        }

        return $json;
    }

    /**
     * Encode a string with URL-safe Base64.
     *
     * @param string $input The string you want encoded
     *
     * @return string The base64 encode of what you passed in
     */
    public static function urlSafeBase64Encode($input)
    {
        return rtrim(strtr(base64_encode($input), '+/', '-_'), '=');
    }
}
