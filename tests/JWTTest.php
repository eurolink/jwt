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
 * Tests for IPs.
 *
 * @author Eurolink <info@eurolink.co>
 */
class JWTTest extends \PHPUnit_Framework_TestCase
{
    public function expectException($type)
    {
        $this->setExpectedException('\Eurolink\JWT\Exception\\' . $type);
    }

    public function testEncodeDecodeShorthand()
    {
        $payload = [
            'iss' => 'http://example.org',
            'aud' => 'http://example.com',
            'iat' => 1356999524,
            'nbf' => 1357000000
        ];

        $key = 'secret_key';

        $token = JWT::encode($payload, $key);
        $decoded = JWT::decode($token, $key, ['HS256']);

        $this->assertEquals((array) $decoded, $payload);
    }

    public function testEncodeDecode()
    {
        $claims = [
            'iss' => 'http://example.org',
            'aud' => 'http://example.com',
            'iat' => 1356999524,
            'nbf' => 1357000000
        ];

        $options = [
            'key' => 'secret_key',
            'alg' => 'HS256'
        ];

        $jwt = new Encode($claims, $options);

        $token = $jwt->getToken();

        $options['algorithms'] = ['HS256'];

        $jwt = new Decode($token, $options);

        $this->assertEquals((array) $jwt->getClaims(), $claims);
    }

    public function testDecodeFromPython()
    {
        $token = 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.Iio6aHR0cDovL2FwcGxpY2F0aW9uL2NsaWNreT9ibGFoPTEuMjMmZi5vbz00NTYgQUMwMDAgMTIzIg.E_U8X2YpMT5K1cEiT_3-IvBYfrdIFIeVYeOqre_Z5Cg';

        $matched = '*:http://application/clicky?blah=1.23&f.oo=456 AC000 123';

        $options = [
            'key' => 'my_key',
            'algorithms' => ['HS256']
        ];

        $jwt = new Decode($token, $options);

        $claims = $jwt->getClaims();

        $this->assertEquals($claims, $matched);
    }

    public function testMalformedUtf8StringsFail()
    {
        $this->expectException('InvalidJson');

        $options = [
            'key' => 'secret_key',
            'alg' => 'HS256'
        ];

        $claims = [pack('c', 128)];

        $jwt = new Encode($claims, $options);

        $token = $jwt->getToken();
    }

    public function testMalformedJsonThrowsException()
    {
        $this->expectException('InvalidJson');

        JWT::jsonDecode('this is not valid JSON string');
    }

    public function testExpiredToken()
    {
        $this->expectException('ExpiredToken');

        $timeInPast = time() - 20;

        $claims = [
            'message' => 'foobar',
            'exp' => $timeInPast
        ];

        $options = [
            'key' => 'secret_key',
            'alg' => 'HS256'
        ];

        $jwt = new Encode($claims, $options);

        $token = $jwt->getToken();

        $options['algorithms'] = ['HS256'];

        $jwt = new Decode($token, $options);

        $claims = $jwt->getClaims();
    }

    public function testBeforeValidTokenWithNbf()
    {
        $this->expectException('InvalidNotBeforeClaim');

        $timeInFuture = time() + 20;

        $claims = [
            'message' => 'foobar',
            'nbf' => $timeInFuture
        ];

        $options = [
            'key' => 'secret_key',
            'alg' => 'HS256'
        ];

        $jwt = new Encode($claims, $options);

        $token = $jwt->getToken();

        $options['algorithms'] = ['HS256'];

        $jwt = new Decode($token, $options);

        $claims = $jwt->getClaims();
    }

    public function testBeforeValidTokenWithIat()
    {
        $this->expectException('InvalidIssuedAtClaim');

        $timeInFuture = time() + 20;

        $claims = [
            'message' => 'foobar',
            'iat' => $timeInFuture
        ];

        $options = [
            'key' => 'secret_key',
            'alg' => 'HS256'
        ];

        $jwt = new Encode($claims, $options);

        $token = $jwt->getToken();

        $options['algorithms'] = ['HS256'];

        $jwt = new Decode($token, $options);

        $claims = $jwt->getClaims();
    }

    public function testValidToken()
    {
        $leeway = 0;
        $timeInFuture = time() + $leeway + 20;
        $message = 'foobar';

        $claims = [
            'message' => $message,
            'exp' => $timeInFuture
        ];

        $options = [
            'key' => 'secret_key',
            'alg' => 'HS256'
        ];

        $jwt = new Encode($claims, $options);

        $token = $jwt->getToken();

        $options['algorithms'] = ['HS256'];

        $jwt = new Decode($token, $options);

        $claims = $jwt->getClaims();

        $this->assertEquals($claims->message, $message);
    }

    public function testValidTokenWithLeeway()
    {
        $leeway = 60;
        $timeInPast = time() - 20;
        $message = 'foobar';

        $claims = [
            'message' => $message,
            'exp' => $timeInPast
        ];

        $options = [
            'key' => 'secret_key',
            'alg' => 'HS256',
        ];

        $jwt = new Encode($claims, $options);

        $token = $jwt->getToken();

        $options['algorithms'] = ['HS256'];
        $options['leeway'] = $leeway;

        $jwt = new Decode($token, $options);

        $claims = $jwt->getClaims();

        $this->assertEquals($claims->message, $message);

    }

    public function testExpiredTokenWithLeeway()
    {
        $this->expectException('ExpiredToken');

        $leeway = 60;
        $timeInPast = time() - 70;
        $message = 'foobar';

        $claims = [
            'message' => $message,
            'exp' => $timeInPast
        ];

        $options = [
            'key' => 'secret_key',
            'alg' => 'HS256',
        ];

        $jwt = new Encode($claims, $options);

        $token = $jwt->getToken();

        $options['algorithms'] = ['HS256'];
        $options['leeway'] = $leeway;

        $jwt = new Decode($token, $options);

        $claims = $jwt->getClaims();

        $this->assertEquals($claims->message, $message);
    }

    public function testValidTokenWithList()
    {
        $timeInFuture = time() + 20;

        $message = 'foobar';

        $claims = [
            'message' => $message,
            'exp' => $timeInFuture
        ];

        $options = [
            'key' => 'secret_key',
            'alg' => 'HS256',
        ];

        $jwt = new Encode($claims, $options);

        $token = $jwt->getToken();

        $options['algorithms'] = ['HS256', 'HS512'];

        $jwt = new Decode($token, $options);

        $claims = $jwt->getClaims();

        $this->assertEquals($claims->message, $message);
    }

    public function testValidTokenWithNbf()
    {
        $message = 'foobar';

        $claims = [
            'message' => $message,
            'iat' => time(),
            'exp' => time() + 20, // time in the future
            'nbf' => time() - 20
        ];

        $options = [
            'key' => 'secret_key',
            'alg' => 'HS256',
        ];

        $jwt = new Encode($claims, $options);

        $token = $jwt->getToken();

        $options['algorithms'] = ['HS256'];

        $jwt = new Decode($token, $options);

        $claims = $jwt->getClaims();

        $this->assertEquals($claims->message, $message);
    }

    public function testValidTokenWithNbfLeeway()
    {
        $leeway = 60;
        $message = 'foobar';

        $claims = [
            'message' => $message,
            'nbf' => time() + 20 // not before in near (leeway) future
        ];

        $options = [
            'key' => 'secret_key',
            'alg' => 'HS256',
        ];

        $jwt = new Encode($claims, $options);

        $token = $jwt->getToken();

        $options['algorithms'] = ['HS256'];
        $options['leeway'] = $leeway;

        $jwt = new Decode($token, $options);

        $claims = $jwt->getClaims();

        $this->assertEquals($claims->message, $message);
    }

    public function testInvalidTokenWithNbfLeeway()
    {
        $this->expectException('InvalidNotBeforeClaim');

        $leeway = 60;
        $message = 'foobar';

        $claims = [
            'message' => $message,
            'nbf' => time() + 65 // not before too far in future
        ];

        $options = [
            'key' => 'secret_key',
            'alg' => 'HS256',
        ];

        $jwt = new Encode($claims, $options);

        $token = $jwt->getToken();

        $options['algorithms'] = ['HS256'];
        $options['leeway'] = $leeway;

        $jwt = new Decode($token, $options);

        $claims = $jwt->getClaims();

        $this->assertEquals($claims->message, $message);
    }

    public function testValidTokenWithIatLeeway()
    {
        $leeway = 60;
        $message = 'foobar';

        $claims = [
            'message' => $message,
            'iat' => time() + 20 // issued in near (leeway) future
        ];

        $options = [
            'key' => 'secret_key',
            'alg' => 'HS256',
        ];

        $jwt = new Encode($claims, $options);

        $token = $jwt->getToken();

        $options['algorithms'] = ['HS256'];
        $options['leeway'] = $leeway;

        $jwt = new Decode($token, $options);

        $claims = $jwt->getClaims();

        $this->assertEquals($claims->message, $message);
    }

    public function testInvalidTokenWithIatLeeway()
    {
        $this->expectException('InvalidIssuedAtClaim');

        $leeway = 60;
        $message = 'foobar';

        $claims = [
            'message' => $message,
            'iat' => time() + 65 // issued too far in future
        ];

        $options = [
            'key' => 'secret_key',
            'alg' => 'HS256',
        ];

        $jwt = new Encode($claims, $options);

        $token = $jwt->getToken();

        $options['algorithms'] = ['HS256'];
        $options['leeway'] = $leeway;

        $jwt = new Decode($token, $options);

        $claims = $jwt->getClaims();

        $this->assertEquals($claims->message, $message);
    }

    public function testInvalidToken()
    {
        $this->expectException('InvalidSignature');

        $message = 'foobar';

        $claims = [
            'message' => $message,
            'exp' => time() + 20 // time in the future
        ];

        $options = [
            'key' => 'secret_key',
            'alg' => 'HS256',
        ];

        $jwt = new Encode($claims, $options);

        $token = $jwt->getToken();

        $options['algorithms'] = ['HS256'];
        $options['key'] = 'invalid_secret_key';

        $jwt = new Decode($token, $options);

        $claims = $jwt->getClaims();

        $this->assertEquals($claims->message, $message);
    }

    public function testNullKeyFails()
    {
        $this->expectException('InvalidKey');

        $message = 'foobar';

        $claims = [
            'message' => $message,
            'exp' => time() + 20 // time in the future
        ];

        $options = [
            'key' => 'secret_key',
            'alg' => 'HS256',
        ];

        $jwt = new Encode($claims, $options);

        $token = $jwt->getToken();

        $options['algorithms'] = ['HS256'];
        $options['key'] = null;

        $jwt = new Decode($token, $options);

        $claims = $jwt->getClaims();

        $this->assertEquals($claims->message, $message);
    }

    public function testEmptyKeyFails()
    {
        $this->expectException('InvalidKey');

        $message = 'foobar';

        $claims = [
            'message' => $message,
            'exp' => time() + 20 // time in the future
        ];

        $options = [
            'key' => 'secret_key',
            'alg' => 'HS256',
        ];

        $jwt = new Encode($claims, $options);

        $token = $jwt->getToken();

        $options['algorithms'] = ['HS256'];
        $options['key'] = '';

        $jwt = new Decode($token, $options);

        $claims = $jwt->getClaims();

        $this->assertEquals($claims->message, $message);
    }

    public function testRSEncodeDecode()
    {
        $privateKey = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA
        ]);

        $publicKey = openssl_pkey_get_details($privateKey);

        $message = 'foobar';

        $claims = [
            'message' => $message,
            'exp' => time() + 20 // time in the future
        ];

        $options = [
            'key' => $privateKey,
            'alg' => 'RS256',
        ];

        $jwt = new Encode($claims, $options);

        $token = $jwt->getToken();

        $options['algorithms'] = ['RS256'];
        $options['key'] = $publicKey['key'];

        $jwt = new Decode($token, $options);

        $claims = $jwt->getClaims();

        $this->assertEquals($claims->message, $message);
    }

    public function testKIDChooser()
    {
        $keys = [
            '1' => 'my_key',
            '2' => 'my_key2'
        ];

        $message = 'foobar';

        $claims = [
            'message' => $message,
            'exp' => time() + 20 // time in the future
        ];

        $options = [
            'key' => $keys['1'],
            'alg' => 'HS256',
            'kid' => '1'
        ];

        $jwt = new Encode($claims, $options);

        $token = $jwt->getToken();

        $options['algorithms'] = ['HS256'];
        $options['key'] = $keys;

        $jwt = new Decode($token, $options);

        $claims = $jwt->getClaims();

        $this->assertEquals($claims->message, $message);
    }

    public function testArrayAccessKIDChooser()
    {
        $keys = new \ArrayObject([
            '1' => 'my_key',
            '2' => 'my_key2'
        ]);

        $message = 'foobar';

        $claims = [
            'message' => $message,
            'exp' => time() + 20 // time in the future
        ];

        $options = [
            'key' => $keys['1'],
            'alg' => 'HS256',
            'kid' => '1'
        ];

        $jwt = new Encode($claims, $options);

        $token = $jwt->getToken();

        $options['algorithms'] = ['HS256'];
        $options['key'] = $keys;

        $jwt = new Decode($token, $options);

        $claims = $jwt->getClaims();

        $this->assertEquals($claims->message, $message);
    }

    public function testNoneAlgorithm()
    {
        $this->expectException('InvalidAlgorithm');

        $message = 'foobar';

        $claims = [
            'message' => $message,
            'exp' => time() + 20 // time in the future
        ];

        $options = [
            'key' => 'secret_key',
            'alg' => 'HS256',
            'kid' => '1'
        ];

        $jwt = new Encode($claims, $options);

        $token = $jwt->getToken();

        $options['algorithms'] = ['none'];

        $jwt = new Decode($token, $options);

        $claims = $jwt->getClaims();

        $this->assertEquals($claims->message, $message);
    }

    public function testIncorrectAlgorithm()
    {
        $this->expectException('InvalidAlgorithm');

        $message = 'foobar';

        $claims = [
            'message' => $message,
            'exp' => time() + 20 // time in the future
        ];

        $options = [
            'key' => 'secret_key',
            'alg' => 'HS256',
            'kid' => '1'
        ];

        $jwt = new Encode($claims, $options);

        $token = $jwt->getToken();

        $options['algorithms'] = ['RS256'];

        $jwt = new Decode($token, $options);

        $claims = $jwt->getClaims();

        $this->assertEquals($claims->message, $message);
    }

    public function testMissingAlgorithm()
    {
        $this->expectException('InvalidAlgorithm');

        $message = 'foobar';

        $claims = [
            'message' => $message,
            'exp' => time() + 20 // time in the future
        ];

        $options = [
            'key' => 'secret_key',
            'alg' => 'HS256',
            'kid' => '1'
        ];

        $jwt = new Encode($claims, $options);

        $token = $jwt->getToken();

        $options['algorithms'] = null;

        $jwt = new Decode($token, $options);

        $claims = $jwt->getClaims();

        $this->assertEquals($claims->message, $message);
    }

    public function testAdditionalHeaders()
    {
        $message = 'foobar';

        $claims = [
            'message' => $message,
            'exp' => time() + 20 // time in the future
        ];

        $options = [
            'key' => 'secret_key',
            'alg' => 'HS256',
            'head'=> [
                'cty' => 'test-eit;v=1'
            ]
        ];

        $jwt = new Encode($claims, $options);

        $token = $jwt->getToken();

        $options['algorithms'] = ['HS256'];

        $jwt = new Decode($token, $options);

        $claims = $jwt->getClaims();

        $headers = $jwt->getHeader();

        $this->assertEquals($claims->message, $message);
        $this->assertArrayHasKey('cty', (array) $headers);
    }

    public function testInvalidSegmentCount()
    {
        $this->expectException('InvalidToken');

        $token = 'brokenheader.brokenbody';

        $options = [
            'key' => 'secret_key',
            'algorithms' => ['HS256']
        ];

        $jwt = new Decode($token, $options);

        $claims = $jwt->getClaims();
    }
}
?>