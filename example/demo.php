<?php
/*
 * This file is part of the JWT package.
 *
 * (c) Eurolink <info@eurolink.co>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

    require realpath(dirname(__FILE__) . '/../autoload.php');
    require realpath(dirname(__FILE__) . '/../tests/Bootstrap.php');

    use Eurolink\JWT;

    /**
     * IMPORTANT:
     * You must specify supported algorithms for your application. See
     * https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40
     * for a list of spec-compliant algorithms.
     */

    $jwt = new JWT\Encode($claims, $options);

    $token = $jwt->getToken();

    echo PHP_EOL . '$token: ' . $token . PHP_EOL;

    $options['algorithms'] = ['HS256'];

    $jwt = new JWT\Decode($token, $options);

    $claims = $jwt->getClaims($assoc = true);

    echo PHP_EOL . '$claims: ' . PHP_EOL;

    print_r($claims);

    /*
     NOTE: This will now be an object instead of an associative array. To get
     an associative array, you will need to cast it as such:
    */

    $claims_array = (array) $claims;

    echo PHP_EOL . '$claims_array: ' . PHP_EOL;

    print_r($claims_array);

    /**
     * You can add a leeway to account for when there is a clock skew times between
     * the signing and verifying servers. It is recommended that this leeway should
     * not be bigger than a few minutes.
     *
     * Source: http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#nbfDef
     */
    $options['leeway'] = 60; // $leeway in seconds

    $jwt = new JWT\Decode($token, $options);

    $claims = $jwt->getClaims();

    echo PHP_EOL . '$claims + leeway: ' . PHP_EOL;

    print_r($claims);