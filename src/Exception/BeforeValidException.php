<?php
/*
 * This file is part of the JWT package.
 *
 * (c) Eurolink <info@eurolink.co>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Eurolink\JWT\Exception;

use Eurolink\JWT;

/**
 * Provided JWT is trying to be used before it's eligible as defined by 'nbf'
 * Provided JWT is trying to be used before it's been created as defined by 'iat'
 *
 * @author Eurolink <info@eurolink.co>
 */
class BeforeValidException extends JWT\Exception
{
    public function __construct($message, $code = 0)
    {
        parent::__construct($message, $code);
    }
}