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
 * Algorithm was not provided
 *
 * @author Eurolink <info@eurolink.co>
 */
class InvalidAlgorithm extends JWT\Exception
{
    public function __construct($message, $code = 0)
    {
        parent::__construct($message, $code);
    }
}