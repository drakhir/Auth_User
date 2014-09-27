<?php

/**
 * User Defined Exceptions
 *
 * PHP Version: 5
 *
 * User defined exceptions for the Auth_User package.
 *
 * @package     Auth_User
 * @author      Jason Giangrande
 * @copyright   Copyright (C) 2011 Jason Giangrande
 * @license     GPL
 * @version     1.0.0
 */

class AuthSourceException extends Exception
{
    public function errorMessage() {
        $error = "'" . $this->getMessage() . "' is not a valid authentication source.";
        return $error;
    }
}

class DBTypeException extends Exception
{
    public function errorMessage() {
        $error = "'" . $this->getMessage() . "' is not a valid database.";
        return $error;
    }
}

class LDAPConnectionException extends Exception
{
    public function errorMessage() {
        $error = "Unable to connect to directory server '" . $this->getMessage() . "'.";
        return $error;
    }
}

class MultiUserException extends Exception
{
    public function errorMessage() {
        $error = "Multiple username entries found for user '" . $this->getMessage() . "'. Authentication failed.";
        return $error;
    }
}

class FormatException extends Exception
{
    public function errorMessage() {
        $error = "Invalid characters found in " . $this->getMessage() . ".";
        return $error;
    }
}

?>
