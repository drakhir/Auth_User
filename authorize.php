<?php

/**
 * User Authorization Class
 *
 * PHP Version: 5
 *
 * This is a user authorization class.  This class provides methods for password verification, optional password
 * assignment, checking user authentication, and assigning user access controls.  All methods meant to be used outside
 * the class return false if they fail.
 *
 * The user access control functionality is optional.  It is intended as a simple means to include some kind of access
 * controls with the actual authentication process.  It is integer based with 0 being the lowest (same rights a
 * standard web user would have) to a user defined value (default = 100).  Basically, it's just a defined number stored
 * with the rest of the user's credentials that should correspond to some real world abilities in a web application.
 *
 * A new AuthUser object takes two parameters.  The first is the login method.  In other words, the source of
 * the login information such as username, password, and optionally, permissions.  The current supported data
 * storage methods are file, var, or db.  The second parameter is the method options array.  It stores all
 * the information that may be needed to access the data storage method, such as file path, or various
 * database information.  Most of the options are used with the db method only.
 *
 * @package     Auth_User
 * @author      Jason Giangrande
 * @copyright   Copyright (C) 2011 Jason Giangrande
 * @license     GPL
 * @version     1.0.0
 */

require_once("exception.php");
require_once("authenticate.php");

class AuthorizeUser extends AuthUser
{
     /**
     * Stores the access control level, if any, of the person being authenticated.
     * @var string
     * @access public
     */
    public $access_control;

    private function _writeToFile() {
        return null;
    }

    private function _writeToDB() {
        return null;
    }

    private function _writeToLdap() {
        return null;
    }

    public function addUser() {
        return null;
    }

    public function deleteUser() {
        return null;
    }

    public function listUsers() {
        return null;
    }

    public function logView() {
        return null;
    }

    public function modUser() {
        return null;
    }

    public function setExpire() {
        return null;
    }

    public function setIdle() {
        return null;
    }
}

?>
