<?php

/**
 * Example configuration options for the Authenticate and Authorize classes.
 *
 * @package     Auth_User
 * @author      Jason Giangrande <jason@giangrande.org>
 * @copyright   Copyright (C) 2011 Jason Giangrande
 */

// General options
/**
 * Defines which hashing method is used to encrypt stored passwords. See the PHP Hash documentation for available
 * algorithms.
 *
 * @var         string
 */
$CONFIG['hash_type'] = "md5";

/**
 * Word or list of words to be used as password salt. Can be a string or an array of words.
 *
 * @var         mixed
 */
$CONFIG['secret_word'] = "";

$CONFIG['username']['min_chars'] = 4;
$CONFIG['username']['max_chars'] = 20;
$CONFIG['password']['min_chars'] = 8;
$CONFIG['password']['max_chars'] = 30;

// Storage options
$CONFIG['storage']['method'] = "SM_FILE";

//$CONFIG['storage']['SM_ARRAY']['users'] = array('jason' => 'blahblah', 'josh' => 'transformers');
$CONFIG['storage']['SM_ARRAY']['users'] = array('jason' => array('passwd' => 'blahblah', 'first_name' => 'Jason',
    'email' => 'jason@giangrande.org'), 'josh' => array('passwd' => 'transformers', 'first_name' => 'Josh',
    'email' => 'josh@giangrande.org'));

$CONFIG['storage']['SM_FILE']['path'] = "/tmp/users.txt";
$CONFIG['storage']['SM_FILE']['order'] = array('username', 'passwd', 'first_name', 'last_name', 'email');

$CONFIG['storage']['SM_DB']['engine'] = "MYSQL";
$CONFIG['storage']['SM_DB']['host'] = "localhost";
$CONFIG['storage']['SM_DB']['user'] = "authuser";
$CONFIG['storage']['SM_DB']['pass'] = "d7Gpq3We";
$CONFIG['storage']['SM_DB']['database'] = "authuser";
$CONFIG['storage']['SM_DB']['user_table'] = "users";

$CONFIG['storage']['SM_LDAP']['host'] = "ldaps://nyx.clarku.edu";
$CONFIG['storage']['SM_LDAP']['suffix'] = "ou=Users,dc=clarku,dc=edu";
$CONFIG['storage']['SM_LDAP']['attrs'] = array('givenName', 'sn', 'mail');

?>
