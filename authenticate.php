<?php

/**
 * User Authentication Class
 *
 * PHP Version: 5
 *
 * This is a simple user authentication class.  This class provides methods for password verification, optional
 * password assignment, and checking user authentication.  All methods meant to be used outside the class return
 * false if they fail.
 *
 * A new AuthUser object takes two parameters.  The first is the login method.  This is the source of the login
 * information such as username, password.  The current supported data storage methods are file, db, ldap, or array.
 * The second parameter is the method options array.  It stores all the information that may be needed to access
 * the data storage method, such as file path, or various database information.  Most of the options are used
 * with the db method only.
 *
 * @package		Auth_User
 * @author		Jason Giangrande <jason.giangrande@gmail.com>
 * @copyright   Copyright (C) 2014 Jason Giangrande
 * @license     GPL
 * @version		1.0.0
 */

/**
 * Defines available storage methods.
 *
 * @var         integer
 */
define("SM_ARRAY", 0);
define("SM_FILE", 1);
define("SM_DB", 2);
define("SM_LDAP", 3);

/**
 * Defines supported SQL database engines.
 *
 * @var         string
 */
define("SQLITE", "sqlite");
define("MYSQL", "mysql");
define("POSTGRESQL", "pgsql");
define("ODBC", "odbc");
define("ORACLE", "oci");

/**
 * Defines how important information should be logged.
 *
 * @var         integer
 */
define("LOG_SYSLOG", 0);
define("LOG_FILE", 1);
define("LOG_DATABASE", 2);

require_once("exception.php");

class AuthUser
{
    /**
     * Stores the email address of the user.
     * @var string
     * @access public
     */
    public $email;

    /**
     * Stores the first name of the user.
     * @var string
     * @access public
     */
    public $first_name;

    /**
     * Stores the last name of the user.
     * @var string
     * @access public
     */
    public $last_name;

    /**
     * Stores the username of the user.
     * @var string
     * @access public
     */
    public $username;

    /**
     * Stores all user information retrieved from storage method except email, username, first_name, and last_name.
     * @var array
     * @access public
     */
    public $user_info = array();

    /**
     * Stores a string of all the authentication data that may be useful; including username, password, secret
     * word hash, the number of the secret word if array of secret words given, and permissions if applicable.
     * @var string
     * @access public
     */
    public $valid_user_check;

    /**
     * The following fields must be defined in the storage method if they are to be used; username,
     * pwhash (a.k.a. password), email, first_name, and last_name.  Username and password are mandatory.
     * @var array
     * @access private
     */
    private $_fields = array('username' => 'username', 'password' => 'pwhash', 'email' => 'email',
                                'first_name' => 'first_name', 'last_name' => 'last_name');

    /**
     * Password Length
     *
     * Define minimum/maximum password length.
     * @var array
     * @access private
     */
    private $_len_password = array("min" => 8, "max" => 30);

    /**
     * Username Length
     *
     * Define minimum/maximum username length.
     * @var array
     * @access private
     */
    private $_len_username = array("min" => 4, "max" => 20);

    /**
     * Options used for credential storage.
     *
     * Most options are for use with the database method.  Options include user_array, file_path, engine (db),
     * username, password, hostname, database, table, ldap_host, and suffix.
     * @var array
     * @access private
     */
    private $_storage = array();

    /**
     * Class constructor
     *
     * This is called when a new AuthUser object is created.  It sets up the data storage method and parses
     * the method options.
     *
     * @param array $storage    Array of options used for the data storage method.  Most options are used
     * to configure the database.
     * @param array $options    Array of general options.
     * @access public
     */
    public function __construct($storage) {
        try {
            $this->_parseStorage($storage);
        } catch (AuthSourceException $e) {
            throw New AuthSourceException($storage['source']);
        } catch (DBTypeException $e) {
            throw New DBTypeException($storage['engine']);
        }
    }

    /**
     * Simple option parser
     *
     * Parse miscellaneous options.
     *
     * @param array $options    Options to be parsed.
     * @access private
     */
    private function _parseOptions($options) {
        foreach ($options as $key => $value) {
            $key = strtolower($key);
            $this->_options[$key] = $value;
        }
    }

    /**
     * Data storage option parser
     *
     * Parses data storage options passed to it.
     *
     * @param array $storage    Options to be parsed.
     * @access private
     */
    private function _parseStorage($storage) {
        if (defined($storage['source'])) {
            $method = $storage['source'];
            $this->_storage['source'] = constant($storage['source']);
        } else {
            throw New AuthSourceException($storage['source']);
        }
        foreach ($storage[$method] as $key => $value) {
            $key = strtolower($key);
            if ($key == "engine") {
                if (defined($value)) {
                    $value = constant($value);
                } else {
                    throw New DBTypeException($storage['engine']);
                }
            }
            $this->_storage[$key] = $value;
        }
    }

    /**
     * Validate username
     *
     * @param string $username    Username of user attempting authentication.
     * @return bool
     * @access private
     */
    private function _parseUsername($username) {
        $regex =  "/^[a-z0-9_-]{" . $this->_len_username['min'] . "," . $this->_len_username['max'] . "}$/";
        if (preg_match($regex, $username)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Validate Password
     *
     * @param string $password    Password of user attempting authentication.
     * @return bool
     * @access private
     */
    private function _parsePassword($password) {
        $regex =  "/^[\S]{" . $this->_len_password['min'] . "," . $this->_len_password['max'] . "}$/";
        if (preg_match($regex, $password)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Stores first name in class
     *
     * @param string $first_name      First name of user attempting authentication.
     * @access private
     */
    private function _parseFirstName($first_name) {
        return ucfirst($first_name);
    }

    /**
     * Stores last name in class
     *
     * @param string $last_name      Last name of user attempting authentication.
     * @access private
     */
    private function _parseLastName($last_name) {
        return ucfirst($last_name);
    }

    /**
     * Stores email in class
     *
     * @param string $email      Email of user attempting authentication.
     * @return string            Email address or array with error information.
     * @access private
     */
    private function _parseEmail($email) {
        if (preg_match('/^[^@\s]+@([-a-z0-9]+\.)+[a-z]{2,}$/i', $email)) {
            return strtolower($email);
        } else {
            throw new FormatException("email address '" . $email . "'");
        }
    }

    /**
     * Stores authenticated user's information to publicly accessible variables.
     *
     * @param array $auth       User's information after successful login or auth.
     * @access private
     */
    private function _loadInfo($auth) {
        if (is_array($auth)) {
            foreach ($auth as $key => $value) {
                $field = array_search($key, $this->_fields);
                if ($field) {
                    switch ($field) {
                        case "username":
                            $this->username = $value;
                            break;
                        case "email":
                            $this->email = $value;
                            break;
                        case "first_name":
                            $this->first_name = $value;
                            break;
                        case "last_name":
                            $this->last_name = $value;
                            break;
                        default:
                            $this->user_info[$key] = $value;
                    }
                }
            }
        }
    }

    /**
     * Reads user information from an array for the SM_ARRAY data storage method.
     *
     * @param string $username      Username of user attempting authentication.
     * @param string $password      Password of user attempting authentication.
     * @return mixed                An array of user information if successful, or false otherwise.
     * @access private
     */
    private function _authArray($username, $password) {
        if (is_array($this->_storage['users']) && ! empty($this->_storage['users'])) {
            $users = $this->_storage['users'];
            if (array_key_exists($username, $users)) {
                if (is_array($users[$username])) {
                    if ($users[$username]['passwd'] == $password) {
                        $auth = $users[$username];
                        $auth['username'] = $username;
                    }
                } elseif ((array_search($password, $users) == $username)) {
                    $auth = array('username' => $username, 'passwd' => $password);
                }
            }
        } else {
            throw new UnexpectedValueException("Fatal Error: User's authentication array improperly defined.");
        }
        if (isset($auth)) {
            $this->_loadInfo($auth);
            $auth = true;
        } else {
            $auth = false;
        }
        return $auth;
    }

    /**
     * Reads user information from a file for the SM_FILE data storage method.
     *
     * @param string $username      Username of user attempting authentication.
     * @param string $password      Password of user attempting authentication.
     * @return mixed                An array of user information if successful, or false otherwise.
     * @access private
     */
	private function _authFile($username, $password) {
        $uname_count = 0;
		if (file_exists($this->_storage['path']) && is_file($this->_storage['path'])) {
	        $lines = file($this->_storage['path']);
    	    foreach ($lines as $line) {
                $line = trim($line);
        	    if (preg_match('/^#/', $line)) {
            	    continue;
	            }
    	        if (preg_match("/^$username(?:[\s:]+)/", $line)) {
        	        $param = preg_split("/[\s:]+/", $line);
                    $param_count = count($this->_storage['order']);
                    $passwd_spot = array_search('passwd', $this->_storage['order']);
                    if ($password == $param[$passwd_spot]) {
                        for ($i = 0; $i < $param_count; $i++) {
                            $auth[$this->_storage['order'][$i]] = $param[$i];
                        }
                    }
                    $uname_count++;
	            }
    	    }
		} else {
            throw new Exception("Fatal Error: File " . $this->_storage['path'] . " does not exist.");
        }
        if ($uname_count == 1) {
            $this->_loadInfo($auth);
            $auth = true;
        } elseif ($uname_count > 1) {
            throw new MultiUserException($username);
        } else {
            $auth = false;
        }
        return $auth;
    }

    /**
     * Reads user information from a database for the SM_DB data storage method.
     *
     * @param string $username      Username of user attempting authentication.
     * @param string $password      Password of user attempting authentication.
     * @return mixed                An array of user information if successful, or false otherwise.
     * @access private
     */
    private function _authDB($username, $password) {
        try {
            $dsn = $this->_storage['engine'] . ":host=" . $this->_storage['host'] . ";dbname=" .
                $this->_storage['database'];
            $dbh = new PDO($dsn, $this->_storage['user'], $this->_storage['pass']);
            $query = "SELECT * FROM " . $this->_storage['user_table'] . " WHERE " . $this->_fields['username'] .
                " = ?";
            $sth = $dbh->prepare($query);
            $sth->execute(array($username));
            if ($sth->rowCount() < 1) {
                return false;
            } elseif ($sth->rowCount() > 1) {
                throw new MultiUserException($username);
            } else {
                $result = $sth->fetch(PDO::FETCH_ASSOC);
            }
        } catch (PDOException $e) {
            print "Error! " . $e->getMessage() . "<br />";
            die();
        }
        if ($result[$this->_fields['password']] == $this->hashStr($password)) {
            $this->_loadInfo($result);
            $auth = true;
        } else {
            $auth = false;
        }
        return $auth;
    }

    /**
     * Reads user information from ldap for the SM_LDAP data storage method.
     *
     * @param string $username      Username of user attempting authentication.
     * @param string $password      Password of user attempting authentication.
     * @return mixed                An array of user information if successful, or false otherwise.
     * @access private
     */
    private function _authLdap($username, $password) {
        $dn = "uid=" . $username . "," . $this->_storage['suffix'];
        $conn = ldap_connect($this->_storage['host']);
        if ($conn) {
            $bind = ldap_bind($conn, $dn, $password);
        } else {
            throw new LDAPConnectionException($this->_storage['host']);
        }
        if ($bind) {
            if ($auth_only) {
                $attrs = ldap_read($conn, $dn, "(objectclass=*)", $this->_storage['attrs']);
            } else {
                $auth = false;
            }
            ldap_unbind($conn);
        } else {
            $auth = false;
        }
        return $auth;
    }

    /**
     * Creates a salt which can be added to other strings to make them harder to guess.
     *
     * @param string $salt          The string to use as the salt generator.
     * @param int $num              Arbitrary number to be used during the salt generation.
     * @return string               The salt.
     * @access private
     */
    private function _addSalt($salt, $num) {
        $salt_len = strlen($salt);
        if ($salt_len > 0) {
            if ($salt_len >= $num) {
                $salt = substr($salt, round($num / 3), round($salt_len / 2));
            } else {
                $salt = substr($salt, round($salt_len / 3), round($num / 2));
            }
        }
        return $salt;
    }

    /**
     * Login the user
     *
     * @param string $username      Username of user attempting authentication.
     * @param string $password      Password of user attempting authentication.
     * @param mixed $secret_word    Optional secret word or words.
     * @return string               A string of user information or false if fails
     * @access public
     */
    public function login($username, $password, $secret_word="") {
        if ($credentials = $this->validateUser($username, $password)) {
            $rand = "";
            if (is_array($secret_word)) {
                $rand = rand(0, count($secret_word) - 1);
                $secret_word = $secret_word[$rand];
                $rand = ',' . $rand;
            }
            $len = strlen($password);
            $salt = $this->_addSalt($secret_word, $len);
            $valid = $username . ',' . $this->hashStr($username . $salt) . $rand;
            $this->valid_user_check = $valid;
            return $valid;
        } else {
            return false;
        }
    }

    /**
     * Logout the user
     *
     * @param string $auth          A string of user information.
     * @param mixed $secret_word    Optional secret word or words.
     * @return boolean              True if successful, or false otherwise.
     * @access public
     */
    public function logout($auth, $secret_word="") {
        if ($this->checkAuth($auth, $secret_word)) {
            unset($this->valid_user_check);
            return true;
        } else {
            return false;
        }
    }

    /**
     * Check user credentials
     *
     * @param string $auth          A string of user information.
     * @param mixed $secret_word    Optional secret word or words.
     * @return string               Returns username of authenticated user if successful, or false otherwise.
     * @access public
     */
    public function checkAuth($auth, $secret_word="") {
        if (isset($auth)) {
            list($username, $hash, $rand) = explode(',', $auth);
            if (isset($rand) && is_array($secret_word)) {
                $secret_word = $secret_word[$rand];
            }
            if ($this->hashStr($username.$secret_word) == $hash) {
                //$vars = $username . ',' . $hash . ',' . $rand;
                return $username;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    /**
     * Initially validates a user from a user data storage source.
     *
     * @param string $username      Username of user attempting authentication.
     * @param string $password      Password of user attempting authentication.
     * @return array                An array of user information if successful, or false otherwise.
     * @access public
     */
    public function validateUser($username, $password) {
        $username = strtolower($username);
        if (! $this->_parseUsername($username)) {
            throw new FormatException("username '" . $username . "'");
        }
        if (! $this->_parsePassword($password)) {
            throw new FormatException("password");
        }
        switch ($this->_storage['method']) {
            case 0:
                try {
                    $credentials = $this->_authArray($username, $password);
                } catch (UnexpectedValueException $e) {
                    throw New UnexpectedValueException();
                }
                break;
            case 1:
                try {
                    $credentials = $this->_authFile($username, $password);
                } catch (MultiUserException $e) {
                    throw New MultiUserException($username);
                } catch (Exception $e) {
                    throw New Exception();
                }
                break;
            case 2:
                try {
                    $credentials = $this->_authDB($username, $password);
                } catch (MultiUserException $e) {
                    throw New MultiUserException($username);
                }
                break;
            case 3:
                try {
                    $credentials = $this->_authLdap($username, $password);
                } catch (MultiUserException $e) {
                    throw New MultiUserException($username);
                }
                break;
            default:
                throw New AuthSourceException($this->_storage['source']);
                break;
        }
        return $credentials;
    }

    /**
     * Creates a hash of a string with any of the algorithms that the PHP Hash extension supports.
     *
     * @param string $string        The string to be hashed.
     * @return string               A hashed version of the input string.
     * @access public
     */
    public function hashStr($string, $algo=null) {
        if (is_null($algo)) {
            $algo = "md5";
        }
        $algos = hash_algos();
        if (array_search($algo, $algos)) {
            $hstr = hash_init($algo);
            hash_update($hstr, $string);
            $hash_str = hash_final($hstr);
        } else {
            throw New Exception("Invalid hash algorithm!");
        }
        return $hash_str;
    }

    /**
     * Set addition fields which should be pulled from storage mechanism.
     *
     * @param array $fields
     * @return void
     * @access public
     */
    public function setDataFields($fields) {
        if (is_array($fields)) {
            foreach ($fields as $key => $value) {
                $this->_fields[$key] = $value;
            }
        }
    }

    /**
     * Sets minimum/maximum password length.
     *
     * @param int $min              Minimum password length.
     * @param int $max              Maximum password length.
     * @return void
     * @access public
     */
    public function setPasswordLen($min, $max) {
        if (is_int($min) && is_int($max)) {
            $this->_len_password['min'] = $min;
            $this->_len_password['max'] = $max;
        }
    }

    /**
     * Sets minimum/maximum username length.
     *
     * @param int $min              Minimum username length.
     * @param int $max              Maximum username length.
     * @return void
     * @access public
     */
    public function setUsernameLen($min, $max) {
        if (is_int($min) && is_int($max)) {
            $this->_len_username['min'] = $min;
            $this->_len_username['max'] = $max;
        }
    }

    /**
     * Returns email address of current user.
     *
     * @return string               Email address of current user.
     * @access public
     */
    public function getEmail() {
        return $this->email;
    }

    /**
     * Returns full name of current user.
     *
     * @return string               Full name of current user.
     * @access public
     */
    public function getName() {
        return trim($this->first_name . " " . $this->last_name);
    }

    /**
     * Returns username of current user.
     *
     * @return string               Username of current user.
     * @access public
     */
    public function getUsername() {
        return $this->username;
    }

    public function changePassword($old_password, $new_password) {
        return null;
    }

    /**
     * Log event to specified destination.
     *
     * @param int $priority
     * @param string $message
     * @param int $destination
     * @access public
     */
    public function logEvent($priority, $message, $destination=LOG_SYSLOG) {
        switch (constant($destination)) {
            case 0:
                openlog("AuthUser", 0, LOG_LOCAL5);
                syslog($priority, $message);
                closelog();
                break;
            case 1:
                break;
            default:
        }
    }

    /**
     * Debugging method
     *
     * Prints an array of all object variables.
     *
     * @access public
     */
    public function dumpObject() {
        print_r(get_object_vars($this));
    }
}
?>
