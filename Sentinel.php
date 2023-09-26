<?php

namespace Rose\Ext;

use Rose\Errors\Error;
use Rose\Data\Connection;
use Rose\Configuration;
use Rose\Session;
use Rose\Gateway;
use Rose\Strings;
use Rose\Resources;
use Rose\Extensions;
use Rose\Text;
use Rose\Expr;
use Rose\Map;
use Rose\Arry;

use Rose\Ext\Wind;

if (!Extensions::isInstalled('Wind'))
    return;

/**
 * Sentinel extension.
 */
class Sentinel
{
    /**
     * Error codes.
     */
    public const ERR_NONE					= 0;
    public const ERR_AUTHORIZATION			= 1;
    public const ERR_CREDENTIALS			= 2;
    public const ERR_BEARER_DISABLED		= 3;

    /**
     * Indicates if the session has been loaded.
     */
    private static $loadedSession = false;

    /**
     * Returns the name of the error code.
     * @param {int} $code - Error code.
     * @returns {string}
     */
    public static function errorName ($code) : string
    {
        switch ($code) {
            case Sentinel::ERR_AUTHORIZATION:
                return 'err_authorization';
            case Sentinel::ERR_CREDENTIALS:
                return 'err_credentials';
            case Sentinel::ERR_BEARER_DISABLED:
                return 'err_bearer_disabled';
        }

        return 'err_none';
    }

    /**
     * Returns the password hash for the specified value.
     * @param {string} $value - Value to hash.
     * @param {bool} $escape - If true, the value will be escaped.
     * @returns {string}
     */
    public static function password ($value, $escape=false) : string
    {
        $conf = Configuration::getInstance()->Sentinel ?? new Map();
        $value = \hash($conf->hash ? $conf->hash : 'sha384', $conf->prefix . $value . $conf->suffix);
        if ($escape) $value = Connection::escape($value);
        
        return $value;
    }

    /**
     * Returns the privileges of the current user (or token privileges if `tokenPrivileges` is enabled).
     * @returns {string[]}
     */
    private static function getPrivileges()
    {
        $conn = Resources::getInstance()->Database;
        if (!Sentinel::status()) return new Arry();

        $conf = Configuration::getInstance()->Sentinel;
        if ($conf && $conf->tokenPrivileges === 'true' && Session::$data->user->token_id) {
            return $conn->execQuery(
                'SELECT DISTINCT p.privilege_id, p.name FROM ##privileges p '.
                'INNER JOIN ##token_privileges t ON t.privilege_id=p.privilege_id '.
                'WHERE t.token_id='.Session::$data->user->token_id
            );
        }

        return $conn->execQuery(
            'SELECT DISTINCT p.privilege_id, p.name FROM ##privileges p '.
            'INNER JOIN ##user_privileges u ON u.privilege_id=p.privilege_id '.
            'WHERE u.user_id='.Session::$data->user->user_id
        );
    }

    /**
     * Checks if the current user is logged in.
     * @returns {bool}
     */
    public static function status()
    {
        $conf = Configuration::getInstance()->Sentinel;
        if (self::$loadedSession)
            return Session::$data->user !== null ? true : false;

        // If the session is not open, we open it in shallow mode to check if the user is logged in.
        Session::open(false);
        Session::close(true);
        self::$loadedSession = true;

        // Check for the authorization header, when present we check if the token is valid and if so we grant access.
        $auth = Gateway::getInstance()->server->HTTP_AUTHORIZATION;
        if (!$auth) return Session::$data->user !== null ? true : false;

        $tmp = Text::toUpperCase($auth);
        if (Text::startsWith($tmp, 'BEARER') && $conf && $conf->authBearer === 'true') {
            $code = self::authorize(Text::substring($auth, 7), false);
            if ($code !== Sentinel::ERR_NONE)
                Wind::reply([ 'response' => Wind::R_VALIDATION_ERROR, 'error' => Strings::get('@messages.'.Sentinel::errorName($code)) ]);
        }
        else if (Text::startsWith($tmp, 'BASIC') && $conf && $conf->authBasic === 'true') {
            $auth = base64_decode(Text::substring($auth, 6));
            $i = strpos($auth, ':');
            if ($i == -1) {
                Gateway::header('HTTP/1.1 401 Not Authenticated');
                Gateway::header('WWW-Authenticate: Basic');
                Wind::reply([ 'response' => Wind::R_VALIDATION_ERROR, 'error' => Strings::get('@messages.'.Sentinel::errorName(Sentinel::ERR_CREDENTIALS)) ]);
            }

            $username = Text::substring($auth, 0, $i);
            $password = Text::substring($auth, $i+1);
            $code = self::login($username, $password, false, true);
            if ($code != Sentinel::ERR_NONE) {
                Gateway::header('HTTP/1.1 401 Not Authenticated');
                Gateway::header('WWW-Authenticate: Basic');
                Wind::reply([ 'response' => Wind::R_VALIDATION_ERROR, 'error' => Strings::get('@messages.'.Sentinel::errorName($code)) ]);
            }
        }

        return Session::$data->user !== null ? true : false;
    }

    /**
     * Checks if the specified token is valid and if so, authorizes the user for access.
     * @param {string} $token - Token to check.
     * @param {bool} $openSession - If true, the session will be opened.
     * @returns {int} Error code.
     */
    public static function authorize (string $token, bool $openSession=true)
    {
        $conf = Configuration::getInstance()->Sentinel;
        if ($conf && $conf->authBearer !== 'true')
            return Sentinel::ERR_BEARER_DISABLED;

        $data = Resources::getInstance()->Database->execAssoc(
            'SELECT u.*, t.token_id, LEAST(u.is_authorized, t.is_authorized) is_authorized '.
            'FROM ##users u '.
            'INNER JOIN ##tokens t ON t.is_active=1 AND t.user_id=u.user_id '.
            'WHERE u.is_active=1 AND t.token='.Connection::escape($token)
        );
        if (!$data) return Sentinel::ERR_CREDENTIALS;

        if ((int)$data->is_authorized == 0)
            return Sentinel::ERR_AUTHORIZATION;

        self::$loadedSession = true;
        if ($openSession) Session::open(true);

        Session::$data->user = $data;
        $list = Sentinel::getPrivileges();
        $data->privileges = $list->map(function($i) { return $i->name; });
        $data->privilege_ids = $list->map(function($i) { return $i->privilege_id; });
        return Sentinel::ERR_NONE;
    }

    /**
     * Checks if the specified credentials are valid and if so, logs the user in.
     * @param {string} $username - Username.
     * @param {string|null} $password - Password (plain text).
     * @param {bool} $openSession - If true, the session will be opened.
     * @param {bool} $allowToken - If true, the password will be treated as a token when the username is 'token'.
     * @returns {int} Error code.
     */
    public static function login (string $username, ?string $password=null, bool $openSession=true, bool $allowToken=false)
    {
        if ($password !== null) {
            if ($allowToken && $username === 'token') {
                $data = Resources::getInstance()->Database->execAssoc (
                    'SELECT u.*, t.token_id, LEAST(u.is_authorized, t.is_authorized) is_authorized '.
                    'FROM ##users u '.
                    'INNER JOIN ##tokens t ON t.is_active=1 AND t.user_id=u.user_id '.
                    'WHERE u.is_active=1 AND t.token='.Connection::escape($password)
                );
            } else {
                $data = Resources::getInstance()->Database->execAssoc (
                    'SELECT * FROM ##users '.
                    'WHERE is_active=1 AND username='.Connection::escape($username).' AND password='.Sentinel::password($password, true)
                );
            }
        } else {
            $data = Resources::getInstance()->Database->execAssoc (
                'SELECT * FROM ##users WHERE is_active=1 AND user_id='.Connection::escape($username)
            );
        }

        if (!$data) return Sentinel::ERR_CREDENTIALS;

        if ((int)$data->is_authorized == 0)
            return Sentinel::ERR_AUTHORIZATION;

        self::$loadedSession = true;
        if ($openSession) Session::open(true);

        Session::$data->user = $data;
        $list = Sentinel::getPrivileges();
        $data->privileges = $list->map(function($i) { return $i->name; });
        $data->privilege_ids = $list->map(function($i) { return $i->privilege_id; });
        return Sentinel::ERR_NONE;
    }

    /**
     * Logs the user in manually using the specified data.
     * @param {Map} $data - User data.
     * @returns {int} Error code.
     */
    public static function manual (Map $data)
    {
        self::$loadedSession = true;
        Session::open(true);

        Session::$data->user = $data;
        $data->privileges = $data->has('privileges') ? $data->get('privileges') : new Arry();
        $data->privilege_ids = $data->has('privilege_ids') ? $data->get('privilege_ids') : new Arry();
        return Sentinel::ERR_NONE;
    }

    /**
     * Checks if the specified credentials are valid.
     * @param {string} $username - Username.
     * @param {string} $password - Password (plain text).
     * @returns {int} Error code.
     */
    public static function valid (string $username, string $password)
    {
        $data = Resources::getInstance()->Database->execAssoc(
            'SELECT * FROM ##users WHERE is_active=1 AND username='.Connection::escape($username).' AND password='.Sentinel::password($password, true)
        );
        if (!$data) return Sentinel::ERR_CREDENTIALS;

        if ((int)$data->is_authorized == 0)
            return Sentinel::ERR_AUTHORIZATION;

        return Sentinel::ERR_NONE;
    }

    /**
     * Logs the user out. The session field `user` will be removed, but the session will continue to exist, if you want the
     * session to be destroyed, call `Session::destroy()`.
     */
    public static function logout() {
        if (!Session::open(false)) return;
        Session::$data->remove('user');
    }

    /**
     * Reloads the user data of the currently active user from the database.
     */
    public static function reload()
    {
        if (!Session::open(false)) return;

        if (Session::$data->user->token_id) {
            $data = Resources::getInstance()->Database->execAssoc (
                'SELECT u.*, t.token_id, LEAST(u.is_authorized, t.is_authorized) is_authorized '.
                'FROM ##users u '.
                'INNER JOIN ##tokens t ON t.is_active=1 AND t.user_id=u.user_id '.
                'WHERE u.is_active=1 AND t.token_id='.Connection::escape(Session::$data->user->token_id)
            );
        } else {
            $data = Resources::getInstance()->Database->execAssoc (
                'SELECT * FROM ##users WHERE is_active=1 AND user_id='.Connection::escape(Session::$data->user->user_id)
            );
        }

        if (!$data) return;

        Session::$data->user = $data;
        $list = Sentinel::getPrivileges();
        $data->privileges = $list->map(function($i) { return $i->name; });
        $data->privilege_ids = $list->map(function($i) { return $i->privilege_id; });
    }

    /**
     * Checks if the current user has one or more privileges.
     * @param {string} $privilege - Privileges separated by comma.
     * @param {string}null} $username - Username to check, if `null` the current user will be used.
     * @returns {bool}
     */
    public static function hasPrivilege ($privilege, $username=null)
    {
        if (!$privilege) return true;

        $conf = Configuration::getInstance()->Sentinel;
        $conn = Resources::getInstance()->Database;

        $privilege = Text::split(',', ($conf && $conf->master === 'true' ? 'master,' : '').$privilege)->map(function($i) { return Connection::escape($i); })->join(',');
        $count = 0;

        if ($username !== null) {
            $count = $conn->execScalar (
                ' SELECT COUNT(*) FROM ##privileges p '.
                ' INNER JOIN ##user_privileges up ON up.privilege_id=p.privilege_id'.
                ' INNER JOIN ##users u ON u.is_active=1 AND u.username='.Connection::escape($username).' AND up.user_id=u.user_id'.
                ' WHERE p.name IN ('.$privilege.')'
            );
            return $count != 0 ? true : false;
        }

        if (!Sentinel::status()) return false;

        if ($conf && $conf->tokenPrivileges === 'true' && Session::$data->user->token_id) {
            $count = $conn->execScalar (
                ' SELECT COUNT(*) FROM ##privileges p '.
                ' INNER JOIN ##token_privileges tp ON tp.privilege_id=p.privilege_id'.
                ' WHERE tp.token_id='.Session::$data->user->token_id.' AND p.name IN ('.$privilege.')'
            );
        }
        else {
            $count = $conn->execScalar (
                ' SELECT COUNT(*) FROM ##privileges p '.
                ' INNER JOIN ##user_privileges up ON up.privilege_id=p.privilege_id'.
                ' WHERE up.user_id='.Session::$data->user->user_id.' AND p.name IN ('.$privilege.')'
            );
        }

        return $count != 0 ? true : false;
    }

    /**
     * Checks if the current user has at least one privilege group.
     * @param {string} $value - Privilege sets separated by comma, AND-groups separated by ampersand (&).
     * @param {string|null} $username - Username to check, if `null` the current user will be used.
     * @returns {bool}
     */
    public static function verifyPrivileges ($value, $username=null)
    {
        if (!$username && !Sentinel::status())
            return false;

        $groups = Text::split(',', Text::trim($value ? $value : ''));
        foreach ($groups->__nativeArray as $group)
        {
            $groupFailed = false;
            foreach (Text::split('&', Text::trim($group))->__nativeArray as $privilege)
            {
                if (!Sentinel::hasPrivilege (Text::trim($privilege), $username)) {
                    $groupFailed = true;
                    break;
                }
            }

            if ($groupFailed == false) return true;
        }

        return false;
    }

    /**
     * Checks if the current user has at least the specified level.
     * @param {int} $level - Level to check.
     * @param {string|null} $username - Username to check, if `null` the current user will be used.
     * @returns {bool}
     */
    public static function hasLevel ($level, $username=null)
    {
        if (!$level) return true;

        $conf = Configuration::getInstance()->Sentinel;
        $conn = Resources::getInstance()->Database;
        $count = 0;

        if ($username !== null) {
            $count = $conn->execScalar (
                ' SELECT COUNT(*) FROM ##privileges p '.
                ' INNER JOIN ##user_privileges up ON up.privilege_id=p.privilege_id'.
                ' INNER JOIN ##users u ON u.is_active=1 AND u.username='.Connection::escape($username).' AND up.user_id=u.user_id'.
                ' WHERE FLOOR(p.privilege_id/100) >= '.$level
            );
            return $count != 0 ? true : false;
        }

        if (!Sentinel::status()) return false;

        if ($conf && $conf->tokenPrivileges === 'true' && Session::$data->user->token_id) {
            $count = $conn->execScalar (
                ' SELECT COUNT(*) FROM ##privileges p '.
                ' INNER JOIN ##token_privileges tp ON tp.privilege_id=p.privilege_id'.
                ' WHERE tp.token_id='.Session::$data->user->token_id.' AND FLOOR(p.privilege_id/100) >= '.$level
            );
        }
        else {
            $count = $conn->execScalar (
                ' SELECT COUNT(*) FROM ##privileges p '.
                ' INNER JOIN ##user_privileges up ON up.privilege_id=p.privilege_id'.
                ' WHERE up.user_id='.Session::$data->user->user_id.' AND FLOOR(p.privilege_id/100) >= '.$level
            );
        }

        return $count != 0 ? true : false;
    }

    /**
     * Returns the level of the current user.
     * @param {string|null} $username - Username to check, if `null` the current user will be used.
     * @returns {int}
     */
    public static function getLevel ($username=null)
    {
        $conf = Configuration::getInstance()->Sentinel;
        $conn = Resources::getInstance()->Database;

        if ($username !== null) {
            $level = $conn->execScalar (
                ' SELECT MAX(FLOOR(p.privilege_id/100)) FROM ##privileges p '.
                ' INNER JOIN ##user_privileges up ON up.privilege_id=p.privilege_id'.
                ' INNER JOIN ##users u ON u.is_active=1 AND u.username='.Connection::escape($username).' AND up.user_id=u.user_id'
            );
            return (int)$level;
        }
        
        if (!Sentinel::status()) return 0;

        if ($conf && $conf->tokenPrivileges === 'true' && Session::$data->user->token_id) {
            $level = $conn->execScalar (
                ' SELECT MAX(FLOOR(p.privilege_id/100)) FROM ##privileges p '.
                ' INNER JOIN ##token_privileges tp ON tp.privilege_id=p.privilege_id'.
                ' WHERE tp.token_id='.Session::$data->user->token_id
            );
        }
        else {
            $level = $conn->execScalar (
                ' SELECT MAX(FLOOR(p.privilege_id/100)) FROM ##privileges p '.
                ' INNER JOIN ##user_privileges up ON up.privilege_id=p.privilege_id'.
                ' WHERE up.user_id='.Session::$data->user->user_id
            );
        }

        return (int)$level;
    }
};

/* ****************************************************************************** */
Expr::register('sentinel::password', function($args, $parts, $data) {
    return Sentinel::password($args->get(1));
});

Expr::register('sentinel::status', function($args, $parts, $data) {
    return Sentinel::status();
});

Expr::register('sentinel::auth-required', function($args, $parts, $data)
{
    $conf = Configuration::getInstance()->Sentinel;
    if (Sentinel::status()) return null;

    if ($conf && $conf->authBasic === 'true') {
        Gateway::header('HTTP/1.1 401 Not Authenticated');
        Gateway::header('WWW-Authenticate: Basic');
    }

    Wind::reply([ 'response' => Wind::R_NOT_AUTHENTICATED ]);
    return null;
});

Expr::register('sentinel::privilege-required', function($args, $parts, $data)
{
    $conf = Configuration::getInstance()->Sentinel;
    if (Sentinel::verifyPrivileges($args->get(1))) return null;

    if (Sentinel::status())
        Wind::reply([ 'response' => Wind::R_PRIVILEGE_REQUIRED ]);

    if ($conf && $conf->authBasic === 'true') {
        Gateway::header('HTTP/1.1 401 Not Authenticated');
        Gateway::header('WWW-Authenticate: Basic');
    }

    Wind::reply([ 'response' => Wind::R_NOT_AUTHENTICATED ]);
    return null;
});

Expr::register('sentinel::has-privilege', function($args, $parts, $data) {
    return Sentinel::verifyPrivileges($args->get(1), $args->{2});
});

Expr::register('_sentinel::case', function($parts, $data)
{
	$n = $parts->length();
	for ($i = 1; $i < $n; $i += 2)
	{
		$case_value = (string)Expr::expand($parts->get($i), $data, 'arg');
		if ($i == $n-1 && !($n&1)) return $case_value;

		if (Sentinel::verifyPrivileges($case_value) || $case_value === 'default')
			return Expr::expand($parts->get($i+1), $data, 'arg');
	}

    return '';
});

Expr::register('sentinel::level-required', function($args, $parts, $data)
{
    $conf = Configuration::getInstance()->Sentinel;
    if (Sentinel::hasLevel ($args->get(1))) return null;

    if (Sentinel::status())
        Wind::reply([ 'response' => Wind::R_PRIVILEGE_REQUIRED ]);

    if ($conf && $conf->authBasic === 'true') {
        Gateway::header('HTTP/1.1 401 Not Authenticated');
        Gateway::header('WWW-Authenticate: Basic');
    }

    Wind::reply([ 'response' => Wind::R_NOT_AUTHENTICATED ]);
    return null;
});

Expr::register('sentinel::has-level', function($args, $parts, $data) {
    return Sentinel::hasLevel ($args->get(1));
});

Expr::register('sentinel::get-level', function($args, $parts, $data) {
    return Sentinel::getLevel ($args->has(1) ? $args->get(1) : null);
});

Expr::register('sentinel::valid', function($args, $parts, $data) {
    return Sentinel::valid ($args->get(1), $args->get(2)) == Sentinel::ERR_NONE;
});

Expr::register('sentinel::token-id', function($args, $parts, $data) {
    $user = Session::$data->user;
    return !$user ? null : $user->token_id;
});

Expr::register('sentinel::validate', function($args, $parts, $data) {
    $code = Sentinel::valid ($args->get(1), $args->get(2));
    if ($code != Sentinel::ERR_NONE)
        Wind::reply([ 'response' => Wind::R_VALIDATION_ERROR, 'error' => Strings::get('@messages.'.Sentinel::errorName($code)) ]);
    return null;
});

Expr::register('sentinel::login', function($args, $parts, $data)
{
    $code = Sentinel::login ($args->get(1), $args->get(2));
    if ($code != Sentinel::ERR_NONE)
        Wind::reply([ 'response' => Wind::R_VALIDATION_ERROR, 'error' => Strings::get('@messages.'.Sentinel::errorName($code)) ]);
    return null;
});

Expr::register('sentinel::authorize', function($args, $parts, $data)
{
    if ($args->has(2))
        $code = Sentinel::authorize ($args->get(1), \Rose\bool($args->get(2)));
    else
        $code = Sentinel::authorize ($args->get(1), false);

    if ($code != Sentinel::ERR_NONE)
        Wind::reply([ 'response' => Wind::R_VALIDATION_ERROR, 'error' => Strings::get('@messages.'.Sentinel::errorName($code)) ]);

    return null;
});

Expr::register('sentinel::login-manual', function($args, $parts, $data) {
    Sentinel::manual ($args->get(1));
    return null;
});

Expr::register('sentinel::login-user', function($args, $parts, $data) {
    $code = Sentinel::login ($args->get(1), null, true, false);
    if ($code != Sentinel::ERR_NONE)
        Wind::reply([ 'response' => Wind::R_VALIDATION_ERROR, 'error' => Strings::get('@messages.'.Sentinel::errorName($code)) ]);
    return null;
});

Expr::register('sentinel::logout', function($args, $parts, $data) {
    Sentinel::logout();
    return null;
});

Expr::register('sentinel::reload', function($args, $parts, $data) {
    Sentinel::reload();
    return null;
});
