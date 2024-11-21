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
use Rose\DateTime;
use Rose\Text;
use Rose\Expr;
use Rose\Map;
use Rose\Arry;

use Rose\Ext\Wind;

// @title Sentinel

/**
 * Sentinel extension.
 */
class Sentinel
{
    /**
     * Error codes.
     */
    public const ERR_NONE                   = 0;
    public const ERR_AUTHORIZATION_BLOCKED  = 1;
    public const ERR_INVALID_CREDENTIALS    = 2;
    public const ERR_AUTH_BEARER_DISABLED   = 3;
    public const ERR_AUTH_BASIC_DISABLED    = 4;
    public const ERR_AUTH_REQUIRED          = 5;
    public const ERR_PERMISSION_REQUIRED    = 6;
    public const ERR_LEVEL_REQUIRED         = 7;
    public const ERR_AUTHORIZATION_BANNED   = 8;
    public const ERR_RETRY_LATER            = 9;

    /**
     * Indicates if the session has been loaded.
     */
    private static $loadedSession = false;

    /**
     * Returns the error message for the respective error code.
     * @param {int} code - Error code.
     * @returns {string}
     */
    public static function errorString ($code) : string
    {
        switch ($code) {
            case Sentinel::ERR_AUTHORIZATION_BLOCKED:
                return Strings::get('@messages.authorization_blocked');
            case Sentinel::ERR_INVALID_CREDENTIALS:
                return Strings::get('@messages.invalid_credentials');
            case Sentinel::ERR_AUTH_BEARER_DISABLED:
                return Strings::get('@messages.authorization_bearer_not_supported');
            case Sentinel::ERR_AUTH_BASIC_DISABLED:
                return Strings::get('@messages.authorization_basic_not_supported');
            case Sentinel::ERR_AUTH_REQUIRED:
                return Strings::get('@messages.authentication_required');
            case Sentinel::ERR_PERMISSION_REQUIRED:
                return Strings::get('@messages.required_permission_not_fulfilled');
            case Sentinel::ERR_LEVEL_REQUIRED:
                return Strings::get('@messages.required_permission_level_not_fulfilled');
            case Sentinel::ERR_AUTHORIZATION_BANNED:
                return Strings::get('@messages.authorization_banned');
            case Sentinel::ERR_RETRY_LATER:
                return Strings::get('@messages.retry_later');
        }

        return '';
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
     * Returns the permissions of the current user (or token permissions if `token_permissions` is enabled).
     * @returns {string[]}
     */
    private static function getPermissions()
    {
        $conn = Resources::getInstance()->Database;
        if (!Sentinel::status()) return new Arry();

        $conf = Configuration::getInstance()->Sentinel;
        if ($conf && $conf->token_permissions === 'true' && Session::$data->user->token_id) {
            return $conn->execQuery(
                'SELECT DISTINCT p.permission_id, p.name FROM ##permissions p '.
                'INNER JOIN ##token_permissions t ON t.permission_id = p.permission_id '.
                'WHERE t.token_id = '.Session::$data->user->token_id
            );
        }

        return $conn->execQuery(
            'SELECT DISTINCT p.permission_id, p.name FROM ##permissions p '.
            'INNER JOIN ##user_permissions u ON u.permission_id = p.permission_id '.
            'WHERE u.user_id = '.Session::$data->user->user_id
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
        if (Text::startsWith($tmp, 'BEARER')) {
            $code = self::authorize(Text::substring($auth, 7), false);
            if ($code !== Sentinel::ERR_NONE)
                Wind::reply([ 'response' => Wind::R_VALIDATION_ERROR, 'error' => Sentinel::errorString($code) ]);
        }
        else if (Text::startsWith($tmp, 'BASIC'))
        {
            if ($conf && $conf->auth_basic !== 'true')
                Wind::reply([ 'response' => Wind::R_VALIDATION_ERROR, 'error' => Sentinel::errorString(Sentinel::ERR_AUTH_BASIC_DISABLED) ]);

            $auth = base64_decode(Text::substring($auth, 6));
            $i = strpos($auth, ':');
            if ($i == -1) {
                Gateway::header('HTTP/1.1 401 Not Authenticated');
                Gateway::header('WWW-Authenticate: Basic');
                Wind::reply([ 'response' => Wind::R_VALIDATION_ERROR, 'error' => Sentinel::errorString(Sentinel::ERR_INVALID_CREDENTIALS) ]);
            }

            $username = Text::substring($auth, 0, $i);
            $password = Text::substring($auth, $i+1);
            $code = self::login($username, $password, false, true);
            if ($code != Sentinel::ERR_NONE) {
                Gateway::header('HTTP/1.1 401 Not Authenticated');
                Gateway::header('WWW-Authenticate: Basic');
                Wind::reply([ 'response' => Wind::R_VALIDATION_ERROR, 'error' => Sentinel::errorString($code) ]);
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
        if ($conf && $conf->auth_bearer !== 'true')
            return Sentinel::ERR_AUTH_BEARER_DISABLED;

        $data = Resources::getInstance()->Database->execAssoc(
            'SELECT u.*, t.token_id, COALESCE(u.blocked_at, t.blocked_at) blocked_at '.
            'FROM ##users u '.
            'INNER JOIN ##tokens t ON t.deleted_at IS NULL AND t.user_id = u.user_id '.
            'WHERE u.deleted_at IS NULL AND t.token = '.Connection::escape($token)
        );
        if (!$data) return Sentinel::ERR_INVALID_CREDENTIALS;

        if ($data->blocked_at)
            return Sentinel::ERR_AUTHORIZATION_BLOCKED;

        self::$loadedSession = true;
        if ($openSession) Session::open(true);

        Session::$data->user = $data;
        $list = Sentinel::getPermissions();
        $data->permissions = $list->map(function($i) { return $i->name; });
        $data->permission_ids = $list->map(function($i) { return $i->permission_id; });
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
                    'SELECT u.*, t.token_id, COALESCE(u.blocked_at, t.blocked_at) blocked_at '.
                    'FROM ##users u '.
                    'INNER JOIN ##tokens t ON t.blocked_at IS NULL AND t.user_id = u.user_id '.
                    'WHERE u.deleted_at IS NULL AND t.token = '.Connection::escape($password)
                );
            } else {
                $data = Resources::getInstance()->Database->execAssoc (
                    'SELECT * FROM ##users '.
                    'WHERE deleted_at IS NULL AND username = '.Connection::escape($username).' AND password = '.Sentinel::password($password, true)
                );
            }
        } else {
            $data = Resources::getInstance()->Database->execAssoc (
                'SELECT * FROM ##users WHERE deleted_at IS NULL AND user_id = '.Connection::escape($username)
            );
        }

        if (!$data) return Sentinel::ERR_INVALID_CREDENTIALS;

        if ($data->blocked_at)
            return Sentinel::ERR_AUTHORIZATION_BLOCKED;

        self::$loadedSession = true;
        if ($openSession) Session::open(true);

        Session::$data->user = $data;
        $list = Sentinel::getPermissions();
        $data->permissions = $list->map(function($i) { return $i->name; });
        $data->permission_ids = $list->map(function($i) { return $i->permission_id; });
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
        $data->permissions = $data->has('permissions') ? $data->get('permissions') : new Arry();
        $data->permission_ids = $data->has('permission_ids') ? $data->get('permission_ids') : new Arry();
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
            'SELECT * FROM ##users WHERE deleted_at IS NULL AND username = '.Connection::escape($username).' AND password = '.Sentinel::password($password, true)
        );
        if (!$data) return Sentinel::ERR_INVALID_CREDENTIALS;

        if ($data->blocked_at)
            return Sentinel::ERR_AUTHORIZATION_BLOCKED;

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
                'SELECT u.*, t.token_id, COALESCE(u.blocked_at, t.blocked_at) blocked_at '.
                'FROM ##users u '.
                'INNER JOIN ##tokens t ON t.blocked_at IS NULL AND t.user_id = u.user_id '.
                'WHERE u.deleted_at IS NULL AND t.token_id = '.Connection::escape(Session::$data->user->token_id)
            );
        } else {
            $data = Resources::getInstance()->Database->execAssoc (
                'SELECT * FROM ##users WHERE deleted_at IS NULL AND user_id = '.Connection::escape(Session::$data->user->user_id)
            );
        }

        if (!$data) return;

        Session::$data->user = $data;
        $list = Sentinel::getPermissions();
        $data->permissions = $list->map(function($i) { return $i->name; });
        $data->permission_ids = $list->map(function($i) { return $i->permission_id; });
    }

    /**
     * Checks if the current user has one or more permissions.
     * @param {string} $permission - Permissions separated by comma.
     * @param {string}null} $username - Username to check, if `null` the current user will be used.
     * @returns {bool}
     */
    public static function hasPermission ($permission, $username=null)
    {
        if (!$permission) return true;

        $conf = Configuration::getInstance()->Sentinel;
        $conn = Resources::getInstance()->Database;

        $permission = Text::split(',', ($conf && $conf->master === 'true' ? 'master,' : '').$permission)->map(function($i) { return Connection::escape($i); })->join(',');
        $count = 0;

        if ($username !== null) {
            $count = $conn->execScalar (
                ' SELECT COUNT(*) FROM ##permissions p '.
                ' INNER JOIN ##user_permissions up ON up.permission_id = p.permission_id'.
                ' INNER JOIN ##users u ON u.deleted_at IS NULL AND u.username = '.Connection::escape($username).' AND up.user_id = u.user_id'.
                ' WHERE p.name IN ('.$permission.')'
            );
            return $count != 0 ? true : false;
        }

        if (!Sentinel::status()) return false;

        if ($conf && $conf->token_permissions === 'true' && Session::$data->user->token_id) {
            $count = $conn->execScalar (
                ' SELECT COUNT(*) FROM ##permissions p '.
                ' INNER JOIN ##token_permissions tp ON tp.permission_id = p.permission_id'.
                ' WHERE tp.token_id = '.Session::$data->user->token_id.' AND p.name IN ('.$permission.')'
            );
        }
        else {
            $count = $conn->execScalar (
                ' SELECT COUNT(*) FROM ##permissions p '.
                ' INNER JOIN ##user_permissions up ON up.permission_id = p.permission_id'.
                ' WHERE up.user_id = '.Session::$data->user->user_id.' AND p.name IN ('.$permission.')'
            );
        }

        return $count != 0 ? true : false;
    }

    /**
     * Checks if the current user has at least one permission group.
     * @param {string} $value - Permission sets separated by pipe, AND-groups separated by ampersand (&).
     * @param {string|null} $username - Username to check, if `null` the current user will be used.
     * @returns {bool}
     */
    public static function verifyPermissions ($value, $username=null)
    {
        if (!$username && !Sentinel::status())
            return false;

        $groups = Text::split('|', Text::trim($value ? $value : ''));
        foreach ($groups->__nativeArray as $group)
        {
            $groupFailed = false;
            foreach (Text::split('&', Text::trim($group))->__nativeArray as $permission)
            {
                if (!Sentinel::hasPermission (Text::trim($permission), $username)) {
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
                ' SELECT COUNT(*) FROM ##permissions p '.
                ' INNER JOIN ##user_permissions up ON up.permission_id = p.permission_id'.
                ' INNER JOIN ##users u ON u.deleted_at IS NULL AND u.username='.Connection::escape($username).' AND up.user_id = u.user_id'.
                ' WHERE FLOOR(p.permission_id/100) >= '.$level
            );
            return $count != 0 ? true : false;
        }

        if (!Sentinel::status()) return false;

        if ($conf && $conf->token_permissions === 'true' && Session::$data->user->token_id) {
            $count = $conn->execScalar (
                ' SELECT COUNT(*) FROM ##permissions p '.
                ' INNER JOIN ##token_permissions tp ON tp.permission_id = p.permission_id'.
                ' WHERE tp.token_id = '.Session::$data->user->token_id.' AND FLOOR(p.permission_id/100) >= '.$level
            );
        }
        else {
            $count = $conn->execScalar (
                ' SELECT COUNT(*) FROM ##permissions p '.
                ' INNER JOIN ##user_permissions up ON up.permission_id = p.permission_id'.
                ' WHERE up.user_id = '.Session::$data->user->user_id.' AND FLOOR(p.permission_id/100) >= '.$level
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
                ' SELECT MAX(FLOOR(p.permission_id/100)) FROM ##permissions p '.
                ' INNER JOIN ##user_permissions up ON up.permission_id = p.permission_id'.
                ' INNER JOIN ##users u ON u.deleted_at IS NULL AND u.username = '.Connection::escape($username).' AND up.user_id = u.user_id'
            );
            return (int)$level;
        }
        
        if (!Sentinel::status()) return 0;

        if ($conf && $conf->token_permissions === 'true' && Session::$data->user->token_id) {
            $level = $conn->execScalar (
                ' SELECT MAX(FLOOR(p.permission_id/100)) FROM ##permissions p '.
                ' INNER JOIN ##token_permissions tp ON tp.permission_id = p.permission_id'.
                ' WHERE tp.token_id = '.Session::$data->user->token_id
            );
        }
        else {
            $level = $conn->execScalar (
                ' SELECT MAX(FLOOR(p.permission_id/100)) FROM ##permissions p '.
                ' INNER JOIN ##user_permissions up ON up.permission_id = p.permission_id'.
                ' WHERE up.user_id = '.Session::$data->user->user_id
            );
        }

        return (int)$level;
    }
};

/* ****************************************************************************** */

/**
 * Calculates the hash of the given password and returns it. The plain password gets the `suffix` and `prefix` configuration fields
 * appended and prepended respectively before calculating its hash. The hash algorithm is set by the `hash` configuration field.
 * @code (`sentinel:password` <password>)
 */
Expr::register('sentinel:password', function($args) {
    return Sentinel::password($args->get(1));
});


/**
 * Returns the authentication status (boolean) of the active session.
 * @code (`sentinel:status`)
 */
Expr::register('sentinel:status', function($args) {
    return Sentinel::status();
});


/**
 * Fails with error code `401` if the active session is not authenticated.
 * @code (`sentinel:auth-required`)
 */
Expr::register('sentinel:auth-required', function($args)
{
    $conf = Configuration::getInstance()->Sentinel;
    if (Sentinel::status()) return null;

    if ($conf && $conf->auth_basic === 'true') {
        Gateway::header('HTTP/1.1 401 Not Authenticated');
        Gateway::header('WWW-Authenticate: Basic');
    }

    Wind::reply([ 'response' => Wind::R_UNAUTHORIZED, 'error' => Sentinel::errorString(Sentinel::ERR_AUTH_REQUIRED) ]);
    return null;
});


/**
 * Verifies if the active session has the specified permissions. Fails with `401` if the session has not been authenticated, or with
 * `403` if the permission requirements are not met. The permissions string contains the permission names OR-sets separated by pipe (|),
 * and the AND-sets separated by ampersand (&).
 * @code (`sentinel:permission-required` <permissions>)
 * @example
 * (sentinel:permission-required "admin | provider & enabled | customer")
 * ; false
 */
Expr::register('sentinel:permission-required', function($args)
{
    $conf = Configuration::getInstance()->Sentinel;
    if (Sentinel::verifyPermissions($args->get(1)))
        return null;

    if (Sentinel::status())
        Wind::reply([ 'response' => Wind::R_FORBIDDEN, 'error' => Sentinel::errorString(Sentinel::ERR_PERMISSION_REQUIRED) ]);

    if ($conf && $conf->auth_basic === 'true') {
        Gateway::header('HTTP/1.1 401 Not Authenticated');
        Gateway::header('WWW-Authenticate: Basic');
    }

    Wind::reply([ 'response' => Wind::R_UNAUTHORIZED, 'error' => Sentinel::errorString(Sentinel::ERR_AUTH_REQUIRED) ]);
    return null;
});


/**
 * Verifies if the active session has the specified permissions. Returns boolean. The permissions string contains the permission
 * name sets (see `sentinel:permission-required`).
 * @code (`sentinel:has-permission` <permissions>)
 */
Expr::register('sentinel:has-permission', function($args) {
    return Sentinel::verifyPermissions($args->get(1), $args->{2});
});


/**
 * Checks the permissions of the active user against one of the case values. Returns the respective result or the default result if
 * none matches. If no default result is specified an empty string will be returned. Note that each case result should be a value
 * not a block. Each case string is a permission name set (see `sentinel:permission-required`).
 *
 * @code (`sentinel:case` <case1> <result1> ... [default <default>])
 * @example
 * (sentinel:case
 *     "admin"      "Has permission admin"
 *     "client"     "Has permission client"
 *     "x | y"      "Has permission x or y"
 *     "a & b & c"  "Has permission a, b and c"
 * )
 */
Expr::register('_sentinel:case', function($parts, $data)
{
    $n = $parts->length();
    for ($i = 1; $i < $n; $i += 2)
    {
        $case_value = (string)Expr::expand($parts->get($i), $data, 'arg');
        if ($i == $n-1 && !($n&1)) return $case_value;

        if (Sentinel::verifyPermissions($case_value) || $case_value === 'default')
            return Expr::expand($parts->get($i+1), $data, 'arg');
    }

    return '';
});


/**
 * Verifies if the active user meets the specified minimum permission level. The level is the permission_id divided by 100. Fails with `401` 
 * if the user has not been authenticated, or with `403` if the permission level requirements are not met.
 * @code (`sentinel:level-required` <level>)
 */
Expr::register('sentinel:level-required', function($args)
{
    $conf = Configuration::getInstance()->Sentinel;
    if (Sentinel::hasLevel($args->get(1))) return null;

    if (Sentinel::status())
        Wind::reply([ 'response' => Wind::R_FORBIDDEN, 'error' => Sentinel::errorString(Sentinel::ERR_LEVEL_REQUIRED) ]);

    if ($conf && $conf->auth_basic === 'true') {
        Gateway::header('HTTP/1.1 401 Not Authenticated');
        Gateway::header('WWW-Authenticate: Basic');
    }

    Wind::reply([ 'response' => Wind::R_UNAUTHORIZED, 'error' => Sentinel::errorString(Sentinel::ERR_AUTH_REQUIRED) ]);
    return null;
});


/**
 * Verifies if the active user meets the specified minimum permission level. The level is the permission_id divided by 100. Returns boolean.
 * @code (`sentinel:has-level` <level>)
 * @example
 * (sentinel:has-level 7)
 * ; true
 */
Expr::register('sentinel:has-level', function($args) {
    return Sentinel::hasLevel($args->get(1));
});


/**
 * Returns the permission level of the active session user, or of the given user if `username` is provided.
 * @code (`sentinel:get-level` [username])
 * @example
 * (sentinel:get-level "admin")
 * ; 7
 */
Expr::register('sentinel:get-level', function($args) {
    return Sentinel::getLevel($args->has(1) ? $args->get(1) : null);
});


/**
 * Verifies if the given credentials are valid, returns boolean.
 * @code (`sentinel:validate` <username> <password>)
 * @example
 * (sentinel:validate "admin" "admin")
 * ; true
 */
Expr::register('sentinel:validate', function($args) {
    return Sentinel::valid($args->get(1), $args->get(2)) === Sentinel::ERR_NONE;
});


/**
 * Verifies if the given credentials are valid, fails with `422` and sets the `error` field accordingly. When successful, opens a session
 * and loads the `user` field with the data of the user that has been authenticated.
 *
 * Note that Sentinel will automatically run the login process (without creating a session) if the `Authorization: BASIC data` header is detected 
 * and the `auth_basic` flag is enabled in the configuration.
 *
 * When using Apache, the `HTTP_AUTHORIZATION` header is not sent to the application, however by setting the following in your `.htaccess` it 
 * will be available for Sentinel to use it.
 *
 * ```SetEnvIf Authorization "(.*)" HTTP_AUTHORIZATION=$1```
 * @code (`sentinel:login` <username> <password>)
 */
Expr::register('sentinel:login', function($args)
{
    $code = Sentinel::login ($args->get(1), $args->get(2));
    if ($code != Sentinel::ERR_NONE)
        Wind::reply([ 'response' => Wind::R_VALIDATION_ERROR, 'error' => Sentinel::errorString($code) ]);
    return null;
});


/**
 * Checks if the `auth_bearer` flag is set to `true` in the Sentinel configuration and then verifies the validity of the token
 * and authorizes access. On errors return status code `422` and sets the `error` field accordingly.
 *
 * When successful, opens a session only if the `persistent` flag is set to `true`, and loads the `user` field of the session
 * with the data of the user related to the token that was just authorized.
 * 
 * Note that Sentinel will automatically run the authorization process (without creating a session) if the `Authorization: BEARER token`
 * header is detected while `auth_bearer` is enabled in the configuration.
 * 
 * @code (`sentinel:authorize` <token> [persistent=false])
 */
Expr::register('sentinel:authorize', function($args)
{
    if ($args->has(2))
        $code = Sentinel::authorize ($args->get(1), \Rose\bool($args->get(2)));
    else
        $code = Sentinel::authorize ($args->get(1), false);

    if ($code != Sentinel::ERR_NONE)
        Wind::reply([ 'response' => Wind::R_VALIDATION_ERROR, 'error' => Sentinel::errorString($code) ]);

    return null;
});


/**
 * Returns the `token_id` of the active session or `null` if the user is either not authenticated yet or the user
 * authenticated by other means without a token (i.e. regular login).
 * @code (`sentinel:token-id`)
 * @example
 * (sentinel:token-id)
 * ; 13
 */
Expr::register('sentinel:token-id', function($args) {
    $user = Session::$data->user;
    return !$user ? null : $user->token_id;
});


/**
 * Starts a session and loads the specified data object into the `user` session field, effectively creating (manually) an
 * authenticated session. If the data being placed in the session does not actually exist in the database, ensure to use only
 * the `sentinel:auth-required` and `sentinel:logout` functions in your API, all others that query the database will fail.
 * @code (`sentinel:login-manual` <data>)
 * @example
 * (sentinel:login-manual { user_id 1 permissions ["admin"] })
 */
Expr::register('sentinel:login-manual', function($args) {
    Sentinel::manual ($args->get(1));
    return null;
});


/**
 * Verifies if the user exist and forces a login **without** any password. Fails with `422` and sets the `error` field
 * accordingly. When successful, opens a session and loads the `user` field of the session with the data of the user
 * that was just authenticated.
 * @code (`sentinel:login-user` <user_id>)
 * @example
 * (sentinel:login-user 1)
 */
Expr::register('sentinel:login-user', function($args) {
    $code = Sentinel::login ($args->get(1), null, true, false);
    if ($code != Sentinel::ERR_NONE)
        Wind::reply([ 'response' => Wind::R_VALIDATION_ERROR, 'error' => Sentinel::errorString($code) ]);
    return null;
});


/**
 * Removes authentication status from the active session. Note that this function does not remove the session itself, only
 * the authentication data related to the user. Use `session:destroy` afterwards to fully remove the session completely.
 * @code (`sentinel:logout`)
 */
Expr::register('sentinel:logout', function($args) {
    Sentinel::logout();
    return null;
});


/**
 * Reloads the active user's session data and permissions from the database. Do not call this function if you logged in in a
 * manual way using `sentinel:login-manual` because the user's data you placed will be overwritten.
 * @code (`sentinel:reload`)
 */
Expr::register('sentinel:reload', function($args) {
    Sentinel::reload();
    return null;
});


/**
 * Ensures the provided identifier is not either banned or blocked. Fails with status code `409` and with the default
 * error message if the `message` parameter is not provided.
 * @code (`sentinel:access-required` <identifier> [message])
 * @example
 * (sentinel:access-required "127.0.0.1" "Your IP has been blocked.")
 * ; If identifier `127.0.0.1` is blocked:
 * ; {"response":409, "error":"@messages.retry_later (60s)", "retry_at":"2024-11-21 11:20:00", "wait":60}
 *
 * (sentinel:access-required "127.0.0.1" "Your IP has been blocked.")
 * ; If identifier `127.0.0.1` is banned:
 * ; {"response":409, "error":"Your IP has been blocked."}
 */
Expr::register('sentinel:access-required', function($args)
{
    $conn = Resources::getInstance()->Database;
    $identifier = $args->get(1);

    $data = $conn->execAssoc('SELECT * FROM ##suspicious_identifiers WHERE identifier='.Connection::escape($identifier));
    if (!$data) return null;

    if ($data->is_banned) {
        Wind::reply([ 
            'response' => Wind::R_CUSTOM_ERROR, 
            'error' => $args->{2} ?? Sentinel::errorString(Sentinel::ERR_AUTHORIZATION_BANNED)
        ]);
    }

    $next_attempt_at = new DateTime($data->next_attempt_at);
    $delta = $next_attempt_at->sub(new DateTime());
    if ($delta > 0)
    {
        $str_delta = '';
        if ($delta > 3600) {
            $str_delta .= (int)($delta/3600) . 'h ';
            $delta = $delta % 3600;
        }

        if ($delta > 60) {
            $str_delta .= (int)($delta/60) . 'm ';
            $delta = $delta % 60;
        }

        if ($delta != 0)
            $str_delta .= $delta . 's';

        Wind::reply([ 
            'response' => Wind::R_CUSTOM_ERROR, 
            'error' => Sentinel::errorString(Sentinel::ERR_RETRY_LATER) . ' (' . Text::trim($str_delta) . ')', 
            'retry_at' => (string)$next_attempt_at,
            'wait' => $next_attempt_at->sub(new DateTime($data->last_attempt_at))
        ]);
    }

    return null;
});


/**
 * Registers an access-denied attempt for the specified identifier. Returns a string indicating the action taken for
 * the identifier, valid values are `auto`, `wait`, `block`, or `ban`.
 * @code (`sentinel:access-denied` <identifier> [action='auto'] [wait-timeout=2] [block-timeout=30])
 * @example
 * (sentinel:access-denied "127.0.0.1")
 * ; "wait"
 */
Expr::register('sentinel:access-denied', function($args)
{
    $conn = Resources::getInstance()->Database;
    $identifier = $args->get(1);

    $now = new DateTime();
    $next = new DateTime();
    $action = Text::toLowerCase($args->{2} ?? 'auto');
    $delay = (int)($args->{3} ?? '2');
    $long_delay = (int)($args->{4} ?? '30');

    $data = $conn->execAssoc('SELECT * FROM ##suspicious_identifiers WHERE identifier='.Connection::escape($identifier));
    if (!$data)
    {
        $data = new Map([
            'identifier' => $identifier,
            'next_attempt_at' => (string)($next->add($delay)),
            'last_attempt_at' => (string)($now),
            'count_failed' => $action === 'wait' || $action === 'auto' ? 1 : 0,
            'count_blocked' => $action === 'block' ? 1 : 0,
            'is_banned' => $action === 'ban' ? true : false
        ]);

        $conn->execQuery(
            'INSERT INTO ##suspicious_identifiers ('. 
                $data->keys()->map(function($i) use(&$conn) { return $conn->escapeName($i); })->join(', ') .
            ') VALUES (' . $conn->escapeExt($data->values())->join(', ') . ')'
        );

        return $action === 'auto' ? 'wait' : $action;
    }

    $data->last_attempt_at = (string)$now;
    $data->count_failed++;

    if ($data->count_failed >= 3 || $action === 'block') {
        $data->count_failed = 0;
        $data->count_blocked++;
        $delay = $long_delay * pow(2, min(8, $data->count_blocked-1));
        $action = 'block';
    }

    if (($data->count_blocked >= 3 && $action === 'auto') || $action === 'ban') {
        $data->is_banned = 1;
        $action = 'ban';
    }

    $data->next_attempt_at = (string)$next->add($delay);

    $conn->execQuery(
        'UPDATE ##suspicious_identifiers SET ' . $conn->escapeExt($data)->join(', ') .
        ' WHERE identifier='.Connection::escape($identifier)
    );

    return $action;
});


/**
 * Grants access to an identifier, calling this will reset the failed and blocked counters. A ban will **continue**
 * to be in effect unless the `unban` parameter is set to `true`.
 * @code (`sentinel:access-granted` <identifier> [unban=false])
 * @example
 * (sentinel:access-granted "127.0.0.1" true)
 * ; null
 */
Expr::register('sentinel:access-granted', function($args)
{
    $conn = Resources::getInstance()->Database;
    $identifier = $args->get(1);
    $unban = \Rose\bool($args->{2});

    $conn->execQuery(
        'UPDATE ##suspicious_identifiers SET count_failed=0, count_blocked=0' .
        ($unban ? ', is_banned=0' : '') .
        ' WHERE identifier='.Connection::escape($identifier)
    );

    return null;
});
