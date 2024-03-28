# Sentinel Authentication Extension

This extension adds user authentication features to [Rose](https://github.com/rsthn/rose-core).

```sh
composer require rsthn/rose-ext-sentinel
```

<br/>

# Database Structure

The following tables are required by Sentinel. Note that any of the tables below can be extended if desired, the columns shown are the required minimum.

```sql
CREATE TABLE users
(
    user_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    created_at DATETIME NOT NULL,
    deleted_at DATETIME DEFAULT NULL,
    blocked_at DATETIME DEFAULT NULL,
    username VARCHAR(256) NOT NULL,
    password VARCHAR(96) NOT NULL
)
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8_unicode_ci AUTO_INCREMENT=1;

CREATE INDEX users_created_at ON users (created_at);
CREATE INDEX users_deleted_at ON users (deleted_at);
CREATE INDEX users_blocked_at ON users (blocked_at);
CREATE INDEX users_username ON users (username, deleted_at);
```

```sql
CREATE TABLE privileges
(
    privilege_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(128) NOT NULL UNIQUE
)
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8_unicode_ci;
```

```sql
CREATE TABLE user_privileges
(
    user_id INT NOT NULL,
    privilege_id INT NOT NULL,
    flag INT DEFAULT 0,
    PRIMARY KEY (user_id, privilege_id),
    FOREIGN KEY (user_id) REFERENCES users (user_id),
    FOREIGN KEY (privilege_id) REFERENCES privileges (privilege_id)
)
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8_unicode_ci;

CREATE INDEX user_privileges_flag ON user_privileges (user_id, flag);
```

### Token Authorization

Whenever authorization via access tokens is desired (by setting `authBearer` to true in the Sentinel configuration section), then add the following tables to your database as well:

```sql
CREATE TABLE tokens
(
    token_id INT PRIMARY KEY AUTO_INCREMENT,
    created_at DATETIME NOT NULL,
    deleted_at DATETIME DEFAULT NULL,
    blocked_at DATETIME DEFAULT NULL,
    user_id INT NOT NULL,
    token VARCHAR(128) NOT NULL UNIQUE,
    name VARCHAR(128) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (user_id)
)
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8_unicode_ci AUTO_INCREMENT=1;

CREATE INDEX tokens_user_id ON tokens (user_id, deleted_at);
CREATE INDEX tokens_token ON tokens (token, deleted_at);
```

```sql
CREATE TABLE token_privileges
(
    token_id INT NOT NULL,
    privilege_id INT NOT NULL,
    flag INT DEFAULT 0,
    PRIMARY KEY (token_id, privilege_id),
    FOREIGN KEY (token_id) REFERENCES tokens (token_id),
    FOREIGN KEY (privilege_id) REFERENCES privileges (privilege_id)
)
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8_unicode_ci;

CREATE INDEX token_privileges_flag ON token_privileges (token_id, flag);
```

### Identifier Banning

Sentinel include support to blacklist identifiers that are trying to brute force the system. To use this feature check the `sentinel::access-required` and `sentinel::access-denied` functions.

The following table is required for this feature:

```sql
CREATE TABLE suspicious_identifiers
(
    identifier VARCHAR(128) NOT NULL,
    PRIMARY KEY (identifier),
    next_attempt_at DATETIME DEFAULT NULL,
    last_attempt_at DATETIME NOT NULL,
    count_failed INT DEFAULT 1,
    count_blocked INT DEFAULT 0,
    is_banned INT DEFAULT 0
)
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8_unicode_ci AUTO_INCREMENT=1;
```

<br/><br/>

# Configuration Section: "Sentinel"

|Field|Type|Description|Default|
|----|----|-----------|-------|
|hash|string|Name of the hash algorithm to use (passed directly to PHP's hash function).|sha384
|prefix|string|Password prefix (salt).|-
|suffix|string|Password suffix (salt).|-
|master|bool|Indicates if privilege `master` should be added to all privilege checks.|false
|authBearer|bool|When set to `true`, allows authentication via "Authorization: Bearer" header and enables the `sentinel::authorize` function.|false
|authBasic|bool|When set to `true`, allows authentication via "Authorization: Basic" header and automatically sends `WWW-Authenticate` header along with HTTP status 401 when authentication has not been completed.|false
|tokenPrivileges|bool|When set to `true`, privileges will be loaded from the `token_privileges` table (instead of `user_privileges`) when the user authenticates using a token.|false

<br/><br/>

# Expression Functions

## `sentinel::password` \<password: _string_\>

Calculates the hash of the given password and returns it. The plain password gets the `Sentinel.suffix` and `Sentinel.prefix` configuration properties appended and prepended respectively before calculating its hash indicated by `Sentinel.hash`.


<br/>

## `sentinel::status`

Returns the authentication status (boolean) of the active session.


<br/>

## `sentinel::auth-required`

Fails with error code `Wind::R_NOT_AUTHENTICATED` if the active session is not authenticated.


<br/>

## `sentinel::privilege-required` \<privileges: _string_\>

Verifies if the active session has the specified privileges. Fails with `Wind::R_NOT_AUTHENTICATED` if the session has not been authenticated, or with `Wind::R_PRIVILEGE_REQUIRED` if the privilege requirements are not met.


<br/>

## `sentinel::has-privilege` \<privileges: _string_\>

Verifies if the active session has the specified privileges. Does not fail, returns boolean instead.

<br/>

## `sentinel::case` [<privileges: _string_> \<result: _any_> ...] [\<default-result>]
Checks the privileges of the current user against one of the case values. Returns the respective result or the default result if none matches. If no default result is specified, empty string is returned.

Note: This is meant for values, not blocks. Just like the standard `case` in Violet.
```lisp
(sentinel::case
    "admin"      "Has privileges admin"
    "client"     "Has privileges client"
    "x, y"       "Has privileges x or y"
    "a & b & c"  "Has privileges a, b and c"
)
```

<br/>

## `sentinel::level-required` \<level: _int_\>

Verifies if the active session meets the specified minimum privilege level. The level is the privilege_id divided by 100. Fails with `Wind::R_NOT_AUTHENTICATED` if the session has not been authenticated, or with `Wind::R_PRIVILEGE_REQUIRED` if the privilege requirements are not met.


<br/>

## `sentinel::has-level` \<level: _int_\>

Verifies if the active session meets the specified minimum privilege level. The level is the privilege_id divided by 100. Does not fail, returns boolean instead.


<br/>

## `sentinel::get-level` [username: _string_]

Returns the privilege level of the active session user, or of the given user if `username` is provided.


<br/>

## `sentinel::valid` \<username: _string_\> \<password: _string_\>

Verifies if the specified credentials are valid, returns boolean.


<br/>

## `sentinel::validate` \<username: _string_\> \<password: _string_\>

Verifies if the given credentials are valid, fails with `Wind::R_VALIDATION_ERROR` and sets the `error` field to "strings.@messages.err_authorization" or "strings.@messages.err_credentials".


<br/>

## `sentinel::login` \<username: _string_\> \<password: _string_\>

Verifies if the given credentials are valid, fails with `Wind::R_VALIDATION_ERROR` and sets the `error` field to "strings.@messages.err_authorization" or "strings.@messages.err_credentials". When successful, opens a session and loads the `user` field with the data of the user that has been authenticated.

Note that Sentinel will automatically run the login process (without creating a session) if the `Authorization: BASIC data` header is detected and the `authBasic` is enabled in the configuration.

When using Apache, the HTTP_AUTHORIZATION header is not sent to the application, however by setting the following in your `.htaccess` it will be available for Sentinel to use it.

```
SetEnvIf Authorization "(.*)" HTTP_AUTHORIZATION=$1
```


<br/>

## `sentinel::token-id`

Returns the `token_id` of the active session or `null` if the user is not authenticated or if the user authenticated by other means without a token.


<br/>

## `sentinel::login-user` \<user_id: _int_\>

Verifies if the user exist and forces a login without password. Fails with `Wind::R_VALIDATION_ERROR` and sets the `error` field to "strings.@messages.err_authorization" or "strings.@messages.err_credentials".

When successful, opens a session and loads the `user` field with the data of the user that has been authenticated.


<br/>

## `sentinel::login-manual` \<data: _object_\>

Initializes a session and loads the specified data object into the `user` session field, effectively creating (manually) an authenticated session. If the data does not exist in the database, use only the `auth-required` and `logout` functions for access control, all others will fail.


<br/>

## `sentinel::authorize` \<token: _string_\> [persistent: _bool_]

First checks that `authBearer` is set to true (enabled) in the Sentinel configuration, when disabled fails with `Wind::ERR_BEARER_DISABLED` and sets the `error` field to "strings.@messages.err_bearer_disabled".

After the initial check it verifies if the given token is valid and authorizes access. Fails with `Wind::R_VALIDATION_ERROR` and sets the `error` field to "strings.@messages.err_authorization".

When successful, opens a session if `persistent` is set to `true`, and loads the `user` field with the data of the user related to the token that just was authorized.

Note that Sentinel will automatically run the authorization process (without creating a session) if the `Authorization: BEARER token` header is detected and `authBearer` is enabled in the configuration.


<br/>

## `sentinel::logout`

Removes authentication status from the active session. Note that this function does not remove the session itself, only the authentication data of the user. Use `session::destroy` to remove the session completely.


<br/>

## `sentinel::reload`

Reloads the active session data and privileges from the database.
