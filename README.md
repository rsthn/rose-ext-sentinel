# Sentinel Authentication Extension

This extension adds user authentication features to [Rose](https://github.com/rsthn/rose-core).

```sh
composer require rsthn/rose-ext-sentinel
```

<br/>

# Database Structure

The following tables are required by Sentinel. Note that any of the tables below can be extended if desired, the columns shown are the required minimum.

```sql
CREATE TABLE ##users
(
    user_id int unsigned primary key auto_increment,
    created datetime default null,

    is_active tinyint not null default 1,
    index idx_is_active (is_active),

    is_authorized tinyint not null default 1,

    username varchar(256) not null,
    index idx_username (is_active, username),

    password varchar(96) not null
)
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci AUTO_INCREMENT=1;
```

```sql
CREATE TABLE ##privileges
(
    privilege_id int unsigned primary key,
    name varchar(128) not null unique key
)
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
```

```sql
CREATE TABLE ##user_privileges
(
    user_id int unsigned not null,
    foreign key (user_id) references ##users (user_id),

    privilege_id int unsigned not null,
    foreign key (privilege_id) references ##privileges (privilege_id),

    primary key (user_id, privilege_id),

    tag tinyint default 0,
    index idx_tag (user_id, tag)
)
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
```

<br/>

And lastly, if authorization via access tokens is desired (by setting `authBearer` to true in the Sentinel configuration section), then add the following tables to your database as well:

```sql
CREATE TABLE ##tokens
(
    token_id int unsigned primary key auto_increment,
    created datetime not null,

    is_active tinyint not null default 1,
    index idx_is_active (is_active),

    user_id int unsigned not null,
    foreign key (user_id) references ##users (user_id),
    index idx_username (is_active, user_id),

    is_authorized tinyint not null default 1,

    token varchar(128) not null unique,
    index idx_token (is_active, token),

    name varchar(128) not null
)
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci AUTO_INCREMENT=1;
```

```sql
CREATE TABLE ##token_privileges
(
    token_id int unsigned not null,
    foreign key (token_id) references ##tokens (token_id),

    privilege_id int unsigned not null,
    foreign key (privilege_id) references ##privileges (privilege_id),

    primary key (token_id, privilege_id),

    tag tinyint default 0,
    index idx_tag (token_id, tag)
)
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
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
