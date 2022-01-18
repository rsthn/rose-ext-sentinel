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
	user_id int unsigned primary key auto_increment,
	created datetime default null,

	is_authorized tinyint not null default 1,
	is_active tinyint not null default 1,

	username varchar(128) not null,
	password varchar(96) not null
)
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci AUTO_INCREMENT=1;

ALTER TABLE users ADD index n_username (username);
ALTER TABLE users ADD index n_is_active (is_active);
```

```sql
CREATE TABLE privileges
(
	privilege_id int unsigned primary key auto_increment,
	name varchar(128) not null unique key
)
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci AUTO_INCREMENT=1;
```

```sql
CREATE TABLE user_privileges
(
	user_id int unsigned not null,
	privilege_id int unsigned not null,
	tag tinyint default 0,

	primary key (user_id, privilege_id),

	constraint foreign key (user_id) references users (user_id) on delete cascade,
	constraint foreign key (privilege_id) references privileges (privilege_id) on delete cascade
)
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
```

<br/>

And lastly, if authorization via access tokens is desired (by setting `authBearer` to true in the Sentinel configuration section), then add the following table to your database as well:

```sql
CREATE TABLE tokens
(
	token_id int unsigned primary key auto_increment,

	is_active tinyint not null default 1,
	created datetime not null,

	user_id int unsigned not null,
	constraint foreign key (user_id) references users (user_id) on delete cascade,

	is_authorized tinyint not null default 1,

	token varchar(128) not null unique,
	name varchar(128) default null
)
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci AUTO_INCREMENT=1;

ALTER TABLE tokens ADD index n_is_active (is_active);
```

<br/><br/>

# Configuration Section: "Sentinel"

|Field|Type|Description|Default|
|----|----|-----------|-------|
|hash|string|Name of the hash algorithm to use (passed directly to PHP's hash function).|sha384
|prefix|string|Password prefix (salt).|Optional
|suffix|string|Password suffix (salt).|Optional
|master|bool|Indicates if privilege "master" should be added to all privilege checks.|false
|authBearer|bool|When set to true, allows authentication via "Authorization: Bearer" header and enables the `sentinel::authorize` function.|false
|authBasic|bool|When set to true, allows authentication via "Authorization: Basic" header.|false

<br/><br/>

# Expression Functions

#### `sentinel::password` password:string

Calculates the hash of the given password and returns it. The plain password gets the `Sentinel.suffix` and `Sentinel.prefix` configuration properties appended and prepended respectively before calculating its hash indicated by `Sentinel.hash`.


#### `sentinel::status`

Returns the authentication status (boolean) of the active session.


#### `sentinel::auth-required`

Fails with error code `Wind::R_NOT_AUTHENTICATED` if the active session is not authenticated.


#### `sentinel::privilege-required` privileges:string

Verifies if the active session has the specified privileges. Fails with `Wind::R_NOT_AUTHENTICATED` if the session has not been authenticated, or with `Wind::R_PRIVILEGE_REQUIRED` if the privilege requirements are not met.


#### `sentinel::has-privilege` privileges:string

Verifies if the active session has the specified privileges. Does not fail, returns boolean instead.


#### `sentinel::level-required` level:int

Verifies if the active session meets the specified minimum privilege level. The level is the privilege_id divided by 100. Fails with `Wind::R_NOT_AUTHENTICATED` if the session has not been authenticated, or with `Wind::R_PRIVILEGE_REQUIRED` if the privilege requirements are not met.


#### `sentinel::has-level` level:int

Verifies if the active session meets the specified minimum privilege level. The level is the privilege_id divided by 100. Does not fail, returns boolean instead.


#### `sentinel::get-level` [username:string]

Returns the privilege level of the active session user, or of the given user if `username` is provided.


#### `sentinel::valid` username:string password:string

Verifies if the specified credentials are valid, returns boolean.


#### `sentinel::validate` username:string password:string

Verifies if the given credentials are valid, fails with `Wind::R_VALIDATION_ERROR` and sets the `error` field to "strings.@messages.err_authorization" or "strings.@messages.err_credentials".


#### `sentinel::login` username:string password:string

Verifies if the given credentials are valid, fails with `Wind::R_VALIDATION_ERROR` and sets the `error` field to "strings.@messages.err_authorization" or "strings.@messages.err_credentials". When successful, opens a session and loads the `user` field with the data of the user that has been authenticated.

Note that Sentinel will automatically run the login process (without creating a session) if the `Authorization: BASIC data` header is detected and the `authBasic` is enabled in the configuration.

When using Apache, the HTTP_AUTHORIZATION header is not sent to the application, however by setting the following in your `.htaccess` it will be available for Sentinel to use it.

```
SetEnvIf Authorization "(.*)" HTTP_AUTHORIZATION=$1
```


#### `sentinel::login:forced` user_id:int

Verifies if the user exist and forces a login without password. Fails with `Wind::R_VALIDATION_ERROR` and sets the `error` field to "strings.@messages.err_authorization" or "strings.@messages.err_credentials".

When successful, opens a session and loads the `user` field with the data of the user that has been authenticated.


#### `sentinel::login:manual` data:object

Initializes a session and loads the specified data object into the `user` session field, effectively creating (manually) an authenticated session. If the data does not exist in the database, use only the `auth-required` and `logout` functions for access control, all others will fail.


#### `sentinel::authorize` token:string [persistent:bool=false]

First checks that `authBearer` is set to true (enabled) in the Sentinel configuration, when disabled fails with `Wind::ERR_BEARER_DISABLED` and sets the `error` field to "strings.@messages.err_bearer_disabled".

After the initial check it verifies if the given token is valid and authorizes access. Fails with `Wind::R_VALIDATION_ERROR` and sets the `error` field to "strings.@messages.err_authorization".

When successful, opens a session (if persistent is set to true), and loads the `user` field with the data of the user related to the token that just was authorized.

Note that Sentinel will automatically run the authorization process (without creating a session) if the `Authorization: BEARER token` header is detected and `authBearer` is enabled in the configuration.


#### `sentinel::logout`

Removes authentication status from the active session.


#### `sentinel::reload`

Reloads the active session data and privileges from the database.

- Added 'sentinel::validate' to ensure the specified credentials are valid, fails with Wind::reply.
- Added 'sentinel::valid' to verify if the specified credentials are valid, returns a boolean.
