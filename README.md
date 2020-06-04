# Sentinel Authentication Extension

This extension adds user authentication features to [Wind](https://github.com/rsthn/rose-ext-wind).

> **NOTE:** The extension detects the presence of Wind, when not installed, this extension will simply not be loaded.

# Installation

```sh
composer require rsthn/rose-ext-sentinel
```


# Database Structure

The following tables are required by Sentinel. Note that any of the tables below can be extended if desired, the columns shown are the required minimum.

> **NOTE** : The `utf8mb4_bin` collation is required in `users` to make lowercase and uppercase distinction.

```sql
CREATE TABLE users
(
    user_id int unsigned primary key auto_increment,
    created datetime default null,

    is_authorized tinyint not null default 1,
    is_active tinyint not null default 1,

    username varchar(128) not null unique key collate utf8mb4_bin,
    password char(96) not null collate utf8mb4_bin
)
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci AUTO_INCREMENT=1;
```

```sql
CREATE TABLE privileges
(
    privilege_id int unsigned primary key auto_increment,

    name varchar(128) not null unique key,
    label varchar(512) not null default ''
)
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_bin AUTO_INCREMENT=1;
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
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
```

## Configuration Section: `Sentinel`


|Field|Type|Description|Default|
|----|----|-----------|-------|
|hash|`string`|Name of the hash algorithm to use (passed directly to PHP's `hash` function).|sha384
|prefix|`string`|Password prefix (salt).|Optional
|suffix|`string`|Password suffix (salt).|Optional
|master|`bool`|Indicates if privilege `'master'` should be added to all privilege checks.|`false`


## Expression Functions

### `sentinel::password` password:string

Calculates the hash of the given password and returns it. The plain password gets the `Sentinel.suffix` and `Sentinel.prefix` appended and prepended respectively before calculating its hash indicated by `Sentinel.hash`.

### `sentinel::status`

Returns the authentication status (boolean) of the active session.

### `sentinel::auth-required`

Fails with error code `Wind::R_NOT_AUTHENTICATED` if the active session is not authenticated.

### `sentinel::privilege-required` privileges:string

Verifies if the active session has the specified privileges. Fails with `Wind::R_NOT_AUTHENTICATED` if the session has not been authenticated, or with `Wind::R_PRIVILEGE_REQUIRED` if the privilege requirements are not met.

### `sentinel::has-privilege` privileges:string

Verifies if the active session has the specified privileges. Does not fail, instead returns `boolean` instead.

### `sentinel::valid` username:string password:string

Verifies if the specified credentials are valid, returns `boolean`.

### `sentinel::validate` username:string password:string

Verifies if the given credentials are valid, fails with `Wind::R_VALIDATION_ERROR` and sets the `error` field to `strings.@messages.err_authorization` or `strings.@messages.err_credentials`.

### `sentinel::login` username:string password:string

Verifies if the given credentials are valid, fails with `Wind::R_VALIDATION_ERROR` and sets the `error` field to `strings.@messages.err_authorization` or `strings.@messages.err_credentials`. When successful, opens a session and loads the `currentUser` field with the data of the user that has been authenticated.

### `sentinel::logout`

Removes authentication status from the active session.

### `sentinel::reload`

Reloads the active session data and privileges from the database.

- Added 'sentinel::validate' to ensure the specified credentials are valid, fails with Wind::reply.
- Added 'sentinel::valid' to verify if the specified credentials are valid, returns a boolean.
