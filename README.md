# Sentinel Authentication Extension

This extension adds user authentication features to Wind.

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

    primary key (user_id, privilege_id),

    constraint foreign key (user_id) references users (user_id) on delete cascade,
    constraint foreign key (privilege_id) references privileges (privilege_id) on delete cascade
)
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
```



## Exposed Functions

### `sentinel::auth-required`

Fails with error code `Wind::R_NOT_AUTHENTICATED` if the active session is not authenticated.

### `sentinel::privilege-required` privileges:string

Verifies if the active session has the specified privileges. Fails with `Wind::R_NOT_AUTHENTICATED` if the session has not been authenticated, or with `Wind::R_PRIVILEGE_REQUIRED` if the privilege requirements are not met.

### `sentinel::password` password:string

Calculates the hash of the given password and returns it.

### `sentinel::status`

Returns the authentication status (boolean) of the active session.

### `sentinel::login` username:string password:string

Authenticates the active session with the specified credentials, fails if the data is incorrect by returning `Wind::R_VALIDATION_ERROR`.

### `sentinel::logout`

Removes authentication status from the active session.

### `sentinel::reload`

Reloads the active session data and privileges from the database.
