--------------------------------------------------------------------------------
CREATE TABLE users
(
    user_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    created_at DATETIME NOT NULL,
    deleted_at DATETIME DEFAULT NULL,
    blocked_at DATETIME DEFAULT NULL,
    username VARCHAR(256) NOT NULL,
    password VARCHAR(96) NOT NULL
)
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci AUTO_INCREMENT=1;
CREATE INDEX users_created_at ON users (created_at);
CREATE INDEX users_deleted_at ON users (deleted_at);
CREATE INDEX users_blocked_at ON users (blocked_at);
CREATE INDEX users_username ON users (username, deleted_at);

--------------------------------------------------------------------------------
CREATE TABLE permissions
(
    permission_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    deleted_at DATETIME DEFAULT NULL,
    name VARCHAR(128) NOT NULL UNIQUE
)
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--------------------------------------------------------------------------------
CREATE TABLE user_permissions
(
    user_id INT NOT NULL,
    permission_id INT NOT NULL,
    flag INT DEFAULT 0,
    PRIMARY KEY (user_id, permission_id),
    FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions (permission_id) ON DELETE CASCADE
)
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX user_permissions_flag ON user_permissions (user_id, flag);

--------------------------------------------------------------------------------
CREATE TABLE tokens
(
    token_id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    created_at DATETIME NOT NULL,
    deleted_at DATETIME DEFAULT NULL,
    blocked_at DATETIME DEFAULT NULL,
    user_id INT UNSIGNED NOT NULL,
    token VARCHAR(128) NOT NULL UNIQUE,
    name VARCHAR(128) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
)
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci AUTO_INCREMENT=1;
CREATE INDEX tokens_user_id ON tokens (user_id, deleted_at);
CREATE INDEX tokens_token ON tokens (token, deleted_at);

--------------------------------------------------------------------------------
CREATE TABLE token_permissions
(
    token_id INT NOT NULL,
    permission_id INT NOT NULL,
    flag INT DEFAULT 0,
    PRIMARY KEY (token_id, permission_id),
    FOREIGN KEY (token_id) REFERENCES tokens (token_id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions (permission_id) ON DELETE CASCADE
)
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX token_permissions_flag ON token_permissions (token_id, flag);

--------------------------------------------------------------------------------
CREATE TABLE sessions
(
    session_id VARCHAR(48) PRIMARY KEY,
    created_at DATETIME DEFAULT NULL,
    last_activity DATETIME DEFAULT NULL,
    device_id VARCHAR(48) DEFAULT NULL,
    user_id INT DEFAULT NULL,
    data VARCHAR(8192) DEFAULT NULL,
    FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
)
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci AUTO_INCREMENT=1;
CREATE INDEX sessions_device_id ON sessions (device_id);

--------------------------------------------------------------------------------
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
ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci AUTO_INCREMENT=1;
