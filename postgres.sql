--------------------------------------------------------------------------------
CREATE TABLE users
(
    user_id INT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY
    , created_at TIMESTAMP
    , deleted_at TIMESTAMP
    , blocked_at TIMESTAMP
    , name VARCHAR(96) NOT NULL
    , phone_number VARCHAR(32) NOT NULL
    , photo_path VARCHAR(128)
);
CREATE INDEX users_created_at ON users (created_at);
CREATE INDEX users_deleted_at ON users (deleted_at);
CREATE INDEX users_blocked_at ON users (blocked_at);
CREATE INDEX users_name ON users (deleted_at, name);
CREATE INDEX users_phone_number ON users (deleted_at, phone_number);

--------------------------------------------------------------------------------
CREATE TABLE permissions
(
    permission_id INT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY
    , deleted_at TIMESTAMP
    , name VARCHAR(128) NOT NULL UNIQUE
);

--------------------------------------------------------------------------------
CREATE TABLE user_permissions
(
    user_id INT NOT NULL REFERENCES users (user_id) ON DELETE CASCADE
    , permission_id INT NOT NULL REFERENCES permissions (permission_id) ON DELETE CASCADE
    , flag INT DEFAULT 0
    , PRIMARY KEY (user_id, permission_id)
);
CREATE INDEX user_permissions_flag ON user_permissions (user_id, flag);

--------------------------------------------------------------------------------
CREATE TABLE devices
(
    device_id VARCHAR(48) PRIMARY KEY
    , created_at TIMESTAMP
    , ipaddr VARCHAR(128)
    , user_id INT REFERENCES users (user_id) ON DELETE CASCADE
    , user_agent VARCHAR(128)
);

--------------------------------------------------------------------------------
CREATE TABLE tokens
(
    token_id INT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY
    , created_at TIMESTAMP NOT NULL
    , deleted_at TIMESTAMP
    , blocked_at TIMESTAMP
    , user_id INT NOT NULL
    , token VARCHAR(128) NOT NULL UNIQUE
    , name VARCHAR(128) NOT NULL
    , FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
);
CREATE INDEX tokens_user_id ON tokens (user_id, deleted_at);
CREATE INDEX tokens_token ON tokens (token, deleted_at);

--------------------------------------------------------------------------------
CREATE TABLE token_permissions
(
    token_id INT NOT NULL REFERENCES tokens (token_id) ON DELETE CASCADE
    , permission_id INT NOT NULL REFERENCES permissions (permission_id) ON DELETE CASCADE
    , flag INT DEFAULT 0
    , PRIMARY KEY (token_id, permission_id)
);
CREATE INDEX token_permissions_flag ON token_permissions (token_id, flag);

--------------------------------------------------------------------------------
CREATE TABLE sessions
(
    session_id VARCHAR(48) PRIMARY KEY
    , created_at TIMESTAMP
    , last_activity TIMESTAMP
    , device_id VARCHAR(48)
    , user_id INT REFERENCES users (user_id) ON DELETE CASCADE
    , data VARCHAR(8192)
);
CREATE INDEX sessions_device_id ON sessions (device_id);

--------------------------------------------------------------------------------
CREATE TABLE suspicious_identifiers
(
    identifier VARCHAR(512) NOT NULL PRIMARY KEY
    , next_attempt_at TIMESTAMP
    , last_attempt_at TIMESTAMP NOT NULL
    , count_failed INT DEFAULT 1
    , count_blocked INT DEFAULT 0
    , is_banned INT DEFAULT 0
);
