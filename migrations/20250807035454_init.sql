CREATE TABLE IF NOT EXISTS users (
    name TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    created_at INT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS transaction_ids (
    transaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL REFERENCES users ON DELETE CASCADE,
    committed INT
) STRICT;

CREATE TABLE IF NOT EXISTS items (
    id BLOB PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users,
    parent_id BLOB REFERENCES items ON DELETE CASCADE,
    path TEXT NOT NULL,
    type TEXT CHECK(type IN ('file', 'folder')) NOT NULL,
    deleted INT NOT NULL DEFAULT 0,
    created_at INT NOT NULL,
    transaction_id INT NOT NULL REFERENCES transaction_ids ON DELETE CASCADE
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS items_owner_path_undeleted ON items(owner_id, path) WHERE deleted = 0;

CREATE TABLE IF NOT EXISTS item_versions (
    version_id BLOB PRIMARY KEY,  
    item_id BLOB not NULL REFERENCES items ON DELETE CASCADE,
    version_number INT NOT NULL,
    created_at INT NOT NULL,
    size INT NOT NULL,
    hash BLOB NOT NULL,
    transaction_id INTEGER NOT NULL REFERENCES transaction_ids ON DELETE CASCADE,
    UNIQUE (item_id, version_number)
) STRICT;

CREATE TABLE IF NOT EXISTS chunks (
    hash BLOB PRIMARY KEY,
    size INT NOT NULL,
    refcount INT NOT NULL,
    data BLOB NOT NULL,
) STRICT;

CREATE TABLE IF NOT EXISTS version_chunks (
    version_id BLOB REFERENCES item_versions ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL,
    chunk_hash BLOB NOT NULL REFERENCES chunks,
    offset INTEGER NOT NULL,
    length INTEGER NOT NULL,
    end INTEGER NOT NULL AS (offset+length-1),
    transaction_id INTEGER NOT NULL REFERENCES transaction_ids ON DELETE CASCADE,
    PRIMARY KEY (version_id, chunk_index)
) STRICT;


CREATE VIEW newest_item_versions AS
SELECT iv.*
FROM item_versions iv
JOIN (
    SELECT item_id, MAX(version_number) AS max_version
    FROM item_versions
    GROUP BY item_id
) latest ON iv.item_id = latest.item_id AND iv.version_number = latest.max_version;


-- CREATE TABLE IF NOT EXISTS share_user (
--     id TEXT PRIMARY KEY,
--     item_id TEXT NOT NULL REFERENCES items ON DELETE CASCADE,
--     user_id TEXT NOT NULL REFERENCES users ON DELETE CASCADE,
--     access_level TEXT CHECK(access_level IN ('view', 'edit', 'coowner')),
--     shared_by TEXT NOT NULL REFERENCES users ON DELETE CASCADE,
--     created_at INT NOT NULL
-- ) STRICT;


CREATE INDEX IF NOT EXISTS idx_items_id_owner_type ON items(id, owner_id, type);
CREATE INDEX IF NOT EXISTS idx_items_owner_id ON items(owner_id);
CREATE INDEX IF NOT EXISTS idx_items_parent_id ON items(parent_id);
CREATE INDEX IF NOT EXISTS idx_items_path ON items(path);
-- CREATE INDEX IF NOT EXISTS idx_share_user_item_id ON share_user(item_id);
-- CREATE INDEX IF NOT EXISTS idx_share_user_user_id ON share_user(user_id);
-- CREATE INDEX IF NOT EXISTS idx_share_user_shared_by ON share_user(shared_by);


