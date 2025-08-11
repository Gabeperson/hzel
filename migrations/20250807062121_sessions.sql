CREATE TABLE IF NOT EXISTS sessions (
    id TEXT NOT NULL,   
    data BLOB NOT NULL,
    expires INT NOT NULL,
    PRIMARY KEY (id)
) STRICT;
