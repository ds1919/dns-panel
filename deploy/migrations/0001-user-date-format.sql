-- Personal date format (Account → Display): NULL = the browser's, dmy = DD.MM.YYYY, iso = YYYY-MM-DD, mdy = MM/DD/YYYY.
ALTER TABLE users ADD COLUMN IF NOT EXISTS date_format VARCHAR(8) DEFAULT NULL AFTER timezone;
