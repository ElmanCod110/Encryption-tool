CREATE TABLE IF NOT EXISTS reserved_project_names (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name_hash CHAR(64) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_reserved_project_name_hash (name_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS secure_packages (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    package_id CHAR(48) NOT NULL,
    owner_hash CHAR(64) NOT NULL,
    name_hash CHAR(64) NOT NULL,
    package_path VARCHAR(1024) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL DEFAULT NULL,
    revoked_at TIMESTAMP NULL DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_secure_package_id (package_id),
    KEY idx_secure_package_owner (owner_hash),
    KEY idx_secure_package_name_hash (name_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
