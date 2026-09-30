-- Networks a server group allows to transfer zones (IP ACL groups only): added to ALLOW-AXFR-FROM of the zones
-- the group receives, next to its servers' own addresses. For AXFR clients that are a network, not a server.
CREATE TABLE IF NOT EXISTS secondary_group_prefixes (
    id                 INT UNSIGNED NOT NULL AUTO_INCREMENT,
    secondary_group_id INT UNSIGNED NOT NULL,
    cidr               VARCHAR(64)  NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_sgp (secondary_group_id, cidr),
    CONSTRAINT fk_sgp_group FOREIGN KEY (secondary_group_id) REFERENCES secondary_groups (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
