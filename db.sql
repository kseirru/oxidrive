-- oxidrive.accounts definition

CREATE TABLE `accounts` (
                            `uuid` varchar(100) NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
                            `username` varchar(100) NOT NULL,
                            `password` varchar(128) NOT NULL,
                            `is_admin` varchar(100) NOT NULL DEFAULT '0',
                            `avatar` varchar(100) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='Table, that used for storing account details like username, password and etc.';