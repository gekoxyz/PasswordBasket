# PasswordBasket

### 2021 graduation exam's project, Galiazzo Matteo.

Password manager and password generator written in Java by me as graduation exam's project.

Database structure:

```
CREATE TABLE IF NOT EXISTS user_login (
	username varchar(25) NOT NULL,
	password varchar(255) NOT NULL,
	salt varchar(50) NOT NULL,
	name varchar(50) DEFAULT NULL,
	mail varchar(50) NOT NULL,
	PRIMARY KEY (username)
) ENGINE = InnoDB;

CREATE TABLE IF NOT EXISTS user_accounts (
	service varchar(100) NOT NULL,
	service_username varchar(100) NOT NULL,
	service_password varchar(100) DEFAULT NULL,
	username varchar(25) NOT NULL,
	PRIMARY KEY (service, service_username, username),
	FOREIGN KEY (username) REFERENCES user_login (username) ON UPDATE CASCADE
) ENGINE = InnoDB;
```
