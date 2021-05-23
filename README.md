# PasswordBasket
Elaborato maturità 2021, Galiazzo Matteo
password manager in java che custodisce le password di un utente e fa da password generator

Database structure:
```
CREATE TABLE user_login (
  username varchar(25) PRIMARY KEY,
  password varchar(255) NOT NULL,
  name varchar(50),
  mail varchar(50) NOT NULL
);

CREATE TABLE user_account (
  service varchar(100),
  service_username varchar(100),
  service_password varchar(100),
  username varchar(25),
  PRIMARY KEY (service, service_username, username),
  FOREIGN KEY (username) REFERENCES user_login (username) ON UPDATE CASCADE
);
```