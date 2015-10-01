CREATE TABLE users (
  fingerprint character varying(255) not null unique,
  public_key text not null
);
