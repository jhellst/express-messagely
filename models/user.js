"use strict";

const { NotFoundError } = require("../expressError");
const db = require("../db");
const bcrypt = require("bcrypt");
const { BCRYPT_WORK_FACTOR } = require("../config");

/** User of the site. */

class User {

  /** Register new user. Returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({ username, password, first_name, last_name, phone }) {
    const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    const result = await db.query(
      `INSERT INTO users (username,
                             password,
                             first_name,
                             last_name,
                             phone,
                             join_at)
         VALUES
           ($1, $2, $3, $4, $5, current_timestamp)
         RETURNING username, password, first_name, last_name, phone`,
    [username, hashedPassword, first_name, last_name, phone]);

    return result.rows[0];
  }

  /** Authenticate: is username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const results = await db.query(
      `SELECT password
      FROM USERS
      WHERE username = $1`,
      [username]
      )

    const hashedPassword = results.rows[0].password;

    return hashedPassword && await bcrypt.compare(password, hashedPassword);
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const result = await db.query(
      `UPDATE users
       SET last_login_at = current_timestamp
         WHERE username = $1
         RETURNING username`,
    [username]);
    const user = result.rows[0];

    if (!user) throw new NotFoundError(`No such user: ${username}`);
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name}, ...] */

  static async all() {
    const result = await db.query(
      `SELECT username, first_name, last_name FROM users ORDER BY username`);
    return result.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const result = await db.query(
      `SELECT username, first_name, last_name, phone, join_at, last_login_at
          FROM users
          WHERE username = $1`,
          [username]);
    const user = result.rows[0];

    if (!user) throw new NotFoundError(`No such user: ${username}`);
    return user;
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {

    const result = await db.query(
      `SELECT m.id, m.to_username AS to_user, m.body, m.sent_at, m.read_at,
              t.username, t.first_name, t.last_name, t.phone
         FROM messages AS m
                JOIN users AS f ON m.from_username = f.username
                JOIN users AS t on m.to_username = t.username
         WHERE m.from_username = $1`,
    [username]);

    //map over our results to get the object we want
    let messages = result.rows;
    messages = messages.map(message => ({
      id: message.id,
      to_user: {
        username:message.username,
        first_name: message.first_name,
        last_name: message.last_name,
        phone: message.phone
      },
      body: message.body,
      sent_at: message.sent_at,
      read_at: message.read_at
      })
    );

    return messages;
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {

    const result = await db.query(
      `SELECT m.id, m.from_username AS from_user, m.body, m.sent_at, m.read_at,
              t.username, t.first_name, t.last_name, t.phone
         FROM messages AS m
                JOIN users AS f ON m.to_username = f.username
                JOIN users AS t on m.from_username = t.username
         WHERE m.to_username = $1`,
    [username]);

    let messages = result.rows;
    messages = messages.map(message => ({
      id: message.id,
      from_user: {
        username:message.username,
        first_name: message.first_name,
        last_name: message.last_name,
        phone: message.phone
      },
      body: message.body,
      sent_at: message.sent_at,
      read_at: message.read_at
      })
    );

    return messages;
  }
}


module.exports = User;
