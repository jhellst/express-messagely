"use strict";

const Router = require("express").Router;
const { SECRET_KEY } = require("../config");
const User = require("../models/user");
const { UnauthorizedError, BadRequestError } = require("../expressError");
const jwt = require("jsonwebtoken");

const router = new Router();

/** POST /login: {username, password} => {token} */
router.post("/login", async function (req, res, next) {

  if (req.body === undefined) throw new BadRequestError();

  const { username, password } = req.body;

  // Authenticate here.
  if (await User.authenticate(username, password)) {
    const payload = { username };
    const token = jwt.sign(payload, SECRET_KEY);
    return res.json(token);
  } else {
    throw new UnauthorizedError("User was not authenticated. Either username or password was incorrect.");
  }
});



/** POST /register: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 */
router.post("/register", async function (req, res, next) {

  if (req.body === undefined) throw new BadRequestError("No username or password provided for registration.");

  if (
    !req.body.username ||
    !req.body.password ||
    !req.body.first_name ||
    !req.body.last_name ||
    !req.body.phone
  ) {
    throw new BadRequestError(
      `One or more sign-up requirements not provided in request
          (username, password, first_name, last_name, phone).`
    );
  }

  const { username, password, first_name, last_name, phone } = req.body;


  // Register here using user model.
  try {
    const user = await User.register({ username, password, first_name, last_name, phone });
    if (await User.authenticate(username, password)) {
      const payload = { username };
      const token = jwt.sign(payload, SECRET_KEY);
      return res.json(token);
    }
  } catch (err) {
    throw new BadRequestError("Error occured during user registration.");
  }
});



module.exports = router;