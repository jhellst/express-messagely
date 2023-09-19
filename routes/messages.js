"use strict";

const Router = require("express").Router;
const router = new Router();

const Message = require('../models/message');
const { ensureCorrectUser, ensureLoggedIn } = require('../middleware/auth');
const { NotFoundError, UnauthorizedError } = require("../expressError");
const User = require("../models/user");


router.use(ensureLoggedIn);


/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Makes sure that the currently-logged-in users is either the to or from user.
 *
 **/
router.get('/:id', async function (req, res, next) {
  const username = res.locals.user.username;
  const message = await Message.get(req.params.id);

  if (!(username === message.to_user.username) && !(username === message.from_user.username)) {
    throw new UnauthorizedError();
  }

  return res.json({ message });
});



/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/
router.post('/', async function (req, res, next) {
  const to_username = req.body.to_username;
  const body = req.body.body;
  const from_username = res.locals.user.username;

  // Retrieve user (to confirm they exist)
  await User.get(to_username);

  const message = await Message.create({ from_username, to_username, body });
  return res.json({ message });
});


/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Makes sure that the only the intended recipient can mark as read.
 *
 **/
router.post('/:id/read', async function (req, res, next) {
  const message_id = req.params.id;

  const current_user = res.locals.user.username;

  let message = await Message.get(message_id);
  if (message.to_user.username !== current_user) {
    throw new UnauthorizedError(
      "Current user does not have authorization to view selected message."
    );
  }

  message = await Message.markRead(message_id);
  return res.json({ message });
});


module.exports = router;