const express = require("express");
const router = express.Router();
const gravatar = require("gravatar");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("config");
const { check, validationResult } = require("express-validator");

const User = require("../../models/User");

// @route   POST api/users
// @desc    Register user
// @access  Public
router.post(
  "/",
  [
    check("name", "Name is required").not().isEmpty(),
    check("email", "Please include a valid email").isEmail(),
    check(
      "password",
      "Please enter a password with 6 or more characters"
    ).isLength({ min: 6 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // DESTRUCTURE NAME, EMAIL AND PASSWORD FROM BODY
    const { name, email, password } = req.body;

    try {
      // CHECK IF THERE IS ALREADY A USER WITH THE GIVEN EMAIL
      let user = await User.findOne({ email });

      // IF THERE IS A USER WITH GIVEN EMAIL, RETURN ERROR
      if (user) {
        return res
          .status(400)
          .json({ errors: [{ msg: " User already exists" }] });
      }

      // CREATE AVATAR FROM GRAVATAR.
      const avatar = gravatar.url(email, {
        s: "200",
        r: "pg",
        d: "mm",
      });

      // CREATE A NEW USER
      user = new User({
        name,
        email,
        avatar,
        password,
      });

      // CREATE A SALT TO USE WHEN HASING PASSWORD
      const salt = await bcrypt.genSalt(10);

      user.password = await bcrypt.hash(password, salt);

      // SAVE CREATED USER TO DB
      await user.save();

      const payload = {
        user: {
          id: user.id,
        },
      };

      jwt.sign(
        payload,
        config.get("jwtSecret"),
        { expiresIn: 360000 },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send("Server error");
    }
  }
);

module.exports = router;
