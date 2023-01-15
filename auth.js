require("dotenv").config();
const express = require("express");
const router = express.Router();
const Joi = require("joi");
router.use(express.json());
const jwt = require("jsonwebtoken");
const xss = require("xss");

const bcrypt = require("bcrypt");

const { MongoClient } = require("mongodb");
// Replace the uri string with your connection string.
const uri = `mongodb+srv://Cluster01997:${process.env.CLUSTERPASS}@cluster01997.t9p0rm3.mongodb.net/?retryWrites=true&w=majority`;

const client = new MongoClient(uri);

const database = client.db("SenderCheck");

router.use((req, res, next) => {
  next();
});

//Register user
router.post("/users", async (req, res) => {
  try {
    //schema for expected input and validation
    const schema = Joi.object({
      first_name: Joi.string().required().max(25),
      last_name: Joi.string().required().max(30),
      user_email: Joi.string().email().required().max(100),
      password: Joi.string().required().min(5).max(50),
    });

    if (!validateSchema(schema, req, res)) {
      return;
    }

    const hashedPassword = await bcrypt.hash(req.body.password, 10); //hash password with a generated salt
    const user = {
      first_name: xss(req.body.first_name),
      last_name: xss(req.body.last_name),
      user_email: xss(req.body.user_email),
      password: hashedPassword,
    };
    const users = database.collection("users");
    const result = await users.findOne({ user_email: user.user_email });
    if (result != null) {
      return res.status(400).send("User already exists");
    }
    await users.insertOne(user);

    //create empty lists for the new user
    const users_with_access = database.collection("users_with_access");
    const users_with_access_template = {
      list_owner: user.user_email,
      users_with_access: [],
    };
    await users_with_access.insertOne(users_with_access_template);

    const trusted_senders = database.collection("trusted_senders");
    const trusted_senders_template = {
      user_email: user.user_email,
      senders_and_emails: {},
    };
    await trusted_senders.insertOne(trusted_senders_template);
    const untrusted_senders = database.collection("untrusted_senders");
    await untrusted_senders.insertOne(trusted_senders_template);
    const trusted_domains_template = {
      user_email: user.user_email,
      domains: [],
    };
    const trusted_domains = database.collection("trusted_domains");
    await trusted_domains.insertOne(trusted_domains_template);
    const untrusted_domains = database.collection("untrusted_domains");
    await untrusted_domains.insertOne(trusted_domains_template);

    return res.status(201).send();
  } catch {
    return res.status(500).send();
  }
});

//Login
router.post("/users/login", async (req, res) => {
  try {
    //schema for expected input and validation
    const schema = Joi.object({
      user_email: Joi.string().email().required(),
      password: Joi.string().required().min(5).max(50),
    });

    if (!validateSchema(schema, req, res)) {
      return;
    }

    const users = database.collection("users");
    const user = await users.findOne({
      user_email: req.body.user_email,
    });

    if (user == null) {
      return res.status(400).send("Incorrect email or password");
    }
    try {
      if (await bcrypt.compare(req.body.password, user.password)) {
        const accessToken = generateAccessToken({
          user_email: user.user_email,
        });
        const refreshToken = jwt.sign(
          user.user_email,
          process.env.REFRESH_TOKEN_SECRET
        );
        const refresh_tokens = database.collection("refresh_tokens");
        await refresh_tokens.insertOne({ refresh_token: refreshToken });
        return res.json({
          access_token: accessToken,
          refresh_token: refreshToken,
        });
      } else {
        return res.status(400).send("Incorrect email or password");
      }
    } catch {
      return res.status(500).send();
    }
  } catch {
    return res.status(500).send();
  }
});

router.post("/token", async (req, res) => {
  try {
    //schema for expected input and validation
    const schema = Joi.object({
      refresh_token: Joi.string().required(),
    });

    if (!validateSchema(schema, req, res)) {
      return;
    }
    const refreshToken = req.body.refresh_token;
    if (refreshToken == null) return res.sendStatus(401);

    const refresh_tokens = database.collection("refresh_tokens");
    const result = await refresh_tokens.findOne({
      refresh_token: refreshToken,
    });
    if (result == null) return res.sendStatus(403);
    jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET,
      (err, user_email) => {
        if (err) return res.sendStatus(403);
        const accessToken = generateAccessToken({ user_email: user_email });
        return res.json({ access_token: accessToken });
      }
    );
  } catch {
    return res.status(500).send();
  }
});

router.delete("/logout", async (req, res) => {
  try {
    const schema = Joi.object({
      refresh_token: Joi.string().required(),
    });

    if (!validateSchema(schema, req, res)) {
      return;
    }

    const refresh_tokens = database.collection("refresh_tokens");
    await refresh_tokens.deleteOne({ refresh_token: req.body.refresh_token });
    return res.sendStatus(204);
  } catch {
    return res.status(500).send();
  }
});

function validateSchema(schema, req, res) {
  const result = schema.validate(req.body);

  if (result.error) {
    res.status(400).send(result.error);
    return false;
  }
  return true;
}

function generateAccessToken(user_email) {
  return jwt.sign(user_email, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "15m",
  });
}

module.exports = { router, validateSchema, generateAccessToken };
