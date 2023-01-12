require("dotenv").config();
const express = require("express");
const app = express();
const Joi = require("joi");
const jwt = require("jsonwebtoken");

const bcrypt = require("bcrypt");

app.use(express.json());

const { MongoClient } = require("mongodb");
// Replace the uri string with your connection string.
const uri = `mongodb+srv://Cluster01997:${process.env.CLUSTERPASS}@cluster01997.t9p0rm3.mongodb.net/?retryWrites=true&w=majority`;

const client = new MongoClient(uri);

const database = client.db("SenderCheck");

//Register user
app.post("/users", async (req, res) => {
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
      first_name: req.body.first_name,
      last_name: req.body.last_name,
      user_email: req.body.user_email,
      password: hashedPassword,
    };
    const users = database.collection("users");
    await users.insertOne(user);
    res.status(201).send();
  } catch {
    res.status(500).send();
  }
});

//Login
app.post("/users/login", async (req, res) => {
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
      const accessToken = generateAccessToken({ user_email: user.user_email });
      const refreshToken = jwt.sign(
        user.user_email,
        process.env.REFRESH_TOKEN_SECRET
      );
      const refresh_tokens = database.collection("refresh_tokens");
      await refresh_tokens.insertOne({ refresh_token: refreshToken });
      res.json({ accessToken: accessToken, refreshToken: refreshToken });
    } else {
      res.status(400).send("Incorrect email or password");
    }
  } catch {
    res.status(500).send();
  }
});

app.post("/token", async (req, res) => {
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
  const result = await refresh_tokens.findOne({ refresh_token: refreshToken });
  if (result == null) return res.sendStatus(403);
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = generateAccessToken({ user_email: user.user_email });
    res.json({ access_token: accessToken });
  });
});

app.delete("/logout", async (req, res) => {
  const schema = Joi.object({
    refresh_token: Joi.string().required(),
  });

  if (!validateSchema(schema, req, res)) {
    return;
  }

  const refresh_tokens = database.collection("refresh_tokens");
  await refresh_tokens.deleteOne({ refresh_token: req.body.refresh_token });
  res.sendStatus(204);
});

app.get("/", async (req, res) => {
  const trusted_senders = database.collection("trusted_senders");

  const query = {
    user_email: "osm@hotmail.com",
  };
  trusted_senders = await trusted_senders.findOne(query);

  res.send(trusted_senders);
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

const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`Listening on port ${port}...`));
