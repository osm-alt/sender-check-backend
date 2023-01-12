require("dotenv").config();
const express = require("express");
const app = express();
const Joi = require("joi");

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
      user_email: Joi.string().email().required(),
      password: Joi.string().required().min(5).max(50),
    });

    if (!validateSchema(schema, req, res)) {
      return;
    }

    const hashedPassword = await bcrypt.hash(req.body.password, 10); //hash password with a generated salt
    const user = { user_email: req.body.user_email, password: hashedPassword };
    const users = database.collection("users");
    users.insertOne(user);
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

  console.log(user);

  if (user == null) {
    return res.status(400).send("Incorrect email or password");
  }
  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      res.send("Success");
    } else {
      res.send("Incorrect email or password");
    }
  } catch {
    res.status(500).send();
  }
});

app.get("/", async (req, res) => {
  const trusted_senders = database.collection("trusted_senders");

  try {
    const query = {
      user_email: "osm@hotmail.com",
    };
    const trusted_senders = await trusted_senders.findOne(query);

    console.log(trusted_senders);
    res.send(trusted_senders);
  } finally {
    // Ensures that the client will close when you finish/error
    await client.close();
  }
});
async function run() {}

const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`Listening on port ${port}...`));

function validateSchema(schema, req, res) {
  const result = schema.validate(req.body);

  if (result.error) {
    res.status(400).send(result.error);
    return false;
  }
  return true;
}
