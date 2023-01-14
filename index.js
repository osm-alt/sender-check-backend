require("dotenv").config();
const express = require("express");
const app = express();
const Joi = require("joi");
const jwt = require("jsonwebtoken");
const xss = require("xss");

app.use(express.json());

const auth = require("./auth");
app.use("/", auth.router);

const { MongoClient } = require("mongodb");
// Replace the uri string with your connection string.
const uri = `mongodb+srv://Cluster01997:${process.env.CLUSTERPASS}@cluster01997.t9p0rm3.mongodb.net/?retryWrites=true&w=majority`;

const client = new MongoClient(uri);

const database = client.db("SenderCheck");

app.get("/check_sender", authenticateToken, async (req, res) => {
  try {
    const schema = Joi.object({
      sender_name: Joi.string().required().max(100), //to check if a specific sender is trusted
      sender_email: Joi.string().required().email().max(100),
      list_owner: Joi.string().required().email().max(100), //owner of the list of trusted senders
    });

    if (!auth.validateSchema(schema, req, res)) {
      return;
    }

    const calling_user = req.user.user_email; //the user (email) who is making this HTTP call
    const list_owner = req.body.list_owner;

    if (list_owner !== calling_user) {
      const users_with_access = database.collection("users_with_access");
      let result = await users_with_access.findOne({
        list_owner: list_owner,
        users_with_access: calling_user, //the calling user is in the users_with_access array
      });
      if (result == null) {
        return res.status(401).send("You do not have access to this list"); //unauthorized
      }
    }

    const sender_name = req.body.sender_name;
    const sender_email = req.body.sender_email;
    const sender_email_domain = sender_email.substring(
      sender_email.lastIndexOf("@") + 1
    );

    const trusted_senders = database.collection("trusted_senders");
    const sender_in_doc = "senders_and_emails." + sender_name; //to reference the key (sender_name) of the embedded document
    result = await trusted_senders.findOne({
      user_email: list_owner,
      [sender_in_doc]: { $exists: true }, //check if the sender's name is in the list
    });

    if (result != null) {
      if (result.senders_and_emails[sender_name].includes(sender_email)) {
        return res.status(200).send("Trusted");
      }
    }

    const untrusted_senders = database.collection("untrusted_senders");
    result = await untrusted_senders.findOne({
      user_email: list_owner,
      [sender_in_doc]: { $exists: true }, //check if the sender's name is in the list
    });

    if (result != null) {
      if (result.senders_and_emails[sender_name].includes(sender_email)) {
        return res.status(200).send("Untrusted");
      }
    }

    const trusted_domains = database.collection("trusted_domains");
    result = await trusted_domains.findOne({
      user_email: list_owner,
      domains: [sender_email_domain],
    });
    if (result != null) {
      return res.status(200).send("Trusted");
    }

    const untrusted_domains = database.collection("untrusted_domains");
    result = await untrusted_domains.findOne({
      user_email: list_owner,
      domains: [sender_email_domain],
    });
    if (result != null) {
      return res.status(200).send("Untrusted");
    }

    return res.sendStatus(404);
  } catch {
    res.sendStatus(500);
  }
});

//read trusted senders of a particular list
app.get("/trusted_senders", authenticateToken, async (req, res) => {
  try {
    const schema = Joi.object({
      list_owner: Joi.string().required().email().max(100), //owner of the list of trusted senders
    });

    if (!auth.validateSchema(schema, req, res)) {
      return;
    }

    const calling_user = req.user.user_email; //the user (email) who is making this HTTP call
    const list_owner = req.body.list_owner;

    const users = database.collection("users");
    let result = await users.findOne({ user_email: list_owner }); //check if the list owner is an actual user
    if (result == null) {
      return res.sendStatus(404);
    }

    if (list_owner !== calling_user) {
      const users_with_access = database.collection("users_with_access");
      result = await users_with_access.findOne({
        list_owner: list_owner,
        users_with_access: calling_user, //the calling user is in the users_with_access array
      });
      if (result == null) {
        return res.status(401).send("You do not have access to this list"); //unauthorized
      }
    }

    const trusted_senders = database.collection("trusted_senders");
    result = await trusted_senders.findOne({
      user_email: list_owner,
    });

    if (result != null) {
      return res.status(200).json(result.senders_and_emails);
    }

    return res.sendStatus(500);
  } catch {
    res.sendStatus(500);
  }
});

//add a trusted senders to your list
app.post("/trusted_senders", authenticateToken, async (req, res) => {
  try {
    const schema = Joi.object({
      sender_name: Joi.string().required().max(100), //to check if a specific sender is trusted
      sender_email: Joi.string().required().email().max(100),
    });

    if (!auth.validateSchema(schema, req, res)) {
      return;
    }

    const calling_user = req.user.user_email; //the user (email) who is making this HTTP call

    const trusted_senders = database.collection("trusted_senders");

    let result = await trusted_senders.findOne({ user_email: calling_user });

    if (result == null) {
      return res.sendStatus(400);
    }

    const sender_name = xss(req.body.sender_name);
    const sender_email = xss(req.body.sender_email);

    let senders_and_emails = result.senders_and_emails;

    if (senders_and_emails[sender_name]) {
      if (senders_and_emails[sender_name].includes(sender_email)) {
        return res.status(400).send("The email for that sender already exists");
      } else {
        senders_and_emails[sender_name].push(sender_email);
        await trusted_senders.updateOne(
          { user_email: calling_user },
          { $set: { senders_and_emails: senders_and_emails } }
        );
        return res.sendStatus(200);
      }
    } else {
      senders_and_emails[sender_name] = [sender_email];
      await trusted_senders.updateOne(
        { user_email: calling_user },
        { $set: { senders_and_emails: senders_and_emails } }
      );
      return res.sendStatus(200);
    }
  } catch {
    res.sendStatus(500);
  }
});

//remove a sender to your trusted senders list
app.delete("/trusted_senders", authenticateToken, async (req, res) => {
  try {
    const schema = Joi.object({
      sender_name: Joi.string().required().max(100), //to check if a specific sender is trusted
      sender_email: Joi.string().required().email().max(100),
    });

    if (!auth.validateSchema(schema, req, res)) {
      return;
    }

    const calling_user = req.user.user_email; //the user (email) who is making this HTTP call

    const trusted_senders = database.collection("trusted_senders");

    let result = await trusted_senders.findOne({ user_email: calling_user });

    if (result == null) {
      return res.sendStatus(400);
    }

    const sender_name = xss(req.body.sender_name);
    const sender_email = xss(req.body.sender_email);

    let senders_and_emails = result.senders_and_emails;

    if (senders_and_emails[sender_name]) {
      let sender_index = senders_and_emails[sender_name].indexOf(sender_email);
      if (sender_index != -1) {
        senders_and_emails[sender_name].splice(sender_index, 1);
        if (senders_and_emails[sender_name].length == 0) {
          delete senders_and_emails[sender_name];
        }
        await trusted_senders.updateOne(
          { user_email: calling_user },
          { $set: { senders_and_emails: senders_and_emails } }
        );
        return res.sendStatus(200);
      }
    }
    return res.sendStatus(404);
  } catch {
    res.sendStatus(500);
  }
});

//------------------------------------------------------//

//read trusted senders of a particular list
app.get("/untrusted_senders", authenticateToken, async (req, res) => {
  try {
    const schema = Joi.object({
      list_owner: Joi.string().required().email().max(100), //owner of the list of trusted senders
    });

    if (!auth.validateSchema(schema, req, res)) {
      return;
    }

    const calling_user = req.user.user_email; //the user (email) who is making this HTTP call
    const list_owner = req.body.list_owner;

    const users = database.collection("users");
    let result = await users.findOne({ user_email: list_owner }); //check if the list owner is an actual user
    if (result == null) {
      return res.sendStatus(404);
    }

    if (list_owner !== calling_user) {
      const users_with_access = database.collection("users_with_access");
      result = await users_with_access.findOne({
        list_owner: list_owner,
        users_with_access: calling_user, //the calling user is in the users_with_access array
      });
      if (result == null) {
        return res.status(401).send("You do not have access to this list"); //unauthorized
      }
    }

    const untrusted_senders = database.collection("untrusted_senders");
    result = await untrusted_senders.findOne({
      user_email: list_owner,
    });

    if (result != null) {
      return res.status(200).json(result.senders_and_emails);
    }

    return res.sendStatus(500);
  } catch {
    res.sendStatus(500);
  }
});

//add a trusted senders to your list
app.post("/untrusted_senders", authenticateToken, async (req, res) => {
  try {
    const schema = Joi.object({
      sender_name: Joi.string().required().max(100), //to check if a specific sender is trusted
      sender_email: Joi.string().required().email().max(100),
    });

    if (!auth.validateSchema(schema, req, res)) {
      return;
    }

    const calling_user = req.user.user_email; //the user (email) who is making this HTTP call

    const untrusted_senders = database.collection("untrusted_senders");

    let result = await untrusted_senders.findOne({ user_email: calling_user });

    if (result == null) {
      return res.sendStatus(400);
    }

    const sender_name = xss(req.body.sender_name);
    const sender_email = xss(req.body.sender_email);

    let senders_and_emails = result.senders_and_emails;

    if (senders_and_emails[sender_name]) {
      if (senders_and_emails[sender_name].includes(sender_email)) {
        return res.status(400).send("The email for that sender already exists");
      } else {
        senders_and_emails[sender_name].push(sender_email);
        await untrusted_senders.updateOne(
          { user_email: calling_user },
          { $set: { senders_and_emails: senders_and_emails } }
        );
        return res.sendStatus(200);
      }
    } else {
      senders_and_emails[sender_name] = [sender_email];
      await untrusted_senders.updateOne(
        { user_email: calling_user },
        { $set: { senders_and_emails: senders_and_emails } }
      );
      return res.sendStatus(200);
    }
  } catch {
    res.sendStatus(500);
  }
});

//remove a sender to your trusted senders list
app.delete("/untrusted_senders", authenticateToken, async (req, res) => {
  try {
    const schema = Joi.object({
      sender_name: Joi.string().required().max(100), //to check if a specific sender is trusted
      sender_email: Joi.string().required().email().max(100),
    });

    if (!auth.validateSchema(schema, req, res)) {
      return;
    }

    const calling_user = req.user.user_email; //the user (email) who is making this HTTP call

    const untrusted_senders = database.collection("untrusted_senders");

    let result = await untrusted_senders.findOne({ user_email: calling_user });

    if (result == null) {
      return res.sendStatus(400);
    }

    const sender_name = xss(req.body.sender_name);
    const sender_email = xss(req.body.sender_email);

    let senders_and_emails = result.senders_and_emails;

    if (senders_and_emails[sender_name]) {
      let sender_index = senders_and_emails[sender_name].indexOf(sender_email);
      if (sender_index != -1) {
        senders_and_emails[sender_name].splice(sender_index, 1);
        if (senders_and_emails[sender_name].length == 0) {
          delete senders_and_emails[sender_name];
        }
        await untrusted_senders.updateOne(
          { user_email: calling_user },
          { $set: { senders_and_emails: senders_and_emails } }
        );
        return res.sendStatus(200);
      }
    }
    return res.sendStatus(404);
  } catch {
    res.sendStatus(500);
  }
});

//------------------------------------------------------//

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; //index 1 because it's BEARER then token in that header
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    console.log(err);
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`Listening on port ${port}...`));
