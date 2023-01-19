require("dotenv").config();
const express = require("express");
const app = express();
const Joi = require("joi");
const jwt = require("jsonwebtoken");
const xss = require("xss");
var cors = require("cors");

app.use(cors());

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
      list_owner: Joi.string().required().email().max(100), //owner of the lists of senders and domains
    });

    if (!auth.validateSchema(schema, req, res)) {
      return;
    }

    let found = false;

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

    const sender_name = req.body.sender_name.replace(/\./g, "(dot)");
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
      found = true;
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
      found = true;
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

    if (found) {
      return res
        .status(404)
        .send("Found sender with that name but not same email");
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

    const sender_name = xss(req.body.sender_name.replace(/\./g, "(dot)"));
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

//remove a sender from your trusted senders list
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

    const sender_name = xss(req.body.sender_name.replace(/\./g, "(dot)"));
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

//read untrusted senders of a particular list
app.get("/untrusted_senders", authenticateToken, async (req, res) => {
  try {
    const schema = Joi.object({
      list_owner: Joi.string().required().email().max(100), //owner of the list of non-trusted senders
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

//add an untrusted sender to your list
app.post("/untrusted_senders", authenticateToken, async (req, res) => {
  try {
    const schema = Joi.object({
      sender_name: Joi.string().required().max(100), //to check if a specific sender is not trusted
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

    const sender_name = xss(req.body.sender_name.replace(/\./g, "(dot)"));
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

//remove a sender from your untrusted senders list
app.delete("/untrusted_senders", authenticateToken, async (req, res) => {
  try {
    const schema = Joi.object({
      sender_name: Joi.string().required().max(100), //to check if a specific sender is not trusted
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

    const sender_name = xss(req.body.sender_name.replace(/\./g, "(dot)"));
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

//read trusted domains of a particular list
app.get("/trusted_domains", authenticateToken, async (req, res) => {
  try {
    const schema = Joi.object({
      list_owner: Joi.string().required().email().max(100), //owner of the list of trusted domains
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

    const trusted_domains = database.collection("trusted_domains");
    result = await trusted_domains.findOne({
      user_email: list_owner,
    });

    if (result != null) {
      return res.status(200).json(result.domains);
    }

    return res.sendStatus(500);
  } catch {
    res.sendStatus(500);
  }
});

//add a trusted domain to your list
app.post("/trusted_domains", authenticateToken, async (req, res) => {
  try {
    const schema = Joi.object({
      domain: Joi.string().required().domain().max(100), //to check if a specific sender is trusted
    });

    if (!auth.validateSchema(schema, req, res)) {
      return;
    }

    const calling_user = req.user.user_email; //the user (email) who is making this HTTP call

    const trusted_domains = database.collection("trusted_domains");

    const domain = xss(req.body.domain);

    let result = await trusted_domains.findOne({
      user_email: calling_user,
    });

    let domains = result.domains;

    if (domains.includes(domain)) {
      return res.status(400).send("That domain already exists");
    } else {
      domains.push(domain);
      await trusted_domains.updateOne(
        { user_email: calling_user },
        { $set: { domains: domains } }
      );
      return res.sendStatus(200);
    }
  } catch {
    res.sendStatus(500);
  }
});

//remove a domain from your trusted domains list
app.delete("/trusted_domains", authenticateToken, async (req, res) => {
  try {
    const schema = Joi.object({
      domain: Joi.string().required().domain().max(100), //to check if a specific sender is trusted
    });

    if (!auth.validateSchema(schema, req, res)) {
      return;
    }

    const calling_user = req.user.user_email; //the user (email) who is making this HTTP call

    const trusted_domains = database.collection("trusted_domains");

    const domain = xss(req.body.domain);

    let result = await trusted_domains.findOne({
      user_email: calling_user,
    });

    let domains = result.domains;

    let domain_index = domains.indexOf(domain);
    if (domain_index != -1) {
      domains.splice(domain_index, 1);
      await trusted_domains.updateOne(
        { user_email: calling_user },
        { $set: { domains: domains } }
      );
      return res.sendStatus(200);
    }

    return res.sendStatus(404);
  } catch {
    res.sendStatus(500);
  }
});

//------------------------------------------------------//

//read untrusted domains of a particular list
app.get("/untrusted_domains", authenticateToken, async (req, res) => {
  try {
    const schema = Joi.object({
      list_owner: Joi.string().required().email().max(100), //owner of the list of untrusted domains
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

    const untrusted_domains = database.collection("untrusted_domains");
    result = await untrusted_domains.findOne({
      user_email: list_owner,
    });

    if (result != null) {
      return res.status(200).json(result.domains);
    }

    return res.sendStatus(500);
  } catch {
    res.sendStatus(500);
  }
});

//add an untrusted domain to your list
app.post("/untrusted_domains", authenticateToken, async (req, res) => {
  try {
    const schema = Joi.object({
      domain: Joi.string().required().domain().max(100), //to check if a specific sender is trusted
    });

    if (!auth.validateSchema(schema, req, res)) {
      return;
    }

    const calling_user = req.user.user_email; //the user (email) who is making this HTTP call

    const untrusted_domains = database.collection("untrusted_domains");

    const domain = xss(req.body.domain);

    let result = await untrusted_domains.findOne({
      user_email: calling_user,
    });

    let domains = result.domains;

    if (domains.includes(domain)) {
      return res.status(400).send("That domain already exists");
    } else {
      domains.push(domain);
      await untrusted_domains.updateOne(
        { user_email: calling_user },
        { $set: { domains: domains } }
      );
      return res.sendStatus(200);
    }
  } catch {
    res.sendStatus(500);
  }
});

//remove a domain from your untrusted domains list
app.delete("/untrusted_domains", authenticateToken, async (req, res) => {
  try {
    const schema = Joi.object({
      domain: Joi.string().required().domain().max(100), //to check if a specific sender is trusted
    });

    if (!auth.validateSchema(schema, req, res)) {
      return;
    }

    const calling_user = req.user.user_email; //the user (email) who is making this HTTP call

    const untrusted_domains = database.collection("untrusted_domains");

    const domain = xss(req.body.domain);

    let result = await untrusted_domains.findOne({
      user_email: calling_user,
    });

    let domains = result.domains;

    let domain_index = domains.indexOf(domain);
    if (domain_index != -1) {
      domains.splice(domain_index, 1);
      await untrusted_domains.updateOne(
        { user_email: calling_user },
        { $set: { domains: domains } }
      );
      return res.sendStatus(200);
    }

    return res.sendStatus(404);
  } catch {
    res.sendStatus(500);
  }
});

//------------------------------------------------------//

//read list of users with access to your lists
app.get("/users_with_access", authenticateToken, async (req, res) => {
  try {
    const schema = Joi.object({});

    if (!auth.validateSchema(schema, req, res)) {
      return;
    }

    const calling_user = req.user.user_email; //the user (email) who is making this HTTP call

    const users = database.collection("users");
    let result = await users.findOne({ user_email: calling_user }); //check if the list owner is an actual user
    if (result == null) {
      return res.sendStatus(404);
    }

    const users_with_access = database.collection("users_with_access");
    result = await users_with_access.findOne({
      list_owner: calling_user,
    });

    if (result != null) {
      return res.status(200).json(result.users_with_access);
    }

    return res.sendStatus(500);
  } catch {
    res.sendStatus(500);
  }
});

//add a user to your list of users with (read) access to your lists
app.post("/users_with_access", authenticateToken, async (req, res) => {
  try {
    const schema = Joi.object({
      user_email: Joi.string().required().email().max(100), //user you want to give access
    });

    if (!auth.validateSchema(schema, req, res)) {
      return;
    }

    const calling_user = req.user.user_email; //the user (email) who is making this HTTP call

    const users_with_access = database.collection("users_with_access");

    const user_email = xss(req.body.user_email);

    let result = await users_with_access.findOne({
      list_owner: calling_user,
    });

    let users_with_access_array = result.users_with_access;

    if (users_with_access_array.includes(user_email)) {
      return res.status(400).send("That user already has access");
    } else {
      users_with_access_array.push(user_email);
      await users_with_access.updateOne(
        { list_owner: calling_user },
        { $set: { users_with_access: users_with_access_array } }
      );
      return res.sendStatus(200);
    }
  } catch {
    res.sendStatus(500);
  }
});

//remove a users from your list of users with access
app.delete("/users_with_access", authenticateToken, async (req, res) => {
  try {
    const schema = Joi.object({
      user_email: Joi.string().required().email().max(100), //user you want to give access
    });

    if (!auth.validateSchema(schema, req, res)) {
      return;
    }

    const calling_user = req.user.user_email; //the user (email) who is making this HTTP call

    const users_with_access = database.collection("users_with_access");

    const user_email = xss(req.body.user_email);

    let result = await users_with_access.findOne({
      list_owner: calling_user,
    });

    let users_with_access_array = result.users_with_access;

    let user_index = users_with_access_array.indexOf(user_email);
    if (user_index != -1) {
      users_with_access_array.splice(user_index, 1);
      await users_with_access.updateOne(
        { list_owner: calling_user },
        { $set: { users_with_access: users_with_access_array } }
      );
      return res.sendStatus(200);
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
