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
  const schema = Joi.object({
    sender_name: Joi.string().required().max(100), //to check if a specific sender is trusted
    sender_email: Joi.string().required().email().max(100),
    list_owner: Joi.string().required().email().max(100), //owner of the list of trusted senders
  });

  if (!auth.validateSchema(schema, req, res)) {
    return;
  }

  const sender_name = req.body.sender_name;
  const sender_email = req.body.sender_email;
  const sender_email_domain = sender_email.substring(
    sender_email.lastIndexOf("@")
  );
  const calling_user = req.user.user_email; //the user (email) who is making this HTTP call
  const list_owner = req.body.list_owner;

  const trusted_senders = database.collection("trusted_senders");
  let trusted_sender_in_doc = "senders_and_emails." + sender_name;
  let result = await trusted_senders.findOne({
    user_email: list_owner,
    [trusted_sender_in_doc]: { $exists: true }, //check if the sender's name is in the list
  });

  if (result != null) {
    if (
      list_owner === calling_user ||
      result.users_with_access.includes(calling_user)
    ) {
      if (result.senders_and_emails[sender_name].includes(sender_email)) {
        return res.status(200).send("Trusted");
      }
    } else {
      return res.status(401).send("You do not have access to this list"); //unauthorized
    }
  }

  // const untrusted_senders = database.collection("untrusted_senders");
  // result = await untrusted_senders.findOne({
  //   user_email: list_owner,
  //   senders_and_emails: { [sender_name]: { $exists: true } }, //check if the sender's name is in the list
  // });
  // if (result != null) {
  //   if (
  //     list_owner === calling_user ||
  //     result.users_with_access.includes(calling_user)
  //   ) {
  //     if (result.senders_and_emails[sender_name].includes(sender_email)) {
  //       return res.status(200).send("Untrusted");
  //     }
  //   } else {
  //     return res.status(401).send("You do not have access to this list"); //unauthorized
  //   }
  // }

  // const trusted_domains = database.collection("trusted_domains");
  // result = await trusted_domains.findOne({
  //   user_email: list_owner,
  // });
  // if (result != null) {
  //   if (
  //     list_owner === calling_user ||
  //     result.users_with_access.includes(calling_user)
  //   ) {
  //     if (result.domains.includes(sender_email_domain)) {
  //       return res.status(200).send("Trusted");
  //     }
  //   } else {
  //     return res.status(401).send("You do not have access to this list"); //unauthorized
  //   }
  // }

  // const untrusted_domains = database.collection("unrusted_domains");
  // result = await untrusted_domains.findOne({
  //   user_email: list_owner,
  // });
  // if (result != null) {
  //   if (
  //     list_owner === calling_user ||
  //     result.users_with_access.includes(calling_user)
  //   ) {
  //     if (result.domains.includes(sender_email_domain)) {
  //       return res.status(200).send("Trusted");
  //     }
  //   } else {
  //     return res.status(401).send("You do not have access to this list"); //unauthorized
  //   }
  // }

  return res.sendStatus(404);
});

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
