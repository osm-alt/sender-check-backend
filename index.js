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

app.get("/", async (req, res) => {
  const trusted_senders = database.collection("trusted_senders");

  const query = {
    user_email: "osm@hotmail.com",
  };
  trusted_senders = await trusted_senders.findOne(query);

  res.send(trusted_senders);
});

const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`Listening on port ${port}...`));
