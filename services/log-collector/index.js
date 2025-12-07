const express = require("express");
const mongoose = require("mongoose");
require("dotenv").config();

const app = express();
app.use(express.json());

// Connexion MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("Mongo error:", err));

// Route de test
app.get("/", (req, res) => {
  res.json({ message: "LogCollector is running" });
});

// Réception des logs
app.post("/logs/upload", async (req, res) => {
  try {
    const log = {
      data: req.body,
      createdAt: new Date()
    };

    await mongoose.connection.collection("raw_logs").insertOne(log);

    res.status(201).json({ message: "Log saved" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error while saving log" });
  }
});

const port = process.env.PORT || 3001;
app.listen(port, () => console.log(`LogCollector running on port ${port}`));
