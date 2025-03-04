import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import dotenv from "dotenv";
import { nanoid } from "nanoid";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

import pkg from "pg";

const { Client } = pkg;

dotenv.config();

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

const accessEnv = process.env;
const PORT = accessEnv.PORT || 3000;
const JWT_SECRET = accessEnv.SECRECT_TOKEN;

const client = new Client({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 5432, // Default PostgreSQL port
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

client.connect(async (err) => {
  if (err) {
    console.log("DB Connection Error: ", err);
    process.exit(1);
  } else {
    console.log("PostgreSQL Connected");

    // Create tables if they do not exist
    try {
      await client.query(`
        CREATE TABLE IF NOT EXISTS users (
          id VARCHAR(10) PRIMARY KEY,
          name VARCHAR(100) NOT NULL,
          email VARCHAR(100) UNIQUE NOT NULL,
          password VARCHAR(255) NOT NULL
        );
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS context (
          id SERIAL PRIMARY KEY,
          data TEXT NOT NULL
        );
      `);

      console.log("Tables checked/created successfully.");
    } catch (createTableError) {
      console.error("Error creating tables: ", createTableError);
    }
  }
});

// Add User to database
app.post("/adduser", async (req, res) => {
  const { name, email, password } = req.body;
  const uId = nanoid(10);

  if (!name || !email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await client.query(
      "INSERT INTO users (id, name, email, password) VALUES ($1, $2, $3, $4) RETURNING *",
      [uId, name, email, hashedPassword]
    );

    const token = jwt.sign({ id: uId, email }, JWT_SECRET, { expiresIn: "2h" });

    res.status(200).json({
      message: "User added successfully",
      user: result.rows[0], // Return the created user
      token,
    });
  } catch (error) {
    console.error("Database error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/context", async (req, res) => {
  try {
    const result = await client.query(
      "SELECT * FROM context WHERE id = (SELECT max(id) FROM context);"
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "No context found" });
    }

    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.log("Context Error: ", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Login User
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const result = await client.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = result.rows[0];
    const storedHashedPassword = user.password;

    const isMatch = await bcrypt.compare(password, storedHashedPassword);

    if (!isMatch) {
      return res.status(401).json({ error: "Invalid password" });
    }

    const token = jwt.sign({ id: user.id, email }, JWT_SECRET, {
      expiresIn: "2h",
    });

    res.status(200).json({
      message: "Login successful",
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
      token,
    });
  } catch (error) {
    console.error("Database error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on ${PORT}`);
});
