import mysql from "mysql2";
import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import dotenv from "dotenv";
import { nanoid } from "nanoid";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

const databaseUrl = process.env.DB_URL;

const accessEnv = process.env;
const PORT = accessEnv.PORT || 3000;
const JWT_SECRET = accessEnv.SECRECT_TOKEN;

const db = mysql.createConnection({
  host: accessEnv.DB_HOST,
  user: accessEnv.DB_USER,
  password: accessEnv.DB_PASS,
  database: accessEnv.DB_NAME,
});

db.connect((err) => {
  if (err) {
    console.log("DB Connection Error: ", err);
    process.exit(1);
  } else {
    console.log("MySQL User Connected");
  }
});

// Add User to database
app.post("/adduser", async (req, res) => {
  const { name, email, password } = req.body;
  const uId = nanoid(10);

  if (!name || !email || !password) {
    return res.status(400).json({ error: "All fields are requied" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const [rows] = await db
      .promise()
      .query(
        "INSERT INTO user (id, name, email, password) VALUES (?, ?, ?, ?)",
        [uId, name, email, hashedPassword]
      );

    const token = jwt.sign({ id: uId, email }, JWT_SECRET, { expiresIn: "2h" });

    res.status(200).json({
      message: "User added successfully",
      user: {
        id: uId,
        name: name,
        email: email,
      },
      token,
    });
  } catch (error) {
    console.error("Database error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/context", async (req, res) => {
  // const {id} = req.body;
  try {
    const result = await db
      .promise()
      .query("Select * from context where id =(select max(id) from context);");

    if (result[0].length === 0) {
      return res.status(404).json({ error: "No context found" });
    }

    res.status(200).json(result[0]);
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
    // Query the user by email from the database
    const [rows] = await db
      .promise()
      .query("SELECT * FROM user WHERE email = ?", [email]);

    if (rows.length === 0) {
      // User not found
      return res.status(404).json({ error: "User not found" });
    }

    const user = rows[0]; // Assuming the user exists
    const storedHashedPassword = user.password;

    // Compare the provided password with the stored hashed password
    const isMatch = await bcrypt.compare(password, storedHashedPassword);

    if (!isMatch) {
      return res.status(401).json({ error: "Invalid password" });
    }

    const token = jwt.sign({ id: user.id, email }, JWT_SECRET, {
      expiresIn: "2h",
    });

    if (res.status(200)) {
      console.log("User logged in");
    }
    // If the password matches, you can respond with user details or a token
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

app.listen(PORT, "192.168.1.11", () => {
  console.log(`Server is running on http://192.168.1.11:${PORT}`);
});
