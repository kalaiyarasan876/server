const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 8080;

app.use(cors());
app.use(bodyParser.json());

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT
});

db.connect((err) => {
  if (err) throw err;
  console.log("MySQL Connected...");
});

// Register Route

app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const query = `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`;
  db.execute(query, [username, email, hashedPassword], (err, result) => {
    if (err) {
      return res.status(400).send({ msg: "User already exists!" });
    }
    res.send({ msg: "User registered successfully!" });
  });
});

// Login Route

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.execute(
    `SELECT * FROM users WHERE email = ?`,
    [email],
    async (err, result) => {
      if (
        err ||
        result.length === 0 ||
        !(await bcrypt.compare(password, result[0].password))
      ) {
        return res.status(400).send({ msg: "Invalid email or password!" });
      }

      const user = result[0];
      const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
        expiresIn: "1h"
      });
      res.send({
        token,
        user: { id: user.id, username: user.username, email: user.email }
      });
    }
  );
});

// Protected Route Example

app.get("/protected", verifyToken, (req, res) => {
  res.send("This is a protected route");
});

// Verify Token Middleware

function verifyToken(req, res, next) {
  const token = req.header("x-auth-token");
  if (!token)
    return res.status(401).send({ msg: "No token, authorization denied" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(400).send({ msg: "Token is not valid" });
  }
}

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
