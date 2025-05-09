import express from "express";
import jwt from "jsonwebtoken";
import path from "path";
import { fileURLToPath } from "url";
import { UserModel, TodoModel } from "./db.js";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import { z } from "zod";
import dotenv from "dotenv";
dotenv.config();

const app = express();
const JWT_SECRET = process.env.JWT_SECRET;

mongoose.connect(process.env.URL);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.json());
app.use(express.static(path.join(__dirname, "/public")));

app.get("/", (req, res) => {
  res.sendFile((__dirname, "public", "index.html"));
});

app.post("/signup", async (req, res) => {
  const passwordSchema = z
    .string()
    .min(8)
    .max(100)
    .regex(/[a-z]/, "Password must contain at least one lowercase letter")
    .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
    .regex(/\d/, "Password must contain at least one number")
    .regex(
      /[!@#$%^&*(),.?":{}|<>[\]\\\/'`~\-_=+]/,
      "Password must contain at least one special character"
    );

  const User = z.object({
    firstname: z.string(),
    lastname: z.string(),
    email: z.string().email().min(5).max(50),
    password: passwordSchema,
  });

  const ParsedDataSuccess = User.safeParse(req.body);

  if (!ParsedDataSuccess.success) {
    res.json({
      message: "Incorrect Format ",
      error: ParsedDataSuccess.error,
    });
    return;
  }

  const email = req.body.email;
  const password = req.body.password;
  const firstname = req.body.firstname;
  const lastname = req.body.lastname;

  const ExistingUser = await UserModel.findOne({
    email,
  });

  if (ExistingUser) {
    return res.status(409).json({
      message: "Email has already been taken",
    });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  await UserModel.create({
    firstname: firstname,
    lastname: lastname,
    email: email,
    password: hashedPassword,
  });

  res.json({
    message: "You are signed up",
  });
});

app.post("/signin", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  const foundUser = await UserModel.findOne({
    email: email,
  });

  if (!foundUser) {
    res.status(403).json({
      message: "User does not exist in our db",
    });
    return;
  }

  const matchPassword = await bcrypt.compare(password, foundUser.password);

  if (foundUser && matchPassword) {
    const token = jwt.sign(
      {
        id: foundUser._id,
      },
      JWT_SECRET
    );

    res.json({
      token: token,
    });
    return;
  } else {
    res.json({
      message: "Incorrect Credentials",
    });
  }
});

function auth(req, res, next) {
  const token = req.headers.token;

  if (!token) {
    return res.status(401).json({ message: "Token not provided" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded.id;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

app.post("/todo", auth, async (req, res) => {
  const id = req.user;
  const title = req.body.title;
  const dueAt = req.body.dueAt;

  const newTodo = await TodoModel.create({
    title: title,
    createdAt: new Date().toLocaleString(),
    dueAt: new Date(dueAt).toLocaleString(),
    userId: id,
  });

  res.json({
    message: "Todo added successfully",
    id: newTodo._id,
    title: newTodo.title,
  });
});

app.get("/todos", auth, async (req, res) => {
  const userId = req.user;
  try {
    const todos = await TodoModel.find({
      userId,
    });
    res.json({
      todos,
    });
  } catch (e) {
    res.json({
      message: e,
    });
  }
});

app.delete("/todo/:id", auth, async (req, res) => {
  const todoId = req.params.id;

  try {
    const result = await TodoModel.deleteOne({
      _id: todoId,
    });
    res.json({
      message: "Todo deleted Successfully",
    });
  } catch (e) {
    res.status(500).json({
      message: e,
    });
  }
});

app.put("/todo/:id", auth, async (req, res) => {
  const UpdateId = Object(req.params.id);
  const updatedText = req.body.updatedText;

  await TodoModel.updateOne(
    { _id: UpdateId },
    { $set: { title: updatedText } }
  );
  res.json({
    message: "todo has been updated",
  });
});

app.put("/todo/:id/done", auth, async (req, res) => {
  const todoId = Object(req.params.id);
  const done = req.body.done;

  try {
    await TodoModel.updateMany({ _id: todoId }, { $set: { done: done } });
    res.json({
      message: "Todo status updated",
    });
  } catch (e) {
    res.status(500).json({
      message: "Error updating todo",
      error: e.message,
    });
  }
});

app.listen(3000);
