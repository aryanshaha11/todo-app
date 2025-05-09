import mongoose from "mongoose";

const Schema = mongoose.Schema;
const ObjectId = mongoose.ObjectId;

const User = new Schema({
  firstname: String,
  lastname: String,
  email: { type: String, unique: true },
  password: String,
});

const Todo = new Schema({
  title: String,
  done: { type: Boolean, default: false },
  createdAt: String,
  dueAt: String,
  userId: { type: Schema.Types.ObjectId, ref: "users" },
});

const UserModel = mongoose.model("users", User);
const TodoModel = mongoose.model("todos", Todo);

export { UserModel, TodoModel };
