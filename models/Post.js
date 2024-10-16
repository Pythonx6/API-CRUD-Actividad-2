const mongoose = require("mongoose");

const postSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    minlength: 5,
  },
  text: {
    type: String,
    required: true,
    minlength: 5,
  },
  author: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
  status: {
    type: String, // Estado del post (ej. 'draft', 'published', 'archived')
    default: "draft",
  },
  views: {
    type: Number, // Contador de vistas
    default: 0,
  },
});

const Post = mongoose.model("Post", postSchema);

module.exports = Post;
