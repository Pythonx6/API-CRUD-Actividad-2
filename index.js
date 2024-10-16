const express = require("express");
const mongoose = require("mongoose");
const { MongoMemoryServer } = require("mongodb-memory-server");
const jwt = require("jsonwebtoken"); // Para manejar tokens JWT
const bcrypt = require("bcrypt"); // Para cifrar contraseñas
const Post = require("./models/Post");
const User = require("./models/User"); // Importar el modelo User

const app = express();
const port = 8000;
const JWT_SECRET = "mySecretKey"; // Usar una clave secreta para firmar el JWT

// Middleware para parsear JSON
app.use(express.json());

// Middleware para autenticar rutas usando JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401); // Si no hay token, retorna 401

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Token inválido
    req.user = user;
    next();
  });
};

// POST: Crear un nuevo usuario (registro)
app.post("/api/v1/users", async (req, res) => {
  try {
    const { name, email, password, bio } = req.body;

    // Cifrar la contraseña antes de guardarla en la base de datos
    const hashedPassword = await bcrypt.hash(password, 10);

    // Crear usuario con active: false por defecto
    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      bio,
      active: false,
    });
    await newUser.save();

    // Enlace simulado para activar la cuenta (solo en consola)
    console.log(
      `User activation link: http://localhost:8000/api/v1/users/activate/${newUser._id}`
    );

    res
      .status(201)
      .json({
        message: "User created. Check activation link in console.",
        user: newUser,
      });
  } catch (error) {
    res.status(400).json({ error: "Invalid data or missing fields" });
  }
});

// ----------- Actividad 4 --------------
// GET: Activar usuario mediante enlace
app.get("/api/v1/users/activate/:id", async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: "User not found" });

    user.active = true; // Cambiar a true el campo 'active'
    await user.save();
    res.status(200).json({ message: "User activated successfully" });
  } catch (error) {
    res.status(400).json({ error: "Invalid ID" });
  }
});

// POST: Login de usuario
app.post("/api/v1/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });
    if (!user.active)
      return res.status(403).json({ error: "Account not activated" });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword)
      return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(200).json({ token });
  } catch (error) {
    res.status(400).json({ error: "Login failed" });
  }
});

// --- Endpoints CRUD de Posts protegidos por autenticación JWT ---

app.post("/api/v1/posts", authenticateToken, async (req, res) => {
  try {
    const { title, text, author } = req.body;
    const newPost = new Post({ title, text, author });
    await newPost.save();
    res.status(201).json(newPost);
  } catch (error) {
    res.status(400).json({ error: "Invalid data or missing fields" });
  }
});

app.get("/api/v1/posts", authenticateToken, async (req, res) => {
  const posts = await Post.find();
  res.status(200).json(posts);
});

app.get("/api/v1/posts/:id", authenticateToken, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ error: "Post not found" });
    res.status(200).json(post);
  } catch (error) {
    res.status(400).json({ error: "Invalid ID" });
  }
});

app.patch("/api/v1/posts/:id", authenticateToken, async (req, res) => {
  try {
    const updatedPost = await Post.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
    });
    if (!updatedPost) return res.status(404).json({ error: "Post not found" });
    res.status(200).json(updatedPost);
  } catch (error) {
    res.status(400).json({ error: "Invalid data or ID" });
  }
});

app.delete("/api/v1/posts/:id", authenticateToken, async (req, res) => {
  try {
    const deletedPost = await Post.findByIdAndDelete(req.params.id);
    if (!deletedPost) return res.status(404).json({ error: "Post not found" });
    res.status(204).send();
  } catch (error) {
    res.status(400).json({ error: "Invalid ID" });
  }
});

app.patch("/api/v1/posts/:id/view", authenticateToken, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ error: "Post not found" });

    post.views += 1;
    await post.save();
    res.status(200).json(post);
  } catch (error) {
    res.status(400).json({ error: "Invalid ID" });
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

const startMongoServer = async () => {
  const mongoServer = await MongoMemoryServer.create();
  const mongoUri = mongoServer.getUri();

  mongoose
    .connect(mongoUri)
    .then(() => {
      console.log("Connected to MongoDB in-memory");
    })
    .catch((error) => {
      console.error("MongoDB connection error:", error);
    });
};

startMongoServer();
