require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const multer = require('multer');
const path = require('path');

// Configure storage for uploaded images
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/uploads/'); // Directory for uploaded files
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // Unique filename
  },
});

// File filter to accept only images
const fileFilter = (req, file, cb) => {
  const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif'];
  if (allowedMimeTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only JPEG, PNG, and GIF are allowed.'));
  }
};

const upload = multer({ storage, fileFilter });

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.set('view engine', 'ejs');
const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config();

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log('Connected to MongoDB');
}).catch((error) => {
  console.error('MongoDB connection error:', error);
});

// MongoDB Connection
// mongoose
//   .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
//   .then(() => console.log('Connected to MongoDB'))
//   .catch(err => console.error('MongoDB connection error:', err));

// Session Configuration
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
    }),
    cookie: { maxAge: 1000 * 60 * 60 * 24 }, // 1 day
  })
);

// User Schema and Model
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  image: { type: String }, // URL or file path for the user's profile image
});

const User = mongoose.model('User', userSchema);

// Middleware to protect routes
const isAuthenticated = (req, res, next) => {
  if (req.session.userId) {
    return next();
  }
  res.redirect('/login');
};

// Routes
app.get('/', (req, res) => res.redirect('/login'));

// Registration
app.get('/register', (req, res) => res.render('register'));
app.post('/register', upload.single('image'), async (req, res) => {
  const { name, email, password } = req.body;
  const image = req.file ? `/uploads/${req.file.filename}` : null; // Save image path
  const hashedPassword = await bcrypt.hash(password, 10);

  const user = new User({ name, email, password: hashedPassword, image });
  try {
    await user.save();
    res.redirect('/login');
  } catch (error) {
    res.render('register', { error: 'User already exists or invalid data.' });
  }
});


// Login
app.get('/login', (req, res) => res.render('login'));
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (user && (await bcrypt.compare(password, user.password))) {
    req.session.userId = user._id;
    res.redirect('/dashboard');
  } else {
    res.render('login', { error: 'Invalid email or password.' });
  }
});

// Dashboard
app.get('/dashboard', isAuthenticated, async (req, res) => {
  const user = await User.findById(req.session.userId);
  res.render('dashboard', { user });
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.redirect('/dashboard');
    }
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

// Start Server
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));