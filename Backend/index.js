const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session');
const flash = require('connect-flash');

const app = express();

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/userDB')
    .then(() => console.log('Connected to MongoDB'))
    .catch((err) => console.error('Failed to connect to MongoDB', err));

// User Schema
const userSchema = new mongoose.Schema({
    fullname: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phone: { type: String, required: true },
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// Middleware to parse form data
app.use(bodyParser.urlencoded({ extended: true }));

// Express session middleware
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: true
}));

// Connect flash middleware
app.use(flash());

// Global variables for flash messages
app.use((req, res, next) => {
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    next();
});

// Set the views directory
app.set('views', path.join(__dirname, 'views'));

// Set the view engine to ejs
app.set('view engine', 'ejs');

// Route for the root URL
app.get("/", (req, res) => {
    res.render("login");
});

// Route for the signup page
app.get("/signup", (req, res) => {
    res.render("signup");
});

// Route to handle signup form submission
app.post("/signup", async (req, res) => {
    const { fullname, email, phone, username, password } = req.body;

    try {
        // Check if user already exists
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            req.flash('error_msg', 'Username already exists');
            return res.redirect('/signup');
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        const newUser = new User({
            fullname,
            email,
            phone,
            username,
            password: hashedPassword
        });

        // Save the user to the database
        await newUser.save();

        req.flash('success_msg', 'Signup successful! Please log in.');
        res.redirect('/');
    } catch (error) {
        console.error(error);
        req.flash('error_msg', 'Error occurred during signup');
        res.redirect('/signup');
    }
});

// Route to handle login form submission
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Find the user by username
        const user = await User.findOne({ username });
        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/');
        }

        // Check if password matches
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            req.flash('error_msg', 'Incorrect password');
            return res.redirect('/');
        }

        req.flash('success_msg', 'Login successful!');
        res.redirect('/dashboard');
    } catch (error) {
        console.error(error);
        req.flash('error_msg', 'Error occurred during login');
        res.redirect('/');
    }
});

// Route for the dashboard after successful login
app.get('/dashboard', (req, res) => {
    res.render('dashboard', { success_msg: req.flash('success_msg') });
});

// Start the server
const port = 5000;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
