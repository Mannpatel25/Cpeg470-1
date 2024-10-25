const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const db = new sqlite3.Database(':memory:'); // In-memory database for development

// Middleware setup
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Set to true if using HTTPS
}));

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));

// Serve the login page when the root is accessed
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Authentication middleware to protect routes
function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        next(); // User is authenticated, proceed to the next middleware/route
    } else {
        res.redirect('/'); // Redirect to the login page if not authenticated
    }
}

// Serve todo.html through a protected route
app.get('/todo', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'todo.html')); // Serve todo.html from the 'views' folder
});

// Create users table
db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT
)`);

// Default user for testing purposes (hardcoded)
const defaultEmail = 'user@gmail.com';
const defaultPassword = 'password';
const hashedPassword = bcrypt.hashSync(defaultPassword, 10); // Encrypt the hardcoded password

// Insert the hardcoded user into the database
db.get(`SELECT * FROM users WHERE email = ?`, [defaultEmail], (err, row) => {
    if (!row) {
        db.run(`INSERT INTO users (email, password) VALUES (?, ?)`, [defaultEmail, hashedPassword], function (err) {
            if (err) {
                console.error('Error creating default user:', err.message);
            } else {
                console.log(`Default user created: Email: ${defaultEmail}, Password: ${defaultPassword}`);
            }
        });
    }
});

// Create todos table
db.run(`CREATE TABLE todos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    description TEXT,
    completed BOOLEAN DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
)`);

// Sign up route
app.post('/signup', (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);

    db.run(`INSERT INTO users (email, password) VALUES (?, ?)`, [email, hashedPassword], function (err) {
        if (err) {
            return res.status(400).json({ message: 'User already exists or invalid data.' });
        }
        res.status(201).json({ message: 'User created successfully. Please login.' });
    });
});

// Login route
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
        if (err || !user || !bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }
        req.session.userId = user.id;  // Set the session userId
        res.status(200).json({ message: 'Login successful.' }); // Send success
    });
});

// Logout route
app.post('/logout', (req, res) => {
    req.session.destroy();
    res.send('Logout successful.');
});

// Get all todos for the logged-in user
app.get('/todos', isAuthenticated, (req, res) => {
    db.all(`SELECT * FROM todos WHERE user_id = ?`, [req.session.userId], (err, rows) => {
        if (err) {
            return res.status(500).send('Error retrieving todos');
        }
        res.json(rows);
    });
});

// Create a new todo for the logged-in user
app.post('/todos', isAuthenticated, (req, res) => {
    const { description } = req.body;

    db.run(`INSERT INTO todos (user_id, description) VALUES (?, ?)`, [req.session.userId, description], function (err) {
        if (err) {
            return res.status(500).send('Error creating todo');
        }
        res.status(201).json({ id: this.lastID, description, completed: false });
    });
});

// Update a todo item (description and/or completed status)
app.put('/todos/:id', isAuthenticated, (req, res) => {
    const todoId = req.params.id;
    const { description, completed } = req.body;

    if (description) {
        db.run(`UPDATE todos SET description = ? WHERE id = ? AND user_id = ?`, [description, todoId, req.session.userId], function (err) {
            if (err || this.changes === 0) {
                return res.status(500).send('Error updating todo or unauthorized access');
            }
            res.send('Todo updated successfully');
        });
    }

    if (completed !== undefined) {
        db.run(`UPDATE todos SET completed = ? WHERE id = ? AND user_id = ?`, [completed, todoId, req.session.userId], function (err) {
            if (err || this.changes === 0) {
                return res.status(500).send('Error updating todo or unauthorized access');
            }
            res.send('Todo updated successfully');
        });
    }
});

// Delete a todo item
app.delete('/todos/:id', isAuthenticated, (req, res) => {
    const todoId = req.params.id;

    db.run(`DELETE FROM todos WHERE id = ? AND user_id = ?`, [todoId, req.session.userId], function (err) {
        if (err || this.changes === 0) {
            return res.status(500).send('Error deleting todo or unauthorized access');
        }
        res.send('Todo deleted successfully');
    });
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
