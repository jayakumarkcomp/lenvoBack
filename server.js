const express = require('express');
const app = express();
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Connect to the SQLite database
const db = new sqlite3.Database('./levno.db');

// Middleware to parse JSON requests
app.use(express.json());

// Set up authentication middleware
const authenticate = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).send('Access denied');

    try {
        const decoded = jwt.verify(token, 'secretkey');
        req.user = decoded;
        next();
    } catch (ex) {
        res.status(400).send('Invalid token');
    }
};

// Set up role-based access control middleware
const authorize = (roles = []) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).send('Forbidden');
        }
        next();
    };
};

// API Endpoints
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM Users WHERE username = ?', username, (err, user) => {
        if (err || !user) return res.status(400).send('Invalid credentials');
        bcrypt.compare(password, user.password, (err, isValid) => {
            if (err || !isValid) return res.status(400).send('Invalid credentials');
            const token = jwt.sign({ user_id: user.user_id, role: user.role }, 'secretkey');
            res.send(token);
        });
    });
});

app.get('/students', authenticate, authorize(['teacher']), (req, res) => {
    db.all('SELECT * FROM Students', (err, students) => {
        if (err) return res.status(500).send('Internal Server Error');
        res.send(students);
    });
});

app.post('/students', authenticate, authorize(['teacher']), (req, res) => {
    const { name, grade } = req.body;
    db.run('INSERT INTO Students (name, grade, user_id) VALUES (?, ?, ?)', name, grade, req.user.user_id, (err) => {
        if (err) return res.status(500).send('Internal Server Error');
        res.send('Student created successfully');
    });
});

app.put('/students/:student_id', authenticate, authorize(['teacher']), (req, res) => {
    const { student_id } = req.params;
    const { name, grade } = req.body;
    db.run('UPDATE Students SET name = ?, grade = ? WHERE student_id = ?', name, grade, student_id, (err) => {
        if (err) return res.status(500).send('Internal Server Error');
        res.send('Student updated successfully');
    });
});

app.delete('/students/:student_id', authenticate, authorize(['teacher']), (req, res) => {
    const { student_id } = req.params;
    db.run('DELETE FROM Students WHERE student_id = ?', student_id, (err) => {
        if (err) return res.status(500).send('Internal Server Error');
        res.send('Student deleted successfully');
    });
});

// Start the server
const port = 3000;
app.listen(port, () => {
    console.log(`Server started on port ${port}`);

});