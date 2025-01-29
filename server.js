require('dotenv').config();

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const app = express();
const os = require('os');
const PORT = 3000;

app.use(express.json());

const db = new sqlite3.Database('./database.db');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS tbl_users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, email TEXT UNIQUE, hashed_pass TEXT)`);
  db.run(`CREATE TABLE IF NOT EXISTS tbl_expenses (id INTEGER PRIMARY KEY, user_id INTEGER, amount DECIMAL, category TEXT, date DATE, notes TEXT, FOREIGN KEY (user_id) REFERENCES tbl_users(ID))`);
});


app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;
    try {
        const hashedPass = await bcrypt.hash(password, 10);
        db.run(
          `INSERT INTO tbl_users (username, email, hashed_pass) VALUES (?, ?, ?)`,
          [username, email, hashedPass],
          (err) => {
            if (err) {
              if (err.message.includes("UNIQUE")) {
                res.status(400).json({ error: "Username or email already exists" });
              } else {
                res.status(500).json({ error: "Internal server error" });
              }
            } else {
              res.status(201).json({ message: "User created successfully" });
            }
          }
        );
      } catch (error) {
        res
          .status(500)
          .json({ error: 'An unexpected error occurred', details: error.message });
      }
  });
app.post('/login', (req, res)=>{
    const {email, password} = req.body;
    db.get('SELECT * FROM tbl_users WHERE email = ?', [email], async (err, user) => {
    if (!user || !(await bcrypt.compare(password, user.hashed_pass))) {
      return res.status(400).json( {error: 'Invalid credentials'});
    }

    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '7d' });
    const refreshToken = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '30d' } 
    );
    res.json({ token, refreshToken });
    })
});
app.get('/profile', authenticateJWT, (req, res) =>{
const userId = req.user.id;

db.get('SELECT id, username, email FROM tbl_users WHERE id = ?', [userId], (err, user)=>{
  if (!user) return res.status(404).json({ error: 'User not found' });
  if(err) return res.status(500).json({error : 'Error fetch user information of user'});
  res.json({id: user.id,username: user.username, email: user.email});
})
});
app.post('/refresh-token', (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ error: 'No refresh token provided' });
  }

  // console.log("Received Refresh Token:", refreshToken);

  jwt.verify(refreshToken, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(403).json({ error: 'Token expired. Please log in again.' });
      }
      return res.status(403).json({ error: 'Invalid or expired refresh token' });
    }

    // console.log("User after token verification:", user);

    const newAccessToken = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    const newRefreshToken = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({ token: newAccessToken, refreshToken: newRefreshToken });
  });
});




function authenticateJWT (req, res, next) {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.status(403).send('No token provided.');
  
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return res.status(403).send('Invalid token.');
      req.user = user;
      next();
    });
  };


app.get('/expenses', authenticateJWT, (req, res) => {
    db.all('SELECT * FROM tbl_expenses WHERE user_id = ?', [req.user.id], (err, rows) => {
      if (err) return res.status(500).send('Error fetching expenses');
      res.json(rows);
    });
  });
  
app.post('/expenses', authenticateJWT, (req, res) => {
    const { amount, category, date, notes } = req.body;
    db.run('INSERT INTO tbl_expenses (user_id, amount, category, date, notes) VALUES (?, ?, ?, ?, ?)', [req.user.id, amount, category, date, notes], function(err) {
      if (err) return res.status(500).send('Error adding expense');
      res.status(201).json({ success: 'Successfully added expense',id: this.lastID });
    });
});
  
function getLocalIPAddress() {
    const interfaces = os.networkInterfaces();
    for (const iface in interfaces) {
      for (const details of interfaces[iface]) {
        if (details.family === 'IPv4' && !details.internal) {
          return details.address;
        }
      }
    }
    return '127.0.0.1';
}

app.listen(PORT, '0.0.0.0', () => {
    const localIP = getLocalIPAddress();
    console.log(`Server is running on:`);
    console.log(`- Local: http://localhost:${PORT}`);
    console.log(`- Network: http://${localIP}:${PORT}`);
});
  

