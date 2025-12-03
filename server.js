const express = require("express")
const sqlite3 = require("sqlite3").verbose()
const path = require("path")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const cors = require("cors")
require("dotenv").config()

const app = express()
const PORT = process.env.PORT || 5000
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key_change_in_production"

// Middleware
app.use(cors())
app.use(express.json())
app.use(express.static("public"))

// Database initialization
const db = new sqlite3.Database("./database.db", (err) => {
  if (err) console.error("Database error:", err)
  else console.log("Connected to SQLite database")
  initializeDatabase()
})

function initializeDatabase() {
  db.serialize(() => {
    // Users table
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin', 'staff')),
        department TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `)

    // Staff members table
    db.run(`
      CREATE TABLE IF NOT EXISTS staff_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE,
        designation TEXT,
        phone TEXT,
        specialization TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
      )
    `)

    // Timetable slots
    db.run(`
      CREATE TABLE IF NOT EXISTS timetable (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        staff_id INTEGER NOT NULL,
        day_of_week TEXT NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT NOT NULL,
        subject TEXT,
        room TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(staff_id) REFERENCES staff_members(id)
      )
    `)

    // Leave requests
    db.run(`
      CREATE TABLE IF NOT EXISTS leave_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        staff_id INTEGER NOT NULL,
        start_date DATE NOT NULL,
        end_date DATE NOT NULL,
        reason TEXT,
        status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'rejected')),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(staff_id) REFERENCES staff_members(id)
      )
    `)

    // Attendance
    db.run(`
      CREATE TABLE IF NOT EXISTS attendance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        staff_id INTEGER NOT NULL,
        date DATE NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('present', 'absent', 'leave')),
        remarks TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(staff_id) REFERENCES staff_members(id),
        UNIQUE(staff_id, date)
      )
    `)

    // Replacements (automatic scheduling)
    db.run(`
      CREATE TABLE IF NOT EXISTS replacements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        original_staff_id INTEGER NOT NULL,
        replacement_staff_id INTEGER NOT NULL,
        timetable_id INTEGER NOT NULL,
        replacement_date DATE NOT NULL,
        reason TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(original_staff_id) REFERENCES staff_members(id),
        FOREIGN KEY(replacement_staff_id) REFERENCES staff_members(id),
        FOREIGN KEY(timetable_id) REFERENCES timetable(id)
      )
    `)
  })
}

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"]
  const token = authHeader && authHeader.split(" ")[1]

  if (!token) return res.sendStatus(401)

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403)
    req.user = user
    next()
  })
}

function authorizeRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role && req.user.role !== "admin") {
      return res.status(403).json({ message: "Access denied" })
    }
    next()
  }
}

// Auth Routes
app.post("/api/auth/register", async (req, res) => {
  const { email, password, name, role, department } = req.body

  if (!email || !password || !name || !role) {
    return res.status(400).json({ message: "Missing required fields" })
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10)
    db.run(
      `INSERT INTO users (email, password, name, role, department) VALUES (?, ?, ?, ?, ?)`,
      [email, hashedPassword, name, role, department],
      function (err) {
        if (err) {
          return res.status(400).json({ message: "Email already exists" })
        }
        res.status(201).json({ message: "User registered successfully", userId: this.lastID })
      },
    )
  } catch (error) {
    res.status(500).json({ message: "Registration error", error: error.message })
  }
})

app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body

  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (err || !user) {
      return res.status(400).json({ message: "Invalid email or password" })
    }

    try {
      const validPassword = await bcrypt.compare(password, user.password)
      if (!validPassword) {
        return res.status(400).json({ message: "Invalid email or password" })
      }

      const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, JWT_SECRET, {
        expiresIn: "24h",
      })

      res.json({ token, user: { id: user.id, email: user.email, role: user.role, name: user.name } })
    } catch (error) {
      res.status(500).json({ message: "Login error", error: error.message })
    }
  })
})

// Staff Management Routes
app.post("/api/staff", authenticateToken, authorizeRole("admin"), (req, res) => {
  const { user_id, designation, phone, specialization } = req.body

  db.run(
    `INSERT INTO staff_members (user_id, designation, phone, specialization) VALUES (?, ?, ?, ?)`,
    [user_id, designation, phone, specialization],
    function (err) {
      if (err) {
        return res.status(400).json({ message: "Error adding staff", error: err.message })
      }
      res.status(201).json({ message: "Staff added successfully", staffId: this.lastID })
    },
  )
})

app.get("/api/staff", authenticateToken, (req, res) => {
  db.all(`SELECT sm.*, u.name, u.email FROM staff_members sm JOIN users u ON sm.user_id = u.id`, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ message: "Error fetching staff", error: err.message })
    }
    res.json(rows)
  })
})

// Timetable Routes
app.post("/api/timetable", authenticateToken, authorizeRole("admin"), (req, res) => {
  const { staff_id, day_of_week, start_time, end_time, subject, room } = req.body

  db.run(
    `INSERT INTO timetable (staff_id, day_of_week, start_time, end_time, subject, room) VALUES (?, ?, ?, ?, ?, ?)`,
    [staff_id, day_of_week, start_time, end_time, subject, room],
    function (err) {
      if (err) {
        return res.status(400).json({ message: "Error creating timetable", error: err.message })
      }
      res.status(201).json({ message: "Timetable entry created", id: this.lastID })
    },
  )
})

app.get("/api/timetable/:staffId", authenticateToken, (req, res) => {
  const { staffId } = req.params

  db.all(`SELECT * FROM timetable WHERE staff_id = ?`, [staffId], (err, rows) => {
    if (err) {
      return res.status(500).json({ message: "Error fetching timetable", error: err.message })
    }
    res.json(rows)
  })
})

app.get("/api/timetable-all", authenticateToken, (req, res) => {
  db.all(
    `SELECT t.*, sm.id as staff_id, u.name FROM timetable t JOIN staff_members sm ON t.staff_id = sm.id JOIN users u ON sm.user_id = u.id`,
    [],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ message: "Error fetching timetable", error: err.message })
      }
      res.json(rows)
    },
  )
})

// Leave Routes
app.post("/api/leave", authenticateToken, (req, res) => {
  const { staff_id, start_date, end_date, reason } = req.body

  db.run(
    `INSERT INTO leave_requests (staff_id, start_date, end_date, reason) VALUES (?, ?, ?, ?)`,
    [staff_id, start_date, end_date, reason],
    function (err) {
      if (err) {
        return res.status(400).json({ message: "Error creating leave request", error: err.message })
      }
      res.status(201).json({ message: "Leave request created", id: this.lastID })
    },
  )
})

app.get("/api/leave", authenticateToken, (req, res) => {
  const query =
    req.user.role === "admin"
      ? `SELECT lr.*, u.name FROM leave_requests lr JOIN staff_members sm ON lr.staff_id = sm.id JOIN users u ON sm.user_id = u.id`
      : `SELECT * FROM leave_requests WHERE staff_id = ?`

  const params = req.user.role === "admin" ? [] : [req.user.id]

  db.all(query, params, (err, rows) => {
    if (err) {
      return res.status(500).json({ message: "Error fetching leave requests", error: err.message })
    }
    res.json(rows)
  })
})

app.patch("/api/leave/:id", authenticateToken, authorizeRole("admin"), (req, res) => {
  const { id } = req.params
  const { status } = req.body

  db.run(`UPDATE leave_requests SET status = ? WHERE id = ?`, [status, id], (err) => {
    if (err) {
      return res.status(400).json({ message: "Error updating leave request", error: err.message })
    }
    res.json({ message: "Leave request updated successfully" })
  })
})

// Attendance Routes
app.post("/api/attendance", authenticateToken, (req, res) => {
  const { staff_id, date, status, remarks } = req.body

  db.run(
    `INSERT INTO attendance (staff_id, date, status, remarks) VALUES (?, ?, ?, ?)
     ON CONFLICT(staff_id, date) DO UPDATE SET status = ?, remarks = ?`,
    [staff_id, date, status, remarks, status, remarks],
    (err) => {
      if (err) {
        return res.status(400).json({ message: "Error marking attendance", error: err.message })
      }
      res.json({ message: "Attendance marked successfully" })
    },
  )
})

app.get("/api/attendance/:staffId", authenticateToken, (req, res) => {
  const { staffId } = req.params

  db.all(`SELECT * FROM attendance WHERE staff_id = ?`, [staffId], (err, rows) => {
    if (err) {
      return res.status(500).json({ message: "Error fetching attendance", error: err.message })
    }
    res.json(rows)
  })
})

// Automatic Scheduling - Find replacement
app.post("/api/find-replacement", authenticateToken, authorizeRole("admin"), (req, res) => {
  const { staff_id, date, timetable_id } = req.body

  // Get the original staff's timetable slot
  db.get(`SELECT * FROM timetable WHERE id = ?`, [timetable_id], (err, slot) => {
    if (err) {
      return res.status(500).json({ message: "Error finding replacement", error: err.message })
    }

    // Find available staff
    db.all(
      `SELECT DISTINCT sm.id, u.name FROM staff_members sm 
         JOIN users u ON sm.user_id = u.id 
         WHERE sm.id != ? 
         AND sm.id NOT IN (
           SELECT staff_id FROM leave_requests 
           WHERE status = 'approved' 
           AND start_date <= ? AND end_date >= ?
         )`,
      [staff_id, date, date],
      (err, available_staff) => {
        if (err) {
          return res.status(500).json({ message: "Error finding replacement", error: err.message })
        }
        res.json({ available_staff })
      },
    )
  })
})

// Create replacement
app.post("/api/replacement", authenticateToken, authorizeRole("admin"), (req, res) => {
  const { original_staff_id, replacement_staff_id, timetable_id, replacement_date, reason } = req.body

  db.run(
    `INSERT INTO replacements (original_staff_id, replacement_staff_id, timetable_id, replacement_date, reason) 
     VALUES (?, ?, ?, ?, ?)`,
    [original_staff_id, replacement_staff_id, timetable_id, replacement_date, reason],
    function (err) {
      if (err) {
        return res.status(400).json({ message: "Error creating replacement", error: err.message })
      }
      res.status(201).json({ message: "Replacement scheduled successfully", id: this.lastID })
    },
  )
})

// Get today's schedule
app.get("/api/schedule/today", authenticateToken, (req, res) => {
  const today = new Date().toISOString().split("T")[0]
  const dayName = new Date().toLocaleDateString("en-US", { weekday: "long" })

  db.all(
    `SELECT t.*, sm.id as staff_id, u.name, u.email FROM timetable t 
     JOIN staff_members sm ON t.staff_id = sm.id 
     JOIN users u ON sm.user_id = u.id 
     WHERE t.day_of_week = ?
     AND sm.id NOT IN (
       SELECT staff_id FROM leave_requests 
       WHERE status = 'approved' 
       AND start_date <= ? AND end_date >= ?
     )`,
    [dayName, today, today],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ message: "Error fetching today's schedule", error: err.message })
      }
      res.json(rows)
    },
  )
})

// Get replacements for a date
app.get("/api/replacements/:date", authenticateToken, (req, res) => {
  const { date } = req.params

  db.all(
    `SELECT r.*, u1.name as original_staff, u2.name as replacement_staff FROM replacements r 
     JOIN staff_members sm1 ON r.original_staff_id = sm1.id 
     JOIN users u1 ON sm1.user_id = u1.id 
     JOIN staff_members sm2 ON r.replacement_staff_id = sm2.id 
     JOIN users u2 ON sm2.user_id = u2.id 
     WHERE r.replacement_date = ?`,
    [date],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ message: "Error fetching replacements", error: err.message })
      }
      res.json(rows)
    },
  )
})

// Static files
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"))
})

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`)
})

module.exports = app
