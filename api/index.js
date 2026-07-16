/**
 * SmartGrades API Server
 * Express + PostgreSQL (Neon) + JWT Auth
 */

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

// ─── Config ──────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'smartgrades-jwt-secret-2026';
const SALT_ROUNDS = 10;

const app = express();

// ─── Database ────────────────────────────────────────────────────────────────

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('neon')
    ? { rejectUnauthorized: false }
    : false,
});

// Auto-migrate: create tables on startup
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS students (
        id text PRIMARY KEY,
        name text NOT NULL,
        school text NOT NULL,
        username text NOT NULL UNIQUE,
        password text DEFAULT '',
        mfa text DEFAULT '',
        created_at timestamptz DEFAULT now(),
        updated_at timestamptz DEFAULT now()
      );
      CREATE TABLE IF NOT EXISTS grades (
        id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        student_id text NOT NULL REFERENCES students(id) ON DELETE CASCADE,
        eval_name text NOT NULL,
        course text NOT NULL,
        teacher text DEFAULT '',
        period text DEFAULT '',
        eval_date text DEFAULT '',
        grade_value real,
        grade_type text DEFAULT 'text',
        grade_display text DEFAULT '',
        color text DEFAULT 'steel',
        does_count boolean DEFAULT true,
        fetched_at timestamptz DEFAULT now()
      );
      CREATE TABLE IF NOT EXISTS users (
        id text PRIMARY KEY,
        email text NOT NULL UNIQUE,
        password_hash text NOT NULL,
        display_name text DEFAULT '',
        role text DEFAULT 'viewer',
        linked_student_id text REFERENCES students(id) ON DELETE SET NULL,
        created_at timestamptz DEFAULT now()
      );
      CREATE TABLE IF NOT EXISTS user_students (
        user_id text NOT NULL,
        student_id text NOT NULL REFERENCES students(id) ON DELETE CASCADE,
        created_at timestamptz DEFAULT now(),
        PRIMARY KEY (user_id, student_id)
      );
      CREATE INDEX IF NOT EXISTS idx_grades_student ON grades(student_id);
      CREATE INDEX IF NOT EXISTS idx_grades_course ON grades(course);
      CREATE INDEX IF NOT EXISTS idx_us_user ON user_students(user_id);
      CREATE INDEX IF NOT EXISTS idx_us_student ON user_students(student_id);

      CREATE TABLE IF NOT EXISTS reports (
        id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        student_id text NOT NULL REFERENCES students(id) ON DELETE CASCADE,
        report_name text NOT NULL,
        school_year text DEFAULT '',
        report_date text DEFAULT '',
        pdf_url text DEFAULT '',
        fetched_at timestamptz DEFAULT now()
      );
      CREATE INDEX IF NOT EXISTS idx_reports_student ON reports(student_id);
    `);
    console.log('✅ Database tables initialized');
  } catch (e) {
    console.error('❌ DB init error:', e.message);
  } finally {
    client.release();
  }
}

initDB();

// ─── Middleware ───────────────────────────────────────────────────────────────

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static frontend files
app.use(express.static(path.join(__dirname, 'public')));

// ─── Auth Middleware ──────────────────────────────────────────────────────────

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.slice(7);
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function generateId() {
  return crypto.randomUUID();
}

function signToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role, display_name: user.display_name },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// ─── Routes: Auth ─────────────────────────────────────────────────────────────

/**
 * POST /api/register
 * Body: { email, password, name }
 * Creates a new user and returns a JWT.
 */
app.post('/api/register', async (req, res) => {
  const { username, password, name } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'username et password sont obligatoires' });
  }

  if (password.length < 4) {
    return res.status(400).json({ error: 'Mot de passe trop court (min 4 caractères)' });
  }

  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [username.toLowerCase()]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'Ce pseudo est déjà pris' });
    }

    const id = generateId();
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const displayName = name || username;

    await pool.query(
      `INSERT INTO users (id, email, password_hash, display_name, role, created_at)
       VALUES ($1, $2, $3, $4, 'viewer', NOW())`,
      [id, username.toLowerCase(), passwordHash, displayName]
    );

    const user = { id, email: username.toLowerCase(), display_name: displayName, role: 'viewer' };
    const token = signToken(user);

    return res.status(201).json({ token, user });
  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/login
 * Body: { email, password }
 * Returns a JWT and user info.
 */
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Pseudo et mot de passe obligatoires' });
  }

  try {
    const result = await pool.query(
      'SELECT id, email, password_hash, display_name, role FROM users WHERE email = $1',
      [username.toLowerCase()]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Pseudo ou mot de passe incorrect' });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      return res.status(401).json({ error: 'Pseudo ou mot de passe incorrect' });
    }

    const token = signToken(user);
    const { password_hash, ...safeUser } = user;

    return res.json({ token, user: safeUser });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /api/me
 * Returns the current authenticated user's profile.
 */
app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, display_name, role, created_at FROM users WHERE id = $1',
      [req.user.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    return res.json(result.rows[0]);
  } catch (err) {
    console.error('Me error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── Routes: Students ─────────────────────────────────────────────────────────

/**
 * GET /api/students
 * Returns students linked to the authenticated user (via user_students).
 */
app.get('/api/students', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT s.id, s.name, s.school, s.username, us.created_at AS linked_at
       FROM students s
       INNER JOIN user_students us ON us.student_id = s.id
       WHERE us.user_id = $1
       ORDER BY s.name`,
      [req.user.id]
    );
    return res.json(result.rows);
  } catch (err) {
    console.error('Get students error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /api/students/search?q=...
 * Search available students (all students in DB) so users can link them.
 */
app.get('/api/students/search', requireAuth, async (req, res) => {
  const q = (req.query.q || '').trim();
  if (q.length < 2) {
    return res.json([]);
  }

  try {
    const result = await pool.query(
      `SELECT id, name, school, username
       FROM students
       WHERE name ILIKE $1 OR username ILIKE $1 OR school ILIKE $1
       LIMIT 20`,
      [`%${q}%`]
    );
    return res.json(result.rows);
  } catch (err) {
    console.error('Search students error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/students
 * Body: { student_id }
 * Links an existing student to the authenticated user.
 */
app.post('/api/students', requireAuth, async (req, res) => {
  const { student_id } = req.body;
  if (!student_id) {
    return res.status(400).json({ error: 'student_id is required' });
  }

  try {
    // Check the student exists
    const studentResult = await pool.query('SELECT id, name, school FROM students WHERE id = $1', [student_id]);
    if (studentResult.rows.length === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }

    // Check not already linked
    const linkCheck = await pool.query(
      'SELECT 1 FROM user_students WHERE user_id = $1 AND student_id = $2',
      [req.user.id, student_id]
    );
    if (linkCheck.rows.length > 0) {
      return res.status(409).json({ error: 'Student already linked to your account' });
    }

    await pool.query(
      'INSERT INTO user_students (user_id, student_id, created_at) VALUES ($1, $2, NOW())',
      [req.user.id, student_id]
    );

    return res.status(201).json({ message: 'Student linked successfully', student: studentResult.rows[0] });
  } catch (err) {
    console.error('Link student error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * DELETE /api/students/:id
 * Unlinks a student from the authenticated user.
 */
app.delete('/api/students/:id', requireAuth, async (req, res) => {
  const studentId = req.params.id;

  try {
    const result = await pool.query(
      'DELETE FROM user_students WHERE user_id = $1 AND student_id = $2 RETURNING student_id',
      [req.user.id, studentId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Student not linked to your account' });
    }

    return res.json({ message: 'Student unlinked successfully' });
  } catch (err) {
    console.error('Unlink student error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── Routes: Grades ───────────────────────────────────────────────────────────

/**
 * GET /api/grades/:studentId
 * Returns grades for a specific student — only if the student is linked to the user.
 * Query params: period, course, search
 */
app.get('/api/grades/:studentId', requireAuth, async (req, res) => {
  const { studentId } = req.params;

  try {
    // Verify the student is linked to this user
    const linkCheck = await pool.query(
      'SELECT 1 FROM user_students WHERE user_id = $1 AND student_id = $2',
      [req.user.id, studentId]
    );
    if (linkCheck.rows.length === 0) {
      return res.status(403).json({ error: 'Access denied: student not linked to your account' });
    }

    let query = `
      SELECT id, student_id, eval_name, course, teacher, period,
             eval_date, grade_value, grade_type, grade_display,
             color, does_count, fetched_at
      FROM grades
      WHERE student_id = $1
    `;
    const params = [studentId];
    let paramIdx = 2;

    if (req.query.period) {
      query += ` AND period = $${paramIdx++}`;
      params.push(req.query.period);
    }

    if (req.query.course) {
      query += ` AND course = $${paramIdx++}`;
      params.push(req.query.course);
    }

    if (req.query.search) {
      query += ` AND (eval_name ILIKE $${paramIdx} OR course ILIKE $${paramIdx} OR teacher ILIKE $${paramIdx})`;
      params.push(`%${req.query.search}%`);
      paramIdx++;
    }

    query += ' ORDER BY eval_date DESC, id DESC';

    const result = await pool.query(query, params);
    return res.json(result.rows);
  } catch (err) {
    console.error('Get grades error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /api/grades/:studentId/summary
 * Returns aggregated summary: average per course, per period.
 */
app.get('/api/grades/:studentId/summary', requireAuth, async (req, res) => {
  const { studentId } = req.params;

  try {
    const linkCheck = await pool.query(
      'SELECT 1 FROM user_students WHERE user_id = $1 AND student_id = $2',
      [req.user.id, studentId]
    );
    if (linkCheck.rows.length === 0) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const byCourse = await pool.query(
      `SELECT course,
              ROUND(AVG(grade_value)::numeric, 2) AS average,
              COUNT(*) AS count,
              MIN(grade_value) AS min,
              MAX(grade_value) AS max
       FROM grades
       WHERE student_id = $1 AND does_count = true AND grade_value IS NOT NULL
       GROUP BY course
       ORDER BY average DESC`,
      [studentId]
    );

    const byPeriod = await pool.query(
      `SELECT period,
              ROUND(AVG(grade_value)::numeric, 2) AS average,
              COUNT(*) AS count
       FROM grades
       WHERE student_id = $1 AND does_count = true AND grade_value IS NOT NULL
       GROUP BY period
       ORDER BY period`,
      [studentId]
    );

    const overall = await pool.query(
      `SELECT ROUND(AVG(grade_value)::numeric, 2) AS average, COUNT(*) AS count
       FROM grades
       WHERE student_id = $1 AND does_count = true AND grade_value IS NOT NULL`,
      [studentId]
    );

    const periods = await pool.query(
      `SELECT DISTINCT period FROM grades WHERE student_id = $1 ORDER BY period`,
      [studentId]
    );

    const courses = await pool.query(
      `SELECT DISTINCT course FROM grades WHERE student_id = $1 ORDER BY course`,
      [studentId]
    );

    return res.json({
      overall: overall.rows[0],
      by_course: byCourse.rows,
      by_period: byPeriod.rows,
      periods: periods.rows.map(r => r.period),
      courses: courses.rows.map(r => r.course),
    });
  } catch (err) {
    console.error('Grades summary error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── Routes: Overview ─────────────────────────────────────────────────────────

/**
 * GET /api/overview
 * Returns overview data for all students linked to the authenticated user.
 */
app.get('/api/overview', requireAuth, async (req, res) => {
  try {
    // Get all linked students with their aggregated grade data
    const result = await pool.query(
      `SELECT
         s.id,
         s.name,
         s.school,
         s.username,
         ROUND(AVG(g.grade_value)::numeric, 2) AS average,
         COUNT(g.id) AS total_grades,
         COUNT(DISTINCT g.course) AS total_courses,
         MAX(g.fetched_at) AS last_updated
       FROM students s
       INNER JOIN user_students us ON us.student_id = s.id
       LEFT JOIN grades g ON g.student_id = s.id AND g.does_count = true AND g.grade_value IS NOT NULL
       WHERE us.user_id = $1
       GROUP BY s.id, s.name, s.school, s.username
       ORDER BY s.name`,
      [req.user.id]
    );

    // For each student, also get course breakdown
    const studentsWithDetails = await Promise.all(
      result.rows.map(async (student) => {
        const courses = await pool.query(
          `SELECT course,
                  ROUND(AVG(grade_value)::numeric, 2) AS average,
                  COUNT(*) AS count
           FROM grades
           WHERE student_id = $1 AND does_count = true AND grade_value IS NOT NULL
           GROUP BY course
           ORDER BY average DESC`,
          [student.id]
        );
        return { ...student, courses: courses.rows };
      })
    );

    return res.json(studentsWithDetails);
  } catch (err) {
    console.error('Overview error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── Catch-all: serve SPA ─────────────────────────────────────────────────────

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Link student by credentials ────────────────────────────────────────────

app.post('/api/students/link-by-creds', requireAuth, async (req, res) => {
  try {
    const { school, firstname, username, password, dob } = req.body;
    if (!firstname || !username || !password || !dob) {
      return res.status(400).json({ error: 'Tous les champs sont obligatoires' });
    }

    // Find student matching the credentials (optionally filtered by school)
    let query = 'SELECT id, name, school, username, mfa, password FROM students WHERE LOWER(username) = LOWER($1)';
    let params = [username];
    if (school) {
      query += ' AND LOWER(school) = LOWER($2)';
      params.push(school);
    }
    const student = await pool.query(query, params);

    if (!student.rows.length) return res.status(404).json({ error: 'Élève non trouvé avec cet identifiant' });

    const s = student.rows[0];

    // Verify password
    if (s.username !== username || (student.rows[0].password && student.rows[0].password !== password)) {
      // Try matching password from the row
      const fullStudent = await pool.query('SELECT password FROM students WHERE id = $1', [s.id]);
      if (fullStudent.rows[0]?.password !== password) {
        return res.status(403).json({ error: 'Mot de passe incorrect' });
      }
    }

    // Verify firstname (case-insensitive match against the name field)
    if (!s.name.toLowerCase().includes(firstname.toLowerCase())) {
      return res.status(403).json({ error: 'Le prénom ne correspond pas' });
    }

    // Verify DOB (mfa field stores YYYY-MM-DD)
    if (s.mfa && s.mfa !== dob) {
      return res.status(403).json({ error: 'La date de naissance ne correspond pas' });
    }

    // All checks passed — link the student
    await pool.query(
      'INSERT INTO user_students (user_id, student_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [req.user.id, s.id]
    );

    res.json({ success: true, student: { id: s.id, name: s.name, school: s.school } });
  } catch (e) {
    console.error('Link by creds error:', e);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─── Reports (bulletins PDF) ──────────────────────────────────────────────────

app.get('/api/reports/:studentId', requireAuth, async (req, res) => {
  try {
    const link = await pool.query(
      'SELECT 1 FROM user_students WHERE user_id = $1 AND student_id = $2',
      [req.user.id, req.params.studentId]
    );
    if (req.user.role !== 'admin' && !link.rows.length) {
      return res.status(403).json({ error: 'Non autorisé' });
    }
    const result = await pool.query(
      'SELECT id, report_name, school_year, report_date, pdf_url FROM reports WHERE student_id = $1 ORDER BY report_date DESC',
      [req.params.studentId]
    );
    res.json(result.rows);
  } catch (e) {
    console.error('Reports error:', e);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─── Sync status ──────────────────────────────────────────────────────────────
// Grades are synced automatically every 2 hours via a cron job on the Moxt platform.
// The fetch endpoints below report the last sync time.

app.get('/api/sync-status', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT student_id, MAX(fetched_at) as last_sync FROM grades g
       INNER JOIN user_students us ON us.student_id = g.student_id AND us.user_id = $1
       GROUP BY student_id`,
      [req.user.id]
    );
    res.json({ synced: true, students: result.rows });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────

// For Vercel serverless: export the app
// For local dev: start the server
if (process.env.VERCEL) {
  module.exports = app;
} else {
  app.listen(PORT, () => {
    console.log(`🚀 SmartGrades API running on http://localhost:${PORT}`);
    console.log(`   DATABASE_URL: ${process.env.DATABASE_URL ? '✅ set' : '❌ NOT SET'}`);
  });
}
