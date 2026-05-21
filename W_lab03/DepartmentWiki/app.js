const express = require('express');
const path = require('path');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;
const FLAG = process.env.FLAG || 'offsec{test_flag}';
const DB_PATH = process.env.DB_PATH || ':memory:';

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
/* The problem here is that "classical" SQL injection don't work since
 the search execute the following safe pre-prepared query and not the one
 that i inject.

 But we can "trigger" the execution by insert a new 
 
 
 */



db.exec(`
  CREATE TABLE IF NOT EXISTS departments (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    name  TEXT NOT NULL,
    icon  TEXT NOT NULL DEFAULT ''
  );

  CREATE TABLE IF NOT EXISTS articles (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    department_id INTEGER NOT NULL,
    title         TEXT NOT NULL,
    slug          TEXT UNIQUE NOT NULL,
    content       TEXT NOT NULL,
    author        TEXT NOT NULL,
    updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (department_id) REFERENCES departments(id)
  );

  CREATE TABLE IF NOT EXISTS revision_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id INTEGER NOT NULL,
    edited_by  TEXT NOT NULL,
    summary    TEXT NOT NULL,
    logged_at  TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (article_id) REFERENCES articles(id)
  );

  CREATE TABLE IF NOT EXISTS internal_config (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    key   TEXT UNIQUE NOT NULL,
    value TEXT NOT NULL
  );
`);

const configCount = db.prepare('SELECT COUNT(*) as c FROM internal_config').get().c;
if (configCount === 0) {
  const insConfig = db.prepare('INSERT INTO internal_config (key, value) VALUES (?, ?)');
  insConfig.run('site_name', 'Department Wiki');
  insConfig.run('maintenance_mode', 'false');
  insConfig.run('admin_token', FLAG);
  insConfig.run('max_upload_size', '10485760');
  insConfig.run('analytics_id', 'UA-XXXXXXXX-1');
}

const deptCount = db.prepare('SELECT COUNT(*) as c FROM departments').get().c;
if (deptCount === 0) {
  const departments = [
    { name: 'Computer Science', icon: '\u{1F4BB}' },
    { name: 'Mathematics',      icon: '\u{1F4D0}' },
    { name: 'Physics',          icon: '\u{269B}' },
    { name: 'Electronics',      icon: '\u{1F50C}' },
    { name: 'Civil Engineering', icon: '\u{1F3D7}' },
  ];

  const insDept = db.prepare('INSERT INTO departments (name, icon) VALUES (?, ?)');
  for (const d of departments) insDept.run(d.name, d.icon);

  const articles = [
    { dept: 1, title: 'Introduction to Algorithms', slug: 'intro-algorithms', content: 'This article covers the fundamentals of algorithm design and analysis. Topics include asymptotic notation, divide-and-conquer strategies, dynamic programming, and graph algorithms.\n\nStudents should be familiar with basic data structures before proceeding. The department recommends completing the Data Structures prerequisite course first.\n\nKey concepts: Big-O notation, recurrence relations, greedy algorithms, NP-completeness.', author: 'Prof. Rossi' },
    { dept: 1, title: 'Operating Systems Overview', slug: 'os-overview', content: 'Modern operating systems manage hardware resources and provide services to applications. This article discusses process scheduling, memory management, file systems, and I/O handling.\n\nThe Linux kernel serves as our primary case study. Lab exercises use a custom kernel module to demonstrate scheduling policies.\n\nPrerequisites: Computer Architecture, C Programming.', author: 'Prof. Bianchi' },
    { dept: 1, title: 'Database Systems', slug: 'database-systems', content: 'Relational database management systems form the backbone of most enterprise applications. This article covers the relational model, SQL, normalization theory, transaction processing, and query optimization.\n\nLab work uses PostgreSQL. Students will design and implement a complete database for a real-world scenario.\n\nTopics: ER diagrams, functional dependencies, ACID properties, indexing strategies.', author: 'Prof. Rossi' },
    { dept: 1, title: 'Computer Networks', slug: 'computer-networks', content: 'This article provides a comprehensive overview of computer networking from the physical layer to the application layer. We follow the TCP/IP model and examine protocols at each layer.\n\nLab sessions involve packet capture with Wireshark and socket programming in Python.\n\nTopics: Ethernet, IP addressing, TCP/UDP, DNS, HTTP, network security basics.', author: 'Prof. Esposito' },
    { dept: 2, title: 'Linear Algebra Essentials', slug: 'linear-algebra', content: 'Linear algebra is the study of vector spaces and linear mappings between them. This article covers vector spaces, matrices, determinants, eigenvalues, and diagonalization.\n\nApplications in computer graphics, machine learning, and signal processing are discussed. Weekly problem sets are mandatory.\n\nKey topics: Gaussian elimination, orthogonality, SVD, least squares.', author: 'Prof. Conti' },
    { dept: 2, title: 'Calculus II: Integration', slug: 'calculus-integration', content: 'Building on Calculus I, this article explores techniques of integration, improper integrals, sequences and series, and an introduction to multivariable calculus.\n\nStudents should have a solid grasp of differentiation and limits. Office hours are available Tuesdays and Thursdays.\n\nTopics: Integration by parts, Taylor series, convergence tests, partial derivatives.', author: 'Prof. Ferrara' },
    { dept: 3, title: 'Classical Mechanics', slug: 'classical-mechanics', content: 'This article covers Newtonian mechanics, Lagrangian and Hamiltonian formulations, oscillations, and rigid body dynamics.\n\nLab experiments include pendulum analysis, collision dynamics, and rotational motion measurements.\n\nPrerequisites: Calculus I, Linear Algebra. Textbook: Goldstein, Classical Mechanics.', author: 'Prof. Verdi' },
    { dept: 3, title: 'Electromagnetism', slug: 'electromagnetism', content: 'Maxwell\'s equations unify electricity and magnetism into a single framework. This article covers electrostatics, magnetostatics, electromagnetic waves, and optics.\n\nLab work involves building simple circuits, measuring magnetic fields, and observing diffraction patterns.\n\nTopics: Gauss\'s law, Faraday\'s law, wave propagation, polarization.', author: 'Prof. Verdi' },
    { dept: 4, title: 'Digital Electronics', slug: 'digital-electronics', content: 'Digital electronics is the foundation of modern computing hardware. This article covers Boolean algebra, logic gates, combinational and sequential circuits, and an introduction to FPGA design.\n\nLab exercises use Verilog HDL and Xilinx development boards. Students will implement a simple processor by the end of the course.\n\nTopics: Karnaugh maps, flip-flops, counters, state machines, FPGA synthesis.', author: 'Prof. Moretti' },
    { dept: 4, title: 'Signal Processing', slug: 'signal-processing', content: 'Signal processing transforms and analyzes signals in both time and frequency domains. This article covers Fourier analysis, filtering, sampling theory, and digital signal processing.\n\nMATLAB is used extensively in lab sessions. Real-world applications include audio processing and communications.\n\nTopics: DFT, FFT, FIR/IIR filters, z-transform, spectral analysis.', author: 'Prof. Gallo' },
    { dept: 5, title: 'Structural Analysis', slug: 'structural-analysis', content: 'Structural analysis determines the effects of loads on physical structures. This article covers equilibrium, trusses, beams, frames, and influence lines.\n\nSoftware tools like SAP2000 are introduced for computational analysis. Field visits to construction sites supplement the coursework.\n\nTopics: Method of joints, moment distribution, virtual work, matrix methods.', author: 'Prof. Romano' },
    { dept: 5, title: 'Geotechnical Engineering', slug: 'geotechnical-engineering', content: 'Geotechnical engineering deals with soil and rock mechanics. This article covers soil classification, permeability, consolidation, shear strength, and foundation design.\n\nLab work includes triaxial testing, direct shear tests, and site investigation planning.\n\nTopics: Mohr-Coulomb criterion, bearing capacity, retaining walls, slope stability.', author: 'Prof. Romano' },
  ];

  const insArt = db.prepare('INSERT INTO articles (department_id, title, slug, content, author) VALUES (?, ?, ?, ?, ?)');
  for (const a of articles) insArt.run(a.dept, a.title, a.slug, a.content, a.author);

  const revisions = [
    { article_id: 1, edited_by: 'Prof. Rossi',    summary: 'Added section on amortized analysis' },
    { article_id: 1, edited_by: 'T.A. Marchetti',  summary: 'Fixed typo in complexity table' },
    { article_id: 3, edited_by: 'Prof. Rossi',    summary: 'Updated lab instructions for PostgreSQL 16' },
    { article_id: 5, edited_by: 'Prof. Conti',    summary: 'Added SVD application examples' },
    { article_id: 7, edited_by: 'Prof. Verdi',    summary: 'Reformatted Lagrangian section' },
    { article_id: 9, edited_by: 'Prof. Moretti',  summary: 'Added Verilog code samples' },
    { article_id: 9, edited_by: 'T.A. Fontana',   summary: 'Corrected flip-flop timing diagrams' },
    { article_id: 11, edited_by: 'Prof. Romano',  summary: 'Updated load factor tables to Eurocode' },
  ];

  const insRev = db.prepare('INSERT INTO revision_log (article_id, edited_by, summary) VALUES (?, ?, ?)');
  for (const r of revisions) insRev.run(r.article_id, r.edited_by, r.summary);
}

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));
app.use(express.static(path.join(__dirname, '..', 'public')));
app.use(express.urlencoded({ extended: false }));

app.get('/', (req, res) => {
  const departments = db.prepare(`
    SELECT d.*, COUNT(a.id) as article_count
    FROM departments d LEFT JOIN articles a ON d.id = a.department_id
    GROUP BY d.id ORDER BY d.name
  `).all();
  const recent = db.prepare(`
    SELECT a.slug, a.title, a.author, a.updated_at, d.name as dept_name, d.icon as dept_icon
    FROM articles a JOIN departments d ON a.department_id = d.id
    ORDER BY a.updated_at DESC LIMIT 5
  `).all();
  res.render('index', { departments, recent });
});

app.get('/department/:id', (req, res) => {
  const dept = db.prepare('SELECT * FROM departments WHERE id = ?').get(req.params.id);
  if (!dept) return res.status(404).render('404');
  const articles = db.prepare(
    'SELECT * FROM articles WHERE department_id = ? ORDER BY title'
  ).all(dept.id);
  res.render('department', { dept, articles });
});

app.get('/article/:slug', (req, res) => {
  const article = db.prepare(
    'SELECT a.*, d.name as dept_name, d.icon as dept_icon, d.id as dept_id FROM articles a JOIN departments d ON a.department_id = d.id WHERE a.slug = ?'
  ).get(req.params.slug);
  if (!article) return res.status(404).render('404');
  const revisions = db.prepare(
    'SELECT * FROM revision_log WHERE article_id = ? ORDER BY logged_at DESC'
  ).all(article.id);
  res.render('article', { article, revisions });
});

app.get('/search', (req, res) => {
  const q = req.query.q || ''; 
  if (!q.trim()) {
    return res.render('search', { results: null, error: null, query: q });
  }

  try {
    const sql = "SELECT a.slug, a.title, a.author, a.updated_at, d.name as dept_name, d.icon as dept_icon FROM articles a JOIN departments d ON a.department_id = d.id WHERE a.title LIKE '%" + q + "%' OR a.content LIKE '%" + q + "%' ORDER BY a.updated_at DESC";
    db.exec(sql);  /*Here the injected query is executed, but NOT SHOWED*/
    const results = db.prepare(/* The problem here is that "classical" SQL injection don't work since
                                   the search show the following safe pre-prepared query and not the one
                                   that i inject.*/
      "SELECT a.slug, a.title, a.author, a.updated_at, d.name as dept_name, d.icon as dept_icon FROM articles a JOIN departments d ON a.department_id = d.id WHERE a.title LIKE ? OR a.content LIKE ? ORDER BY a.updated_at DESC"
    ).all('%' + q + '%', '%' + q + '%');
    res.render('search', { results, error: null, query: q });
  } catch (err) {
    res.render('search', { results: null, error: err.message, query: q });
  }
});

app.get('/revisions', (req, res) => {
  const revisions = db.prepare(`
    SELECT r.*, a.title as article_title, a.slug as article_slug
    FROM revision_log r JOIN articles a ON r.article_id = a.id
    ORDER BY r.logged_at DESC LIMIT 20
  `).all();
  res.render('revisions', { revisions });
});

app.use((req, res) => {
  res.status(404).render('404');
});

app.listen(PORT, () => {
  console.log(`Department Wiki running on http://localhost:${PORT}`);
});
