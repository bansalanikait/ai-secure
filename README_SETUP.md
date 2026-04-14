# AI-Secure: Security Vulnerability Scanner

**An intelligent, AI-powered security scanner for code analysis, GitHub repositories, and web applications.**

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
5. [Setup MongoDB](#setup-mongodb)
6. [Configuration (.env)](#configuration-env)
7. [Running the Application](#running-the-application)
8. [How to Use](#how-to-use)
9. [Project Structure](#project-structure)
10. [Troubleshooting](#troubleshooting)

---

## 🎯 Overview

**AI-Secure** is a comprehensive security analysis tool that:
- Scans code files for security vulnerabilities
- Analyzes GitHub repositories automatically
- Crawls and fuzzes web applications
- Uses AI (OpenAI) to explain vulnerabilities
- Generates detailed security reports in PDF format
- Stores all scans in MongoDB for history tracking

**Python Version Required:** 3.13.9

---

## ✨ Features

✅ **File Scanning** - Upload and scan Python, JavaScript, TypeScript files for vulnerabilities  
✅ **GitHub Repository Scanning** - Analyze entire repositories from GitHub URLs  
✅ **Web Crawling & Fuzzing** - Discover vulnerabilities in web applications  
✅ **AI Explanations** - Get detailed vulnerability explanations powered by OpenAI  
✅ **PDF Reports** - Download comprehensive security reports  
✅ **Scan History** - View all past scans stored in MongoDB  
✅ **Security Scoring** - Get grades (A-F) based on security posture  
✅ **OWASP & CWE Mapping** - Vulnerabilities mapped to industry standards  

---

## 📦 Prerequisites

Make sure you have:
- **Python 3.13.9** installed
- **Git** (for GitHub repo scanning)
- **MongoDB** (local or cloud)
- **OpenAI API Key** (optional, for AI explanations)

---

## 🔧 Installation

### Step 1: Clone/Navigate to Project
```bash
cd ai-secure
```

### Step 2: Create and Activate Virtual Environment
```powershell
# Create virtual environment
python -m venv myenv

# Activate it
myenv\Scripts\Activate.ps1
```

### Step 3: Install Dependencies
```bash
pip install -r requirement.txt
```

---

## 🗄️ Setup MongoDB

### **Option 1: Local MongoDB (Easier for Development)**

#### Windows Installation:
1. Download: https://www.mongodb.com/try/download/community
2. Run the **MSI installer**
3. Choose "Complete" installation
4. MongoDB will start as a Windows Service automatically

#### Verify Installation:
```powershell
# Check if MongoDB is running
Get-Service -Name MongoDB

# Should return: "Running"
```

#### Connection String (Local):
```
mongodb://localhost:27017
```

---

### **Option 2: MongoDB Atlas (Cloud - Recommended)**

#### Setup Steps:
1. Go to: https://cloud.mongodb.com
2. Click **Sign Up** (free tier available)
3. Create a cluster (takes ~5 minutes)
4. Go to **Network Access** → Add your IP (or 0.0.0.0/0 for development)
5. Click **Connect** → Select **Drivers** → Copy connection string

#### Connection String Example:
```
mongodb+srv://username:password@cluster0.xyz.mongodb.net/?retryWrites=true&w=majority
```

**⚠️ Important:** If your password contains special characters like `@`, encode them:
- `@` → `%40`
- `!` → `%21`
- `#` → `%23`

Example: `password@123` becomes `password%40123`

---

## ⚙️ Configuration (.env)

### Create `.env` File

Create a file named `.env` in the project root directory:

```
# MongoDB Connection String (choose one)

# If using Local MongoDB:
MONGO_URI=mongodb://localhost:27017/ai-secure

# If using MongoDB Atlas (Cloud):
MONGO_URI=mongodb+srv://username:password@cluster0.xyz.mongodb.net/?retryWrites=true&w=majority

# OpenAI API Key (Optional - for AI explanations)
OPENAI_API_KEY=sk-...your-key-here...
```

### Environment Variables Explained:

| Variable | Purpose | Example |
|----------|---------|---------|
| `MONGO_URI` | Database connection | `mongodb://localhost:27017` |
| `OPENAI_API_KEY` | AI explanations | `sk-proj-abc123...` |

---

## 🚀 Running the Application

### Step 1: Activate Virtual Environment
```powershell
myenv\Scripts\Activate.ps1
```

### Step 2: Start the Server
```bash
uvicorn app.main:app --reload
```

### Step 3: Access the Application

**Frontend:** http://localhost:8000  
**API Docs:** http://localhost:8000/docs (Swagger UI)  
**Alternative Docs:** http://localhost:8000/redoc

---

## 💻 How to Use

### 1️⃣ **Scan a Code File**

1. Go to: http://localhost:8000
2. Click **"Scan File"**
3. Upload a Python/JavaScript file
4. Review the report with:
   - Security score (0-100)
   - Letter grade (A-F)
   - Vulnerabilities found
   - Line numbers with code snippets
   - Recommended fixes

### 2️⃣ **Scan a GitHub Repository**

1. Click **"Scan Repository"**
2. Enter GitHub URL: `https://github.com/username/repo`
3. Select files to scan
4. View comprehensive report showing:
   - Total files analyzed
   - All vulnerabilities by file
   - Security score

### 3️⃣ **Crawl & Fuzz a Website**

1. Click **"Scan Website"**
2. Enter target URL: `https://example.com`
3. Scanner will:
   - Crawl all pages
   - Test for common vulnerabilities
   - Generate security report

### 4️⃣ **View Scan History**

1. Go to **"History"** page
2. See all past scans with:
   - Timestamp
   - File/repo scanned
   - Security score
   - Number of vulnerabilities

### 5️⃣ **Download PDF Report**

1. Complete a scan
2. Click **"Download PDF"**
3. Get detailed report with:
   - Executive summary
   - Technical details
   - OWASP classifications
   - Mitigation strategies

---

## 📁 Project Structure

```
ai-secure/
├── README.md                 # Original README
├── README_SETUP.md          # This setup guide
├── requirement.txt          # Python dependencies
├── runtime.txt              # Python version info
├── test.py                  # Test file
├── .env                     # Environment configuration (create this)
│
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application & routes
│   ├── scanner.py           # Code scanning engine
│   ├── database.py          # MongoDB connection
│   ├── crawler.py           # Web crawler for sites
│   ├── fuzzing_engine.py    # Fuzzing for web testing
│   ├── llm_service.py       # OpenAI integration
│   ├── pdf_service.py       # PDF report generation
│   ├── utils.py             # Utility functions
│   ├── vulnerability_taxonomy.py  # Vulnerability classifications
│   ├── ai_reasoning.py      # AI reasoning module
│   └── static/              # Frontend files
│       ├── index.html       # Main upload page
│       ├── history.html     # Scan history page
│       └── flow.html        # Flow visualization
│
├── myenv/                   # Virtual environment
└── .gitignore
```

---

## 📊 Key API Endpoints

### **POST /scan**
Upload and scan a code file
```bash
curl -X POST http://localhost:8000/scan -F "file=@code.py"
```

### **POST /scan-repo**
Scan a GitHub repository
```bash
curl -X POST http://localhost:8000/scan-repo \
  -H "Content-Type: application/json" \
  -d '{"repo_url":"https://github.com/user/repo"}'
```

### **GET /reports**
Get all scan reports
```bash
curl http://localhost:8000/reports
```

### **GET /reports/{report_id}**
Get specific report details
```bash
curl http://localhost:8000/reports/507f1f77bcf86cd799439011
```

---

## 🐛 Troubleshooting

### ❌ Error: "MONGO_URI is not set"
**Solution:**
1. Create `.env` file in project root
2. Add: `MONGO_URI=mongodb://localhost:27017`
3. Restart server

### ❌ Error: "Database not found / Connection refused"
**Possible causes:**

**1. MongoDB not running:**
```powershell
# Check MongoDB service (Windows)
Get-Service -Name MongoDB

# Start it if stopped
Start-Service -Name MongoDB
```

**2. Wrong connection string:**
- Verify `.env` has correct MongoDB URI
- Check if credentials are URL-encoded

**3. IP not whitelisted (MongoDB Atlas):**
- Go to: https://cloud.mongodb.com
- Click **Network Access**
- Add your IP or `0.0.0.0/0`

### ❌ Error: "ModuleNotFoundError: No module named 'xyz'"
**Solution:**
```bash
# Reinstall dependencies
pip install -r requirement.txt

# Or install specific package
pip install motor pydantic fastapi
```

### ❌ Port 8000 Already in Use
**Solution:**
```powershell
# Use different port
uvicorn app.main:app --port 8001 --reload
```

### ❌ OpenAI API Errors (for AI explanations)
**Solutions:**
1. Verify API key in `.env` is correct
2. Check API quota: https://platform.openai.com/account/usage
3. Ensure API key hasn't expired
4. Without API key, app still works with basic explanations

---

## 🔐 Security Best Practices

When using this tool:

✅ **Never commit `.env` to Git** - Add to `.gitignore`  
✅ **Use strong MongoDB passwords** - Whitelist specific IPs  
✅ **Rotate API keys regularly** - Keep them secret  
✅ **Use HTTPS in production** - Change `http://` to `https://`  
✅ **Restrict CORS origins** - Change from `"*"` to specific domains  

---

## 📝 Example Workflow

### Complete Setup from Scratch:

```powershell
# 1. Navigate to project
cd ai-secure

# 2. Create virtual environment
python -m venv myenv
myenv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirement.txt

# 4. Create .env file (use notepad or any editor)
# Add:
# MONGO_URI=mongodb://localhost:27017
# OPENAI_API_KEY=your_key_here

# 5. Make sure MongoDB is running
Get-Service -Name MongoDB

# 6. Start the application
uvicorn app.main:app --reload

# 7. Open browser
# http://localhost:8000
```

---

## 🤝 Support

If you encounter issues:

1. **Check terminal output** - Most errors are logged there
2. **Review `.env` configuration** - Most common cause
3. **Verify MongoDB is running** - Essential for all features
4. **Check MongoDB Atlas IP whitelist** - If using cloud
5. **Restart the server** - Sometimes fixes connection issues

---

## 📚 Additional Resources

- **FastAPI Docs:** https://fastapi.tiangolo.com/
- **MongoDB Docs:** https://docs.mongodb.com/
- **OpenAI API:** https://platform.openai.com/
- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **CWE:** https://cwe.mitre.org/

---

## 📄 License & Version

**Version:** 1.0  
**Python:** 3.13.9  
**Last Updated:** April 2026

---

## ✅ Quick Checklist

Before starting, make sure you have:
- [ ] Python 3.13.9 installed
- [ ] Virtual environment created and activated
- [ ] Dependencies installed (`pip install -r requirement.txt`)
- [ ] `.env` file created with `MONGO_URI`
- [ ] MongoDB running (local or Atlas connected)
- [ ] Port 8000 is available
- [ ] (Optional) OpenAI API key added

Once all checked, run: `uvicorn app.main:app --reload` 🚀

---

**Happy scanning! 🔒**
