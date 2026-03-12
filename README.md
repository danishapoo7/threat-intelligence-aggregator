# Threat Intelligence Aggregator

A **Cybersecurity Threat Intelligence Platform** that aggregates malicious indicators from multiple threat feeds, processes them, and visualizes them in an interactive **SOC-style dashboard**.

The system collects **Indicators of Compromise (IOCs)** such as:

* IP addresses
* Domains
* URLs
* Malware hashes

and performs **correlation, normalization, and risk scoring** to identify high-risk threats.

---

# Project Architecture

The system follows a modular architecture:

Threat Feeds → IOC Parser → Normalization Engine → Correlation Engine → Risk Scoring → Database → SOC Dashboard → Reports & Blocklists

---

# Features

### Threat Feed Aggregation

Collects threat intelligence feeds from multiple sources.

### IOC Parsing

Extracts:

* IP addresses
* Domains
* URLs
* File hashes

### Normalization Engine

Standardizes IOC structure and adds metadata:

* Source
* Timestamp
* Category

### Correlation Engine

Identifies indicators appearing multiple times across feeds.

### Risk Scoring System

Prioritizes threats based on frequency and IOC type.

### IOC Database

Stores normalized indicators in an SQLite database.

### SOC Dashboard

Interactive dashboard with:

* IOC distribution charts
* Parsed IOC tables
* Correlation results
* Threat map visualization
* IOC search functionality

### Blocklist Generation

Automatically generates blocklists for security deployment.

### Report Export

Threat reports can be exported as:

* CSV
* JSON

---

# Technologies Used

| Technology | Purpose                   |
| ---------- | ------------------------- |
| Python     | Core programming language |
| Streamlit  | Dashboard interface       |
| SQLite     | IOC database              |
| Pandas     | Data processing           |
| Plotly     | Data visualization        |
| Requests   | Fetching threat feeds     |

---

# Project Structure

```
threat-intelligence-aggregator
│
├── app.py
│
├── feeds
│   └── feed_loader.py
│
├── parser
│   └── ioc_parser.py
│
├── normalization
│   └── normalize.py
│
├── correlation
│   └── correlation_engine.py
│
├── scoring
│   └── score.py
│
├── database
│   └── db_manager.py
│
├── blocklist
│   └── blocklist_generator.py
│
├── data
│   └── threat_db.sqlite
```

---

# Installation

Clone the repository:

```
git clone https://github.com/danishapoo7/threat-intelligence-aggregator.git
```

Go to project directory:

```
cd threat-intelligence-aggregator
```

Create virtual environment:

```
python -m venv venv
```

Activate environment:

Windows

```
venv\Scripts\activate
```

Install dependencies:

```
pip install -r requirements.txt
```

---

# Run the Application

Start the Streamlit dashboard:

```
streamlit run app.py
```

The dashboard will open at:

```
http://localhost:8501
```

---

# Dashboard Modules

### Dashboard

Displays:

* IOC distribution
* Parsed indicators
* Correlation results
* Risk scoring

### IOC Database

View all stored indicators.

### IOC Search

Search any indicator from the database.

### Threat Map

Visualizes global threat sources.

### Reports

Generate threat intelligence reports and export them.

---

# Expected Output

The system generates:

* Normalized IOC database
* Parsed IPs, domains, URLs, hashes
* Correlation results
* Threat intelligence reports
* Blocklist files

Example outputs:

* High-risk IPs appearing in multiple feeds
* Consolidated malicious domain list
* Malware hashes detected across feeds

---

# Future Improvements

Possible enhancements:

* Machine learning threat detection
* SIEM integration
* Real-time threat monitoring
* Threat actor attribution
* Advanced attack visualization

---

# Project Deployment

Streamlit Cloud deployment:

```
https://your-streamlit-app-url.streamlit.app
```

---

# Author

Muhammed Danish AP
Cybersecurity Project – Threat Intelligence Aggregator

---

# License

This project is developed for educational and cybersecurity research purposes.

