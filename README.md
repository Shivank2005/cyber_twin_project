
# CyberX-AI-Digital-Twin

## Project Overview
CyberX-AI-Digital-Twin is an integrated cybersecurity digital twin platform designed to simulate, detect, and analyze various cyber attack vectors. It allows cybersecurity researchers, developers, and educational institutions to test and validate security protocols in a fully isolated digital replica of their network environment. The project combines a Flask-based web application with AI/ML modules for attack detection, offering a safe environment for security testing and vulnerability assessment.

## Features
- **User Management**
  - Secure user registration and login using Flask.
  - Password hashing with bcrypt.
  - Dual storage of user credentials using MySQL and LDAP for enhanced security.
  
- **Web Interface**
  - Intuitive and responsive HTML templates.
  - Dedicated pages for home, registration, and login.

- **Attack Detection Modules**
  - **SQL Injection Detection:** Uses machine learning techniques to identify SQL injection attempts.
  - **XSS Attack Prediction:** Implements ensemble learning methods (Random Forest, Gradient Boosting, and XGBoost) to forecast cross-site scripting (XSS) attacks.
  - **Session Hijacking Detection:** Leverages natural language processing (using BERT) on network logs to simulate and detect session hijacking attempts.

- **Digital Twin-Based Attack Simulation**
  - **Phase 1: Digital Twin Setup:**  
    - Configure network security layers, including firewalls, IDS/IPS, and network segmentation.
    - Isolate and validate the digital twin environment from production networks.
    - Optimize network traffic patterns and latency settings.
    - Virtualize servers, databases, and network devices for replicating real-world conditions.
  
  - **Phase 2: AI/ML-Driven Attack Model Training:**  
    - Collect historical and novel attack data from trusted sources (e.g., MITRE ATT&CK, CVE databases).
    - Preprocess, label, and structure data for model training.
    - Develop and train AI/ML models to simulate various cyberattacks (e.g., phishing, malware injection, DDoS).
  
  - **Phase 3: Attack Simulation & Vulnerability Assessment:**  
    - Execute simulated attack scenarios on the digital twin.
    - Perform automated vulnerability scans and penetration tests.
    - Capture data on system resilience and breach impacts.
  
  - **Phase 4: Insights & Recommendations:**  
    - Generate actionable security insights and update remediation strategies.
    - Implement automated remediation and define critical assets for continuous monitoring.
  
- **Extensibility**
  - Modular design separating web functionalities from AI-agent detection modules.
  - Clear structure enables the addition of new modules or enhancement of existing ones with minimal integration efforts.

## Installation and Setup

### Prerequisites
- Python 3.8 or later
- MySQL Server
- LDAP Server (for authentication)
- pip package manager

### Dependencies
Ensure the following Python packages are installed:
- Flask
- mysql-connector-python
- ldap3
- bcrypt
- scikit-learn
- xgboost
- imbalanced-learn
- pandas
- transformers
- torch

You can install the required packages using pip:
```bash
pip install Flask mysql-connector-python ldap3 bcrypt scikit-learn xgboost imbalanced-learn pandas transformers torch
```

### Configuration
1. **MySQL and LDAP Settings:**  
   In app.py, update the following configuration objects with your server details:
   - `db_config` (MySQL details: host, user, password, database)
   - LDAP configuration parameters (`ldap_server`, `ldap_user_dn`, `ldap_password`, `ldap_base_dn`)

2. **Dataset Paths:**  
   For the machine learning modules found in `/models/AI-agent1`, `/models/AI-agent2`, and `/models/AI-agent3`, update the dataset file paths as needed based on your environment.

### Running the Application
Start the Flask server by executing:
```bash
python app.py
```
The application will listen on `http://0.0.0.0:8080`. Open this address in your browser to access the system.

## Usage

- **Web Interface:**  
  - **Homepage (`/`):** Provides the landing and organizational overview.
  - **Registration (`/register`):** Allows users to create a new account. The flow includes password hashing and storage in both MySQL and LDAP.
  - **Login (`/login`):** Users authenticate via LDAP where the provided password is validated against the stored, hashed password.
  
- **Attack Simulation & Detection:**  
  - Each machine learning module (SQL Injection, XSS Attack Prediction, Session Hijacking) includes scripts for data preprocessing, model training, evaluation, and feature importance analysis.
  - Run these scripts individually (via terminal or Jupyter Notebook) to train models or evaluate current system vulnerabilities.

- **Flowchart Overview:**  
  The solution is built upon an AI-Powered Attack Simulation process using Digital Twin Technology, broken down into:
  1. **Digital Twin Setup** for isolated, real-life simulation.
  2. **AI/ML-Driven Attack Model Training** using historical and new attack data.
  3. **Attack Simulation & Vulnerability Assessment** to test response and capture impact metrics.
  4. **Insights & Recommendations** for continuous security enhancements with a feedback loop for ongoing model refinement.

## Project Structure
```
CyberX-AI-Digital-Twin-main/
├── app.py                     # Main Flask app; handles routing, user registration/login with MySQL and LDAP.
├── README.md                  # Project documentation.
├── templates/                 # HTML templates for the web interface.
│   ├── index.html             # Landing page.
│   ├── home.html              # Home/Secure page.
│   ├── login.html             # Login page.
│   └── register.html          # Registration page.
└── models/                    # Machine learning modules for attack detection.
    ├── AI-agent1/             # SQL Injection detection module.
    │   └── sql_injection_detectio.py
    ├── AI-agent2/             # XSS Attack prediction module.
    │   └── XSS_attack_prediction.py
    └── AI-agent3/             # Session Hijacking detection module.
        └── session_hijacking.py
```

## Architecture and Design
- **Backend:**  
  - Developed using Flask for handling HTTP requests and rendering HTML templates.
  - Implements dual authentication storage via MySQL and LDAP.
  
- **Security & Data Integrity:**  
  - Utilizes bcrypt for secure password hashing.
  - Incorporates proper error handling for database and LDAP operations.
  
- **AI Modules:**  
  - Each module leverages modern ML frameworks (scikit-learn, XGBoost, and transformers) for simulating and detecting various cyberattacks.
  - Modular design allows independent execution and testing of each attack simulation phase.
  
- **Digital Twin Integration:**  
  - Phased approach replicates a real-world network environment safely in an isolated setting.
  - Supports a continuous feedback loop where outcomes drive AI model re-training and system configuration enhancements.
 
![Flowchart](Flowchart%20s2.png)


## Testing and Contribution Guidelines

### Testing
- **Unit Testing:**  
  - Develop unit tests to verify Flask routes and the functionality of the AI modules.
  - Run tests using your preferred framework (e.g., pytest):
    ```bash
    pytest
    ```
- **Manual Testing:**  
  - Interact with the web pages by registering, logging in, and testing error scenarios.
  - Execute the machine learning modules to check data preprocessing and model performance.

### Contribution Guidelines
- **Reporting Issues:**  
  - Use the repository’s issue tracker for bug reports or feature requests.
- **Submitting Pull Requests:**  
  - Fork the repository, make your changes, and submit a pull request with a clear description and necessary tests.
  - Follow the coding style and include documentation updates where applicable.

## License and Acknowledgments
- **License:**  
  - Distributed under the MIT License. See the LICENSE file for full details.
- **Acknowledgments:**  
  - Special thanks to **BSI Learning Australia** and **SRM AP University** for their educational contributions.
  - Gratitude to the open source community for providing robust libraries and tools that enabled this project.


Enjoy exploring **CyberX-AI-Digital-Twin** and contributing to the advancement of secure, AI-driven digital twin technologies!

