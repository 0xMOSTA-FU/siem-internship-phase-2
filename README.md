#  My SOC Detection Engineering Project-Phase2

## Overview

Welcome to my **SOC Detection Engineering Project**! This repository showcases my practical experience in developing, testing, and documenting detection rules for various cybersecurity attack scenarios. The project focuses on leveraging Windows Security Logs and Sysmon events, ingested into an Elastic Stack (Kibana), to proactively identify and alert on malicious activities within an enterprise environment.

My goal was to simulate common attack techniques, understand their forensic footprints (Event IDs and log data), and then translate that understanding into actionable detection logic. This project highlights my capabilities in:

* **Threat Simulation:** Replicating attacker methodologies.
* **Log Analysis:** Identifying key indicators in security logs.
* **Detection Rule Development:** Crafting effective queries (KQL) and rules (Sigma).
* **Documentation:** Creating clear, detailed reports for each detection.
* **SIEM Integration:** Working with Elastic Stack for log ingestion, analysis, and alerting.

## Project Structure

This repository is organized to provide a clear, scenario-based walkthrough of the detection engineering process.


```md
## Project Structure

More actions
My_SOC_Detection_Project/

├── Scenarios/
│   ├── Scenario_1_Privilege_Escalation/
│   │   ├── detection-report.md
│   │   ├── sigma_rules.yml          (Bonus Challenge)
│   │   ├── splunk_queries.spl       (Bonus Challenge)
│   │   ├── screenshots/             (Folder for all related images)
│   │   └── logs/                    (Folder for sample log files)
│   ├── Scenario_2_Lateral_Movement/
│   │   ├── detection-report.md
│   │   ├── sigma_rules.yml
│   │   ├── splunk_queries.spl
│   │   ├── screenshots/
│   │   └── logs/
│   ├── Scenario_3_Suspicious_Download_Execution/
│   │   ├── detection-report.md
│   │   ├── sigma_rules.yml
│   │   ├── splunk_queries.spl
│   │   ├── screenshots/
│   │   └── logs/
│   ├── Scenario_4_Abnormal_User_Behavior/
│   │   ├── detection-report.md
│   │   ├── sigma_rules.yml
│   │   ├── splunk_queries.spl
│   │   ├── screenshots/
│   │   └── logs/
│   └── Scenario_5_C2_Beaconing/
│       ├── detection-report.md
│       ├── sigma_rules.yml
│       ├── splunk_queries.spl
│       ├── screenshots/
│       └── logs/
│ ├── Scenario_1_Privilege_Escalation/
│ │ ├── detection-report.md
│ │ ├── sigma_rules.yml
│ │ ├── splunk_queries.spl
│ │ ├── screenshots/
│ │ └── logs/
│ ├── Scenario_2_Lateral_Movement/
│ │ ├── detection-report.md
│ │ ├── sigma_rules.yml
│ │ ├── splunk_queries.spl
│ │ ├── screenshots/
│ │ └── logs/
│ ├── Scenario_3_Suspicious_Download_Execution/
│ │ ├── detection-report.md
│ │ ├── sigma_rules.yml
│ │ ├── splunk_queries.spl
│ │ ├── screenshots/
│ │ └── logs/
│ ├── Scenario_4_Abnormal_User_Behavior/
│ │ ├── detection-report.md
│ │ ├── sigma_rules.yml
│ │ ├── splunk_queries.spl
│ │ ├── screenshots/
│ │ └── logs/
│ └── Scenario_5_C2_Beaconing/
│ ├── detection-report.md
│ ├── sigma_rules.yml
│ ├── splunk_queries.spl
│ ├── screenshots/
│ └── logs/
├── Sigma.md
└── README.md


```

## Technologies Used

* **Operating System:** Windows 10 (for attack simulation and log generation)
* **Log Collection:**
    * **Sysmon:** System Monitor for detailed process, network, and file system activity logging.
    * **Winlogbeat:** Elastic Beat for shipping Windows Event Logs (Security, Sysmon, etc.) to Elasticsearch.
* **SIEM/Analysis Platform:**
    * **Elasticsearch:** Distributed search and analytics engine.
    * **Kibana:** Data visualization and exploration tool (used for log analysis, KQL queries, and Detection Engine).
* **Threat Intelligence Framework:**
    * **MITRE ATT&CK Framework:** Used for mapping detected techniques to known adversary tactics and techniques.
* **Detection Rule Formats (Bonus Challenges):**
    * **Sigma:** Generic signature format for SIEM systems.
    * **Splunk SPL:** Splunk Search Processing Language.

## Simulated Attack Scenarios & Detections

Each scenario folder (`Scenarios/Scenario_X_...`) contains a detailed `detection-report.md` file, which includes:

* **Objective:** What the detection aims to achieve.
* **Attack Flow:** A step-by-step description of the simulated attack, including the exact commands executed on the Windows machine. This directly reflects my hands-on testing.
* **Event IDs:** The specific Windows Security Log and Sysmon Event IDs that were observed and used for detection.
* **Detection Logic (KQL):** The Kibana Query Language (KQL) queries implemented in the Elastic Detection Engine to identify the malicious activity. These queries are specifically tailored to the logs generated during my simulations.
* **Screenshots:** Visual evidence from Event Viewer (showing raw logs), Kibana Discover (showing ingested logs), and Kibana Detection Engine (showing triggered alerts). *(This section is where you will add your actual screenshots from your lab environment)*
* **Recommendations:** Actionable recommendations for mitigation and prevention based on the detected technique.
* **Sample Logs & Queries Used:** Raw JSON log entries and the KQL queries used in my Kibana environment. *(You will populate this with your actual sample logs and the KQL queries you used)*

### Featured Scenarios:

1.  **Scenario 1: Privilege Escalation**
    * **Techniques:** T1055 (Process Injection), T1547 (Boot or Logon Autostart Execution) - specifically, creating new admin accounts.
    * **Focus:** Detecting the creation of new administrative accounts and their addition to privileged groups using `net.exe` commands.
    * [Explore the detailed detection report for Privilege Escalation](/Scenarios/Scenario_1_Privilege_Escalation/detection-report.md)

2.  **Scenario 2: Lateral Movement**
    * **Techniques:** T1021.002 (Remote Services: SMB/Windows Admin Shares), T1021.006 (Remote Services: Windows Management Instrumentation).
    * **Focus:** Identifying the use of tools like PsExec, WMIC, and `net use` for remote execution and access to administrative shares.
    * [Explore the detailed detection report for Lateral Movement](/Scenarios/Scenario_2_Lateral_Movement/detection-report.md)

3.  **Scenario 3: Suspicious File Download & Execution**
    * **Techniques:** T1105 (Ingress Tool Transfer), T1059.001 (Command and Scripting Interpreter: PowerShell).
    * **Focus:** Detecting the download of suspicious executables/scripts via common utilities (`powershell.exe`, `curl.exe`, `bitsadmin.exe`) and their execution from unusual directories.
    * [Explore the detailed detection report for Suspicious File Download & Execution](/Scenarios/Scenario_3_Suspicious_Download_Execution/detection-report.md)

4.  **Scenario 4: Abnormal User Behavior / Account Compromise**
    * **Techniques:** T1078 (Valid Accounts), T1020 (Automated Exfiltration), T1074 (Data Staged).
    * **Focus:** Identifying unusual login patterns (e.g., outside business hours) and high-volume file copying to staging directories, indicative of data exfiltration preparation.
    * [Explore the detailed detection report for Abnormal User Behavior](/Scenarios/Scenario_4_Abnormal_User_Behavior/detection-report.md)

5.  **Scenario 5: Command & Control (C2) Beaconing**
    * **Techniques:** T1071 (Application Layer Protocol), T1008 (Fallback Channels).
    * **Focus:** Detecting repetitive outbound network connections (beaconing) from suspicious processes, indicating an active C2 channel.
    * [Explore the detailed detection report for C2 Beaconing](/Scenarios/Scenario_5_C2_Beaconing/detection-report.md)

## Bonus Challenges (Sigma Rules & Splunk SPL)

For those interested in cross-SIEM compatibility and broader detection capabilities, I've also included:

* **Sigma Rules (`sigma_rules.yml`):** Generic, open-source signatures for each detection scenario, allowing for easy conversion to various SIEM query languages (like Elastic KQL, Splunk SPL, Azure Sentinel KQL, etc.). This demonstrates my ability to work with vendor-agnostic detection formats.
* **Splunk SPL Queries (`splunk_queries.spl`):** Equivalent queries written in Splunk's Search Processing Language (SPL) for each scenario, showcasing adaptability across different SIEM platforms.

These bonus files are located within each scenario's respective folder.

## How to Replicate

To replicate this project and test the detections:

1.  **Set up a Windows 10 VM:** Ensure it has administrative privileges.
2.  **Install Sysmon:** Configure Sysmon with a comprehensive configuration file (e.g., SwiftOnSecurity's Sysmon config) to capture detailed events.
3.  **Install Winlogbeat:** Configure Winlogbeat to collect logs from Windows Security and Sysmon event channels and ship them to your Elasticsearch instance.
4.  **Set up Elastic Stack (Elasticsearch & Kibana):** Ensure all services are running and Winlogbeat is successfully sending data.
5.  **Execute Attack Commands:** Navigate to each `detection-report.md` file, follow the "Attack Flow" commands, and execute them on your Windows VM.
6.  **Analyze & Create Detections:**
    * Monitor Kibana Discover for the generated logs.
    * Create detection rules in Kibana's Detection Engine using the provided KQL.
    * Verify alerts are triggered.
    * (Optional) Use `sigmac` to convert the Sigma rules and test them.

## Contributions

Feel free to explore the repository, provide feedback, or suggest improvements. This project is a continuous learning journey in the field of cybersecurity detection engineering.

---

**Developed with 💙 by [Mostafa Essam/0xMOSTA]**
