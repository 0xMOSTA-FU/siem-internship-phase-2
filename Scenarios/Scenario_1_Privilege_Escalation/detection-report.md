
------
> Very important note: what you’ll see here is a mix of examples, templates, queries, and general ideas—alongside the actual work, implementations, and real
> examples we applied ourselves.
> The real implementation parts will be shown with screenshots from our lab.
> You may also find some general and expected examples included in the broader explanation.

-----

# Scenario 1: Privilege Escalation Attempt (MITRE T1055 / T1547)

##  Objective
The primary objective of this scenario was to simulate and detect a common and critical attack technique: **Privilege Escalation**. Specifically, we focused on an attacker gaining higher-level administrative permissions on a compromised Windows system. Our goal was to create robust detection rules that identify the creation or modification of user accounts to gain administrative rights, which is a hallmark of successful privilege escalation.

##  Our Thinking & Approach
Our thought process for detecting privilege escalation was rooted in understanding the "how" and "what" of an attacker's actions:

1.  **Understanding the Attacker's Goal:** An attacker wants to become an administrator. How do they do that? Usually by either creating a new administrator account or adding an existing low-privileged account to the Administrators group.
2.  **Identifying Core Windows Mechanisms:**
    * **User/Group Management:** Windows handles this via `net user` and `net localgroup` commands. This means `net.exe` is a key process to monitor.
    * **Logging of Account Changes:** Windows Security Logs are designed to track these exact changes (account creation, group modification).
3.  **Pinpointing Key Event IDs:**
    * We knew `Event ID 4720` (user account created) was crucial.
    * We also knew `Event ID 4728` (member added to security-enabled global group) was key, especially if the group is "Administrators".
    * For command-line execution, Sysmon's `Event ID 1` (Process Create) would capture `net.exe` and its arguments.
4.  **Correlation is Key:** A single event might be benign. Creating a user account (`4720`) could be normal. Adding a user to a group (`4728`) could be normal. But when a *newly created user* is *immediately added to the Administrators group*, that's highly suspicious and requires correlation.
5.  **High-Fidelity Indicators:** Direct command-line execution of `net user /add` followed by `net localgroup administrators /add` is a very strong indicator, almost always malicious, especially if not from an expected administrative script.

##  Our Step-by-Step Implementation

### 1. Attack Flow Simulation
To generate the necessary logs and simulate the attack, we executed the following command on our Windows test machine:

```powershell
net user backdoor /add && net localgroup administrators backdoor /add
```
* **Purpose of `net user backdoor /add`:** This creates a new local user account named "backdoor". We chose a generic, suspicious name to represent an attacker-controlled account.
* **Purpose of `net localgroup administrators backdoor /add`:** This immediately adds the newly created "backdoor" user to the local "Administrators" group. This is the crucial privilege escalation step.

### 2. Log Collection & Analysis
After executing the command, we monitored our Elastic Stack:

* **Winlogbeat's Role:** Confirmed that Winlogbeat was successfully collecting Windows Security Logs and Sysmon logs from our test machine.
* **Kibana Discover:** We navigated to Kibana Discover and filtered for relevant Event IDs:
    * Searched for `event.code: 4720` to find the user creation event. We noted the `TargetUserName` (backdoor).
    * Searched for `event.code: 4728` to find the group modification event. We verified `TargetUserName: Administrators` and `MemberName: backdoor`.
    * Searched for `event.code: 1` and `Image: "*\\net.exe"` to capture the command-line execution. We examined the `CommandLine` field for the `user /add` and `localgroup administrators /add` arguments.
* **Field Mapping Verification:** We carefully examined the raw JSON of these logs to confirm the exact field names (e.g., `winlogbeat.event_data.TargetUserName`, `winlogbeat.event_data.CommandLine`) that Winlogbeat was providing, ensuring our KQL would be accurate.

### 3. Detection Logic Development (KQL & Sigma/Splunk)

Based on our analysis, we developed the following detection rules:

* **Rule 1: New Administrative Account Creation (Correlation)**
    * **Description:** This rule correlates the creation of a new user account (`Event ID 4720`) with its subsequent addition to the local "Administrators" group (`Event ID 4728`) within a short timeframe (e.g., 1 minute). This combination is highly indicative of an attacker attempting to establish persistence or elevate privileges.
    * **KQL Query:**
        ```kql
        event.code: 4720 AND winlogbeat.event_data.TargetUserName.keyword : * AND event.code: 4728 AND winlogbeat.event_data.TargetUserName.keyword : "Administrators" 
        AND winlogbeat.event_data.MemberName.keyword : * # This needs to correlate with TargetUserName from 4720
        ```
        * **Refinement for Correlation:** In Kibana's Detection Engine, this rule would be configured as a **"Correlation Rule"** where one event follows another, or a **"Threshold Rule"** if the same `TargetUserName` (from 4720) and `MemberName` (from 4728) appear within a short interval. For a single query, we'd look for both events in the same time range with matching usernames.
        * **KQL for single event search that covers both (less robust correlation):**
            ```kql
            (event.code: 4720 AND winlogbeat.event_data.TargetUserName.keyword : "backdoor") 
            OR (event.code: 4728 AND winlogbeat.event_data.TargetUserName.keyword : "Administrators" AND winlogbeat.event_data.MemberName.keyword : "backdoor")
            ```
            *(Note: A true correlation rule in Kibana's Detection Engine offers better accuracy for linked events than a single OR query.)*

* **Rule 2: Direct `net.exe` Admin Group Modification (High-Fidelity)**
    * **Description:** This rule directly targets the execution of `net.exe` with specific command-line arguments that create a user and add it to the Administrators group. This is a very high-fidelity alert as it captures the direct tool usage.
    * **KQL Query:**
        ```kql
        event.code: 1 
        AND winlogbeat.event_data.Image.keyword : "*\\net.exe" 
        AND winlogbeat.event_data.CommandLine.keyword : "*user* /add*" 
        AND winlogbeat.event_data.CommandLine.keyword : "*localgroup* administrators* /add*"
        ```

* **Rule 3: Special Logon after Suspicious Activity (Confirmation)**
    * **Description:** This rule detects a successful logon where the account is assigned special privileges (typically administrative). While not a standalone escalation alert, it acts as a confirmation of successful administrative access after a suspicious activity.
    * **KQL Query:**
        ```kql
        event.code: 4672 AND winlogbeat.event_data.PrivilegeList.keyword : "*SeTcbPrivilege*"
        ```

### 4. Testing & Validation
* We deployed these KQL queries as rules in Kibana's Detection Engine.
* We re-executed the `net user` and `net localgroup` commands on our test machine.
* We confirmed that both "New Administrative Account Creation" and "Direct `net.exe` Admin Group Modification" rules triggered alerts in Kibana.
* We validated that the `Event ID 4672` (if we logged in with the new admin account) appeared in the logs, providing further context.

##  Screenshots from our lab along with the explanation.

![Screenshot 2025-06-11 234444](https://github.com/user-attachments/assets/7658e9f3-9ebf-4b66-a920-5b8441cfd5c4)

![Screenshot 2025-06-11 235001](https://github.com/user-attachments/assets/7788b8ab-7f3a-471d-80cb-853c6bf74190)

![Screenshot 2025-06-11 235024](https://github.com/user-attachments/assets/2c0ef9ec-0d42-4318-83d3-7980ca90f221)

![Screenshot 2025-06-11 235057](https://github.com/user-attachments/assets/55f91c92-c4f3-4c80-b31a-0b61277d4d14)


##  Recommendations for Mitigation & Prevention
Based on this scenario, here are key recommendations to harden defenses against Privilege Escalation:

* **Principle of Least Privilege:** Grant users and services only the absolute minimum permissions required. Never give administrative rights unless strictly necessary.
* **Multi-Factor Authentication (MFA):** Enforce MFA for all administrative accounts and critical systems to prevent unauthorized access even if credentials are stolen.
* **Regular Account Audits:** Periodically review local and domain administrative group memberships. Look for newly created accounts or unauthorized additions.
* **Endpoint Detection and Response (EDR):** Deploy EDR solutions to monitor process creation, command-line arguments, and registry changes in real-time, catching suspicious activities missed by traditional logging.
* **User Account Control (UAC):** Ensure UAC is enabled and configured to "Always notify" for administrative consent.
* **Patch Management:** Keep operating systems and applications updated to remediate vulnerabilities attackers might exploit for privilege escalation.

##  Sample Logs and Queries Used
*messenge for me* *(Place your actual raw JSON log entries and the KQL queries that worked for you here.)* *don’t Forget plz*

**Sample Log (Windows Security Event ID 4720 - Account Creation):**
```json
{
  "@timestamp": "2025-06-12T09:00:00.000Z",
  "event": {
    "code": 4720,
    "kind": "event",
    "category": "user",
    "action": "user_account_created",
    "outcome": "success"
  },
  "winlogbeat": {
    "event_data": {
      "SubjectUserSid": "S-1-5-21-...",
      "SubjectUserName": "your_test_user",
      "TargetUserName": "backdoor",
      "TargetSid": "S-1-5-21-...",
      "PrivilegeList": "-"
    },
    "provider_name": "Microsoft-Windows-Security-Auditing"
  },
  "message": "A user account was created. Subject: your_test_user, New Account: backdoor"
}
```

**Sample Log (Windows Security Event ID 4728 - Member Added to Global Group):**
```json
{
  "@timestamp": "2025-06-12T09:00:00.100Z",
  "event": {
    "code": 4728,
    "kind": "event",
    "category": "user",
    "action": "group_member_added",
    "outcome": "success"
  },
  "winlogbeat": {
    "event_data": {
      "MemberSid": "S-1-5-21-...",
      "MemberName": "backdoor",
      "TargetUserName": "Administrators",
      "TargetSid": "S-1-5-32-544",
      "PrivilegeList": "-"
    },
    "provider_name": "Microsoft-Windows-Security-Auditing"
  },
  "message": "A member was added to a security-enabled global group. Subject: your_test_user, Member: backdoor, Group: Administrators"
}
```

**Sample Log (Sysmon Event ID 1 - Process Create for net.exe):**
```json
{
  "@timestamp": "2025-06-12T09:00:00.050Z",
  "event": {
    "code": 1,
    "kind": "event",
    "category": "process",
    "type": "start",
    "outcome": "success"
  },
  "winlogbeat": {
    "event_data": {
      "CommandLine": "net user backdoor /add && net localgroup administrators backdoor /add",
      "Image": "C:\\Windows\\System32\\net.exe",
      "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "User": "your_test_user",
      "ProcessId": "...",
      "Hashes": "MD5=...",
      "CurrentDirectory": "C:\\"
    },
    "provider_name": "Microsoft-Windows-Sysmon"
  },
  "message": "Process Create: net.exe with command: net user backdoor /add && net localgroup administrators backdoor /add"
}
```



![image](https://github.com/user-attachments/assets/ee364c5b-4283-4014-b7ac-e9b4019a5d6e)

