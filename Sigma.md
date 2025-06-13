# Understanding Sigma Rules and Their Role in Modern SOC Analytics

In modern Security Operations Centers (SOCs), efficient and well-structured analytics are crucial for timely threat detection and incident response. Sigma, an open standard for writing generic SIEM detection rules, plays a pivotal role in streamlining detection engineering and enhancing collaboration across teams and organizations. This article dives deep into the Sigma rule format, how analytics are designed, tested, shared, and how automation can be leveraged to distribute and apply analytics more effectively.

---

## What is Sigma?

Sigma is a generic and open signature format that allows security analysts to describe detection rules in a standardized way. Think of Sigma as what Snort is for network intrusion detection, but for SIEM log queries.

Instead of writing vendor-specific queries for tools like Splunk, Elasticsearch, or QRadar, analysts can write one Sigma rule and use converters to transform it into the appropriate format for the target platform.

![image](https://github.com/user-attachments/assets/f88fa547-4360-4df5-a611-6326a055843e)

---

## Sigma Rule Format Overview

![image](https://github.com/user-attachments/assets/bc0bf4fe-4371-4c22-8e55-0b5763a5bbea)

Sigma rules are written in **YAML** (Yet Another Markup Language), a human-readable and git-friendly format. Each rule consists of four main sections:

### 1. Metadata

This section contains basic information about the rule:

* `title`: A short, descriptive name.
* `status`: Indicates if the rule is active, under testing, or deprecated.
* `description`: A detailed explanation of what the rule detects.
* `author`: Name(s) of the creator(s).
* `tags`: Useful for categorization, such as mapping to the [MITRE ATT\&CK](https://attack.mitre.org/) framework (e.g., `T1059.001` for PowerShell execution).
* `references`: Links to relevant documentation, blog posts, or threat intel reports.

**Example:**

```yaml
status: stable
author: John Doe
title: Admin Share Access
references:
  - https://attack.mitre.org/techniques/T1077/
tags:
  - attack.lateral_movement
  - attack.t1077
```

### 2. Log Source

This section tells us where the data is coming from:

* `category`: General log type (e.g., `firewall`, `process_creation`).
* `product`: Specific vendor or system (e.g., `Windows`, `Symantec`).
* `service`: Particular service (e.g., `ssh`, `dns`).

**Example:**

```yaml
logsource:
  category: process_creation
  product: windows
  service: sysmon
```

### 3. Detection

Here we specify the logic that triggers the rule using selectors:

```yaml
detection:
  selection:
    EventID: 5140
    ShareName: 'Admin$'
  filter:
    AccountName|endswith: '$'
  condition: selection and not filter
```

This example detects access to an admin share (`Admin$`) unless the account ends with a `$` (typically system accounts in Active Directory).

### 4. Condition

Defines how selectors are logically combined (e.g., `and`, `or`, `1 of`).

```yaml
condition: selection or another_selector
```

---

## Realistic Detection Examples

Let’s consider a few examples that demonstrate Sigma’s practical utility:

### Admin Share Mapping

Detecting unauthorized access to administrative shares:

```yaml
EventID: 5140
ShareName: 'Admin$'
```

Exclude typical system accounts:

```yaml
AccountName|endswith: '$'
```

**Real-World Use:** This might catch lateral movement attempts via mapped drives in a Windows domain.

### Antivirus Detection of Hacking Tools

```yaml
Signature|contains:
  - 'mimikatz'
  - 'cobaltstrike'
  - 'powersploit'
```

**Real-World Use:** Matches any AV alert that mentions common red-team or APT tools.

### PsExec Service Abuse

```yaml
selection1:
  EventID: 7045
  ServiceName: 'PSEXESVC'

selection2:
  EventID: 7036
  ServiceName: 'PSEXESVC'

selection3:
  EventID: 1
  Image: '*\\PSEXESVC.exe'

condition: 1 of selection*
```

**Real-World Use:** Detects lateral movement using PsExec across different log sources (Windows logs, Sysmon).

---

## Converting Sigma to SIEM Queries

Writing Sigma is just the first step. You must convert it to your SIEM's native query language.

![image](https://github.com/user-attachments/assets/31c3614a-ca35-4951-bfd5-35b5a20b8f1a)


### Step-by-Step Conversion:

1. **Write the Sigma rule** in YAML.
2. **Use a converter** (like `sigmac`) to transform it to Splunk, Elasticsearch, QRadar, or another SIEM format.
3. **Map field names**: Replace generic field names with the actual field names used in your logs.

```bash
sigmac -t splunk myrule.yml
```

You can also define field mappings in a YAML file to automate this step.

### Why Mapping is Critical

Each environment may log the same event in a different way. For example:

* One system might use `AccountName`, another uses `user.name`.
* If you don’t map correctly, your rule won’t match any events.

![image](https://github.com/user-attachments/assets/7441f4ef-8ffa-4eba-a8b2-a1ac32576ea4)

---

## Automating Sigma Rule Sharing

Automation helps operationalize detection engineering at scale.

### MISP Integration

* **MISP** (Malware Information Sharing Platform) supports Sigma rules as structured objects.
* Use **Sigma2MISP** to push rules to MISP events.
* Anyone subscribed can **pull rules via the MISP API**, convert them, and deploy in their SIEM.

**Use Case:** Threat intel report mentions a new backdoor. The shared Sigma rule is auto-imported, converted, and alerts are generated without human involvement.

---

## Best Practices in Analytic Design and Testing

Writing good analytics is not just about detecting something, but detecting it **reliably and accurately**. Here are some tips:

### Design Considerations

* **Specificity**: More specific rules reduce false positives.
* **List Matching**: Use allowlists/denylists.
* **Patterns**: Regular expressions for flexible string matching.
* **Behavioral Analytics**: Use event sequences or frequency analysis.
* **Anomaly Detection**: Statistical or ML-based methods to detect outliers.

### Example

Instead of detecting every PowerShell use, only alert when PowerShell is launched **with a Base64 encoded command**:

```yaml
Image: 'powershell.exe'
CommandLine|contains: 'Base64'
```

### Testing and Tuning

* **Run historical searches** to see how often your rule matches.
* **Tune thresholds and filters** to suppress noise.
* **Use enrichment** (e.g., user context, geo-IP, device reputation) to improve accuracy.

### Document Everything

* Avoid “tribal knowledge.” Make sure every analytic:

  * Is documented
  * Includes rationale
  * Has references and tags

---

## Summary

Sigma provides a standardized, platform-agnostic approach to creating, sharing, and automating threat detection logic. By understanding its structure, utilizing its flexibility, and integrating it into platforms like MISP, organizations can significantly improve their detection capabilities.

Whether you are writing your first detection rule or building an entire detection engineering pipeline, Sigma gives you the tools and structure to scale efficiently while maintaining clarity and consistency.

---

## Install Sigma

### First: Let's confirm Python itself is recognized:

```powershell
python --version
```

### Second: Let's confirm pip is recognized:

```powershell
pip --version
```

### Third: If the previous two steps worked, try installing sigma Now:

```powershell
pip install sigma
```

```powershell
Collecting sigma
  Downloading sigma-0.0.1-py3-none-any.whl.metadata (879 bytes)
Downloading sigma-0.0.1-py3-none-any.whl (1.4 kB)
Installing collected packages: sigma
Successfully installed sigma-0.0.1
```

----
## Resources

* [Sigma GitHub Repository](https://github.com/SigmaHQ/sigma)
