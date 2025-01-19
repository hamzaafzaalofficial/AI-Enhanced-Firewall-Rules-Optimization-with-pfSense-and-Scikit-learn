# AI-Enhanced Firewall Rules Optimization with pfSense and Scikit-learn

This project leverages machine learning to optimize firewall rules for pfSense. It analyzes network traffic logs, identifies patterns, and generates recommendations for firewall rule adjustments using clustering and classification techniques.

---

## System Overview

### 1. pfSense Firewall
**Role:** Captures and logs network traffic.  
**Actions:**
- Collects firewall logs from `/var/log/filter.log`.
- Exports logs to a file for analysis (`/tmp/firewall_export.log`).

---

### 2. Data Preprocessing
**Role:** Prepares raw firewall logs for analysis.  
**Actions:**
- Loads exported logs into a Python environment.
- Cleans and preprocesses the data (e.g., assigns column names, filters relevant features).

---

### 3. Machine Learning Model
**Role:** Analyzes traffic patterns and generates recommendations.  

**Components:**
- **Clustering (KMeans):**
  - Groups similar traffic patterns (e.g., by IP ranges or ports).
  - Detects anomalies and calculates block rates for each cluster.
- **Classification (Decision Tree):**
  - Predicts whether traffic should be allowed or blocked.
  - Identifies important features (e.g., ports, protocols) using feature importance.

---

### 4. Rule Generation
**Role:** Generates optimized firewall rules based on the analysis.  
**Actions:**
- Suggests `BLOCK` rules for clusters with high block rates.
- Suggests `ALLOW` rules for clusters with low block rates.
- Adjusts rules based on feature importance (e.g., UDP protocol, specific ports).

---

### 5. Firewall Rule Implementation
**Role:** Applies the optimized rules in pfSense.  
**Actions:**
- Updates firewall rules in the pfSense dashboard.
- Tests the new rules using tools like `ping` and `traceroute`.

---

### 6. Continuous Monitoring
**Role:** Ensures the effectiveness of the optimized rules.  
**Actions:**
- Monitors traffic logs for anomalies.
- Periodically re-evaluates and fine-tunes the rules.

---

## Flow of the System
1. Traffic logs are collected from pfSense and exported for analysis.
2. The logs are preprocessed and loaded into a Python environment.
3. The machine learning model analyzes the traffic using clustering and classification.
4. Based on the analysis, optimized firewall rules are generated.
5. The rules are implemented in pfSense and tested for effectiveness.
6. The system continuously monitors traffic and fine-tunes the rules as needed.

---

## Requirements
- pfSense firewall with logging enabled.
- Python environment with libraries: `scikit-learn`, `pandas`, `numpy`.
- Access to pfSense dashboard for rule implementation.

---

## Usage
1. Export firewall logs from pfSense to `/tmp/firewall_export.log`.
2. Run the Python script to preprocess and analyze the logs.
3. Review the generated rules and implement them in pfSense.
4. Monitor traffic and re-evaluate rules periodically.

