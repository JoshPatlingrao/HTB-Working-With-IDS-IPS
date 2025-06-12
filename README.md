# HTB-Working-With-IDS-IPS
This is a compilation of my notes for this module

### Intro to IDS/IPS
#### Notes
IDS vs IPS
- Intrusion Detection System:
  - Monitors network traffic for suspicious activity
  - Alerts security teams when a threat is detected
  - Passive – doesn’t stop threats, just reports them.
  - Operates in 2 modes:
    - Signature-based detection (matches known threats): accurate but only detects known threats
    - Anomaly-based detection (spots unusual behavior): can detect new threats but may give false alarms
- IPS (Intrusion Prevention System):
  - Also monitors network traffic
  - Active – blocks threats as they are detected
  - Sits inline in the network (directly on the data path)
  - Uses both signature-based and anomaly-based methods
  - Can drop bad packets, block traffic, or reset connections
 
Where
- Both are usually placed behind the firewall to catch threats that get past it
    - IDS is placed to monitor traffic
    - IPS is placed inline to block threats in real time.
- They can also be installed on individual devices (hosts):
  - Host-based IDS (HIDS)
  - Host-based IPS (HIPS)

Why is it Important?
- Part of a defense-in-depth strategy (multiple layers of security)
- Provide visibility and control over network traffic
- Help detect and stop attacks early

IDS/IPS Maintenance
- Regular updates are needed:
  - Threat signatures must stay current
  - Anomaly detection needs tuning to reduce false positives
- Requires ongoing effort by the security team.

Role of SIEM
- SIEM (Security Information and Event Management) systems:
  - Collect and analyze logs from IDS, IPS, and other sources
  - Correlate events to detect advanced or coordinated attacks
  - Provide a centralized view of network security

### Suricata Fundamentals
#### Notes
What is it?
- An open-source tool for network security
- Used in IDS, IPS, and Network Security Monitoring (NSM)
- Developed by the Open Information Security Foundation (OISF), a non-profit, community-led organization

What does it do?
- Monitors all network traffic to detect signs of attacks or suspicious activity
- Can analyze both overall network behavior and specific app-layer traffic (like HTTP, DNS, etc.)
- Uses a set of rules to identify threats, determine what to look for and define its response process

Why is it effective?
- Works on both standard computers and specialized hardware
- Designed for high-speed performance, making it suitable for busy networks
- Flexible and powerful, thanks to community-driven rule updates and support

Operation Modes
- IDS Mode:
  - Monitors traffic quietly without taking action
  - Detects and flags suspicious activity
  - Helps improve network visibility and speeds up incident response
  - Does not block or prevent attacks
- IPS Mode:
  - Actively blocks threats before they enter the internal network
  - All traffic is inspected before it's allowed in
  - Increases security, but may cause latency (slower traffic)
  - Requires deep knowledge of the network to avoid blocking safe traffic
  - Rules must be carefully tested to prevent false positives
- IDPS Mode (Intrusion Detection and Prevention System):
  - A hybrid of IDS and IPS
  - Monitors traffic passively, but can send RST packets (reset connections) when threats are found
  - Offers a balance of protection and performance (less latency than IPS)
  - Good for environments that need some blocking ability without full inline inspection
- NSM Mode (Network Security Monitoring):
  - Focuses only on logging network data
  - No active blocking or alerting—just records everything
  - Useful for investigating incidents later
  - Generates a large volume of data
 
Suricata Inputs and Outputs
- Inputs
  - Offline
    - Reads PCAP files - saved packet captures
    - Useful for:
      - Post-incident analysis (looking at past traffic)
      - Testing rule sets and configurations safely
  - Live
    - Reads real-time traffic from network interfaces.
    - Methods include:
      - LibPCAP:
        - Standard method, but limited performance
        - No load-balancing, not ideal for high-speed networks.
      - NFQ (Netfilter Queue):
        - Linux-specific method for inline IPS mode
        - Works with IPTables to send packets to Suricata
        - Needs drop rules to block threats
      - AF_PACKET:
        - Better performance than LibPCAP
        - Supports multi-threading
        - Can’t be used inline if the machine also routes packets
        - May not work on older Linux systems
    - Note: There are also other, advanced input methods not commonly used.
- Outputs
  - Generates: alerts, logs, detailed network data (DNS queries, network flows, HTTP, TLS, SMTP metadata, etc.)
  - Output Formats
    - EVE JSON:
      - Main and most flexible output format
      - Includes events like: alerts, HTTP/DNS/TLS metadata, network flows, dropped packets
      - Works well with tools like Logstash for analysis.
    - Unified2 Format:
      - Snort-compatible binary alert format
      - Useful for integration with Snort-based tools
      - Can be viewed using the u2spewfoo tool
     
#### Walkthrough
Q1. Filter out only HTTP events from /var/log/suricata/old_eve.json using the the jq command-line JSON processor. Enter the flow_id that you will come across as your answer.
- Open Powershell and SSH to the target, once in, enter the password
  - ssh htb-student@<Target IP>
- Filter for HTTP event in Suricata
  - cat /var/log/suricata/old_eve.json | jq -c 'select(.event_type == "http")'
- You will see from the returned data, all have the same flow_id
- Answer is: 1252204100696793

Q2. Enable the http-log output in suricata.yaml and run Suricata against /home/htb-student/pcaps/suspicious.pcap. Enter the requested PHP page as your answer. Answer format: _.php
- Open Powershell and SSH to the target, once in, enter the password
  - ssh htb-student@<Target IP>
- Enable the http-log output in suricata.yaml
  - sudo nano /etc/suricata/suricata.yaml
  - Scroll down until you find the 'http-log:' section and change 'enabled:' from no to yes
  - Ctrl+S to save
  - Ctrl+X to exit
- Restart Suricata for apply changes
  - sudo systemctl restart suricata
- Run Suricata
  - suricata -r /home/htb-student/pcaps/suspicious.pcap
- Type 'ls' and there should ba a 'http.log' file generated
- Open the 'http.log' file
  - cat http.log
  - Read through the logs to see the .php page that's requested.
- Answer is: app.php
