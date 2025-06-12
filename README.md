# HTB-Working-With-IDS-IPS
This is a compilation of my notes for this module

## Intro to IDS/IPS
### Notes
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

## Suricata Fundamentals
### Notes
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

Configuring Suricata & Custom Rules
- After accessing the Suricata instance via SSH, you can view all rule files with a simple command
  - ls -lah /etc/suricata/rules/
- Rules are listed clearly and can be read or inspected to understand what they do
  - more /etc/suricata/rules/emerging-malware.rules
- Some rules might be commented out, meaning:
  - They are not active
  - This usually happens when the rule is outdated or replaced
- Rules often use variables like:
  - $HOME_NET: Your internal network
  - $EXTERNAL_NET: External traffic (like the internet).
- These variables are defined in the suricata.yaml file and can be customized for your own network
  - more /etc/suricata/suricata.yaml
  - Can also create your own variables for better flexibility
  - To load your own custom rules (like local.rules), you need to:
    - Run this command: sudo vim /etc/suricata/suricata.yaml
    - Add /home/htb-student/local.rules to rule-files:
    - Press the Esc key
    - Enter :wq and then, press the Enter key

Hands-on With Suricata Inputs
- Offline Mode
  - Run Suricata with a PCAP file (e.g., suspicious.pcap) to test detection
    - suricata -r /home/htb-student/pcaps/suspicious.pcap
  - Suricata will generate logs like:
    - eve.json (detailed events)
    - fast.log (quick alert summary)
    - stats.log (performance info)
  - You can use flags like:
    - -k to skip checksum checks
    - -l to set a custom output log directory
    - suricata -r /home/htb-student/pcaps/suspicious.pcap -k none -l .
- Live Mode
  - LibPCAP mode: Captures packets live from a network interface
    - Run: ifconfig
      - To find ports to listen to
    - Run: sudo suricata --pcap=ens160 -vv
  - NFQ (Inline IPS mode):
    - Run: sudo iptables -I FORWARD -j NFQUEUE
      - sudo suricata -q 0
    - Requires a specific setup to intercept and analyze live traffic
    - Used for actively blocking malicious packets.
  - AF_PACKET (IDS mode):
    - Run either one:
      - sudo suricata -i ens160
      - sudo suricata --af-packet=ens160
    - Passive monitoring without blocking
    - Supports multi-threading for better performance.
- Observing Live Traffic
  - Open a second SSH session and use tcpreplay to replay PCAP traffic (e.g., from suspicious.pcap) into the live Suricata session
    - sudo  tcpreplay -i ens160 /home/htb-student/pcaps/suspicious.pcap
  - After the test, stop both tcpreplay and Suricata
  - You can find the logs at: /var/log/suricata

Hands-on With Suricata Outputs
- Suricata stores log files in: /var/log/suricata
- Root access is needed to view or manipulate these logs
- Key log files include:
  - eve.json – detailed and versatile (main log)
    - This is an example: less /var/log/suricata/old_eve.json
    - Suricata’s main log file, formatted in JSON
    - Contains rich data like: timestamp, event_type, flow_id, etc.
    - Can be filtered using the jq command
      - View only alert events: cat /var/log/suricata/old_eve.json | jq -c 'select(.event_type == "alert")'
      - Find the first DNS event: cat /var/log/suricata/old_eve.json | jq -c 'select(.event_type == "dns")' | head -1 | jq .
      - Can also filter by TLS, SSH, etc.
    - flow_id:
      - A unique identifier for each network connection ("flow")
      - Helps track and correlate related events in eve.json
      - Useful for understanding everything related to a single communication session
    - pcap_cnt:
      - A packet counter that increments as Suricata processes packets
      - Shows the order of packet processing
      - Helpful for tracing when and where an alert happened in a packet stream.
  - fast.log – quick summary of alerts
    - Run this: cat /var/log/suricata/old_fast.log
    - A quick and readable alert log (text format)
    - Records only alerts
    - Enabled by default.
  - stats.log – performance and diagnostic stats
    - Run this: cat /var/log/suricata/old_stats.log
    - Shows performance statistics and system-level data
    - Useful for debugging or tuning Suricata.
- You can disable the eve.json log if needed and enable specific logs instead
- Example: Enable http-log to get detailed HTTP events
  - When active, a new http.log file is generated every time HTTP traffic is detected.

Hands-on With Suricata Outputs - File Extraction
- Suricata can extract and save files transferred over network protocols (e.g., HTTP)
- This is useful for: threat hunting, forensics and data analysis

How to Enable File Extraction
- Edit suricata.yaml Configuration File
  - Find the file-store section
  - Update the following options:
    - version: 2
    - enabled: yes
    - force-filestore: yes
  - Set the dir option to specify where extracted files will be saved.
- Testing
  - Create a Custom Rule
    - Add this rule to local.rules: alert http any any -> any any (msg:"FILE store all"; filestore; sid:2; rev:1;)
    - This tells Suricata to extract all HTTP-transferred files.
  - Run Suricata on a PCAP File
    - Test with: suricata -r /home/htb-student/pcaps/vm-2.pcap
    - Suricata will: analyze the PCAP, log events, extract files
- Where Files are Stored
  - Extracted files are saved in a folder named filestore
  - Files are stored based on SHA256 hash of their contents
  - Example:
    - File hash starts with f9bc6d...
    - File path will be: /var/log/suricata/filestore/f9/f9bc6d...
- File Inspection
  - Use tools like xxd to inspect file contents in hex format: xxd /var/log/suricata/filestore/21/21742fc6...

Live Rule Reloading
- This feature allows updating rules without restarting Suricata
- Ensures continuous traffic inspection with no downtime

How to Enable Live Rule Reloading
- Edit suricata.yaml:
  - Find the detect-engine section
  - Set the reload option to true:
    - detect-engine:
    - reload: true
- Apply Rule Reloading Without Restarting:
  - Run this command to trigger a ruleset refresh: sudo kill -USR2 $(pidof suricata)

Updating Suricata Rulesets
- Basic Ruleset Update:
  - Run: sudo suricata-update
  - This fetches the latest rules from: https://rules.emergingthreats.net/open/
  - Saves rules to: /var/lib/suricata/rules/
- View Available Ruleset Sources: sudo suricata-update list-sources
- Enable a Specific Ruleset Source (e.g., et/open): sudo suricata-update enable-source et/open
- Fetch & Apply the Enabled Ruleset: sudo suricata-update
- Restart might be needed: sudo systemctl restart suricata
- Before applying changes, test if the config file is valid: sudo suricata -T -c /etc/suricata/suricata.yaml
  - This checks for errors or missing files in the config
  - If Succesful:
    - Suricata runs in test mode
    - Confirmation message: "Configuration provided was successfully loaded. Exiting."

Documentation Recommendation
- Suricata has extensive official documentation
- It’s highly recommended for exploring advanced features and proper configuration
- https://docs.suricata.io/

Key Features
- Deep Packet InspectionL: inspects traffic down to the protocol level.
- Anomaly Detection: flags unusual traffic patterns for analysis.
- IDS/IPS Capabilities: Intrusion Detection, Intrusion Prevention, and hybrid (IDPS) mode.
- Lua Scripting: for writing custom detection logic.
- GeoIP Support: identifies geographic locations of IP addresses.
- IPv4 & IPv6 Support
- IP Reputation: can block or alert based on known malicious IPs.
- File Extraction: extracts files from network traffic for forensics.
- Advanced Protocol Inspection: handles complex protocols (e.g., TLS, HTTP/2, etc.)
- Multitenancy: supports environments with multiple clients or networks.

Extra Note: Detecting Anomalies
- Suricata can detect non-standard or abnormal network traffic
- Refer to the Protocol Anomalies Detection section in Suricata’s docs
- This improves visibility and security against protocol misuse.

### Walkthrough
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
