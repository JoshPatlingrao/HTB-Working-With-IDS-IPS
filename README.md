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

## Suricata Rule Dev Pt. 1
### Notes
Suricata Rules
- Suricata rules instruct the engine to watch for specific patterns in network traffic
- They’re used for:
  - Detecting malicious behavior
  - Providing contextual network insights (e.g., tracking specific activity)
- Rules can be broad or specific depending on detection goals
- Well-crafted rules balance detection coverage vs. false positives
- Rule creation often relies on threat intelligence and community-shared indicators
- Each rule consumes system resources (CPU & RAM)

Suricata Rule Anatomy
- General Rule Format: action protocol from_ip port -> to_ip port (rule options)
- Header Section: The header of a rule defines the action, protocol, IP addresses, ports, and traffic direction for how the rule should be applied.
  - action: tells Suricata what to do if contents match
    - alert: generates alert
    - log: log traffic without an alert
    - pass: ignore the packet
    - drop: drop packet in IPS mode
    - reject: send TCP RST packets
  - protocol: tcp, udp, icmp, http, dns, etc.
  - directionality: ->, <-, <>
    - Uses rule host variables: $HOME_NET, $EXTERNAL_NET
    - Example:
      - Outbound: $HOME_NET any -> $EXTERNAL_NET 9090
      - Inbound: $EXTERNAL_NET any -> $HOME_NET 8443
      - Bidirectional: $EXTERNAL_NET any <> $HOME_NET any
    - Rule ports define the ports at which the traffic for this rule will be evaluated
- Rule Message & Content: The message and content section specifies the alert message to display when a rule is triggered and defines the traffic patterns considered important for detection.
  - Message: shown when rule is triggered. Should describe malware name/type or behavior.
    - Flow: specifies the initiator and responder of the connection and ensures the rule monitors only established TCP sessions
      - E.g. alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"Potential HTTP-based attack"; flow:established,to_server; sid:1003;)
    - DSize: matches based on the payload size of a packet, using the TCP segment length, not the total packet length
      - E.g. alert http any any -> any any (msg:"Large HTTP response"; dsize:>10000; content:"HTTP/1.1 200 OK"; sid:2003;)
  - Rule Content: contains unique values used to identify specific traffic, which Suricata matches in packet payloads for detection
    - Rule Buffers: limit content matching to specific parts of a packet, improving efficiency by reducing unnecessary searches
      - E.g. alert http any any -> any any (http.accept; content:"image/gif"; sid:1;)
        - http.accept: Sticky buffer to match on the HTTP Accept header. Only contains the header value. The \r\n after the header are not part of the buffer.
    - Rule Options: act as additional modifiers to aid detection, helping Suricata locate the exact location of contents
      - nocase: ensures rules are not bypassed through case changes
      - offset: informs Suricata about the start position inside the packet for matching
        - E.g. alert tcp any any -> any any (msg:"Detect specific protocol command"; content:"|01 02 03|"; offset:0; depth:5; sid:3003;)
          - This rule alerts when a specific byte sequence (|01 02 03|) is found at the start of the TCP payload.
          - The offset:0 keyword sets the content match to start from the beginning of the payload, and depth:5 specifies a length of five bytes to be considered for matching
      - distance: tells Suricata to look for the specified content 'n' bytes relative to the previous match
        - E.g. alert tcp any any -> any any (msg:"Detect suspicious URL path"; content:"/admin"; offset:4; depth:10; distance:20; within:50; sid:3001;)
          - This rule alerts when the string /admin is found in the TCP payload, starting at byte 5 (offset:4) within a 10-byte window (depth:10).
          - It uses distance:20 to skip 20 bytes after a prior match and within:50 to ensure the match happens within the next 50 bytes.
  - Rule Metadata
    - reference: links the rule to its original source
    - sid: is a unique identifier for managing and distinguishing rules
    - revision: shows the rule's version history and any updates made
- Pearl Compatible Regular Expression (PCRE): uses regular expressions for advanced matching, written between forward slashes with optional flags at the end. Use anchors for position control and escape special characters as needed. Avoid creating rules that rely only on PCRE.
  - E.g. alert http any any -> $HOME_NET any (msg: "ATTACK [PTsecurity] Apache Continuum <= v1.4.2 CMD Injection"; content: "POST"; http_method; content: "/continuum/saveInstallation.action"; offset: 0; depth: 34; http_uri; content: "installation.varValue="; nocase; http_client_body; pcre: !"/^\$?[\sa-z\\_0-9.-]*(\&|$)/iRP"; flow: to_server, established;sid: 10000048; rev: 1;)
    - Rule triggers on HTTP traffic (alert http) from any source and destination to any port on the home network (any any -> $HOME_NET any)
    - The msg field gives a description of what the alert is for, namely ATTACK [PTsecurity] Apache Continuum <= v1.4.2 CMD Injection
    - The rule checks for the POST string in the HTTP method using the content and http_method keywords. The rule will match if the HTTP method used is a POST request
    - The content keyword with http_uri matches the URI /continuum/saveInstallation.action, starting at offset 0 with a depth of 34, targeting a specific Apache Continuum endpoint
    - Another content keyword searches for installation.varValue= in the HTTP client body, using nocase for case-insensitive matching, potentially detecting command injection payloads
    - PCRE in this case was used to implement Perl Compatible Regular Expressions
      - ^ marks the start of the line
      - \$? checks for an optional dollar sign at the start
      - [\sa-z\\_0-9.-]* matches zero or more (*) of the characters in the set. The set includes:
        - \s a space
        - a-z any lowercase letter
        - \\ a backslash
        - _ an underscore
        - 0-9 any digit
        - . a period
        - '-' a hyphen
          - Speech marks shouldn't be there. Only done since it messes up formatting
        - (\&|$) checks for either an ampersand or the end of the line
        - /iRP at the end indicates this is an inverted match (meaning the rule triggers when the match does not occur), case insensitive (i), and relative to the buffer position (RP).
    - The flow keyword specifies that the rule triggers on established, inbound traffic directed toward the server.
- Refer to: https://docs.suricata.io/en/latest/rules/index.html
  - For more info on Suricata rules

IDS/IPS Rule Development Approaches
Creating IDS/IPS rules involves both technical expertise and threat awareness
- Signature-based detection uses known patterns, like commands or strings, to identify specific malware with high accuracy, but can't detect new threats
- Behavior-based detection looks for anomalous activity (e.g., unusual response sizes or traffic patterns) to catch unknown or zero-day attacks, but may produce more false positives
- Stateful protocol analysis tracks protocol state and flags unexpected behavior, offering deeper insight into malicious activity within normal-looking traffic.

### Walkthrough
Q1. In the /home/htb-student directory of this section's target, there is a file called local.rules. Within this file, there is a rule with sid 2024217, which is associated with the MS17-010 exploit. Additionally, there is a PCAP file named eternalblue.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to MS17-010. What is the minimum offset value that can be set to trigger an alert?
- Open the rules and adjust the offset. Hint: go lower.
  - sudo nano /home/htb-student/local.rules
- Reset Suricata so the rules will apply.
  - sudo systemctl restart suricata
- Run Suricata on the .pcap file
  - sudo suricata -r /home/htb-student/pcaps/eternalblue.pcap -k none -l .
- Check the fast.log file to see if the alarm raised or not
  - sudo cat /var/log/suricata/fast.log
- Keep playing around until alarm is not raised anymore and the minimum is found.
- Answer is: 4

## Suricata Rule Dev Pt. 2
### Notes
Although encryption hides payloads, valuable metadata remains visible. Two key tools for detecting threats in encrypted traffic are:
- SSL/TLS Certificate Analysis
  - SSL certificates (shared during the handshake) contain unencrypted metadata like issuer, subject, and expiration
  - Suspicious domains often have odd or uncommon certificate details, which can be used to write detection rules
- JA3 Fingerprinting
  - JA3 generates a unique fingerprint of SSL/TLS client behavior from the Client Hello packet
  - Malware often uses distinct JA3 hashes, making them useful for identifying malicious encrypted traffic
- These techniques help craft Suricata rules that detect threats even without decrypting the traffic.

### Walkthrough
Q1. There is a file named trickbot.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to a certain variation of the Trickbot malware. Enter the precise string that should be specified in the content keyword of the rule with sid 100299 within the local.rules file so that an alert is triggered as your answer.
- Get the JA3 Digest of trickbot.pcap
  - ja3 -a --json /home/htb-student/pcaps/trickbot.pcap
- Answer is: 72a589da586844d7f0818ce684948eea
