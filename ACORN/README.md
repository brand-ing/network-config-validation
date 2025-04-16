# ACORN: AI Configuration Oversight for Router Networks

## Author: Brandon I.

### Description:

**What it does**

Imagine you're a network administrator responsible for hundreds of network devices across a company. Each device has a configuration file with hundreds or thousands of lines of settings that determine how the device operates and what security measures are in place.
My tool takes these configuration files, analyzes them using both rule-based checks and machine learning, and then tells you:

* Which devices have security problems
* What specific security issues exist
* How serious each problem is
* How to fix each issue

**How it works**

You upload your network device configuration files to the tool
The tool breaks down these files into understandable components
It runs dozens of security checks on each configuration
AI helps identify patterns that might indicate security issues beyond simple rule checking
The system generates a report with security scores and specific recommendations


**Datasets used**

secrepo
- dhcp traffic (DHCP stands for Dynamic Host Configuration Protocol )
- Yahoo! Password Frequency Corpus (???)
- pcap - packet capture (if this turns into network intrusion)
TII-SSRC-23 Dataset
Gotham Dataset 2025
ZYELL-NCTU NetTraffic-1.0
IoT Inspector Dataset
Questions: How is this data captured? 


CVE
STIGs