Course: 
TOTAL: CompTIA Security+ Certification Course by Total Seminars
# Risk Management

## Business Risk

* Risk: Potential for a threat (malicious actor) to exploit a vulnerability (weakness in our system) and cause harm to our asset (what we want to protect)

### CIA Triad

* Confidentiality: Data is only accessible to those with the authority to see it
* Integrity: Data remains unaltered and genuine
* Availability: Ensures systems, applications, and data are accessible and operational when needed

## Threats

### Types of threats

* External
* Internal
* Resource availability (funding)
* Capability (Man-power)
* Sophisticaion (script-kiddie vs state actor)
* Capability (low, medium, high)

### Allowed application list

Allowed list of applications that can be used within the company.  
This is to avoid unknown or potentially dangerous tools to enter the network. 

## Risk Management Concepts

### Risk Vectors

Path, method, or means by which an attacker can break into a computer system. 

Digital and physical risk vectors

* Mission critical systems
* sensitive data
* third-party access

#### Types of security policies

* Acceptable use policy (AUP): E-mail, social media, etc
* Resource access policies: app, or file access
* Account policies: Account hardening
* Data retention policies
* Change control policies
* Asset management policies

## Security Controls

Implemented differently based on platform/vendor/user

* Solution that mitigates threats: Malware scanner mitigates malware infections

### Security control categories

* Managerial / administrative: employee background checks
* Operational: periodic review of security policies
* Technical: firewall rule configuration
* Physical: Gates or mantraps
* Detective: Log analysis
* Corrective: Patching known vulnerabilities
* Deterrent: Device logon warning banners
* Compensating: Network isolation for IoT (compensates for another control which cannot be implemented, or helps with another control)

## Example

Risk: Theft of online banking credentials
Attack vector: spoofed email message with a link to a spoofed website tricking an end user
Mitigation through security controls: user security awareness, antivirus software, spam filters

## Risk assessments and treatments

Prioritizing threats against assets and determining what to do about it

Applicable to: 
* entire organization
* a singple oroject or deparment

targets: 
* servers
* legacy systems
* intellectual property
* software licensing

### Risk assessment process

* Risk awareness: Cybersecurity intelligence sources
* Evaluate security controls
* implement security controls
* periodic review

#### Risk types
* Environmental: earthquakes
* person-made: terrorism
* internal: malicious insider
* external: DDoS

#### Risk treatments

* mitigation / reduction: security controls set proactively put in place before undertaking the risk
* transference / sharing: some risk is transferred to a third party in exchange for payment (cybersecurity insurance)
* avoidance: avoid an activity because the risks outweight potential gains
* acceptance: the current level of risk is acceptable

## Quantitative risk assessment

Based on numeric values (usually money)
Based on asset value (AV) and exposure factor (EF)
asset value: self-explanatory
exposure factor: percentage of asset value loss when negative incident occurs

### Single loss expectancy (SLE)

how much loss is experienced during one negative incident?
multiply AV by the EF

### Annualized rate of occurrence (ARO)

Expected number of yearly occurrences: 2-3 times a year

### Annualized loss expectancy (ALE)

total yearly cost of bad things happening
ALE: SLE * ARO

## Qualitative risk assessment

Subjective opinion regarding: threat likelihood and impact of realized threat, based on severity rating

These risks are set in a risk register

### Risk register

Organizations should have one
centralized list of risks, severities, responsibilities and mitigations
generally considered qualitative

## Security and the information life cycle

security involved at every phase of data collection

example: 
1. collect
2. store
3. process
4. share
5. archive and deletion

### Personally identifiable information
one or more pieces of information that can be traced back to an individual

### Protected health information

same, but for medical information

### privacy-enhancing technologies

* anonymization
usually allowed to be used (anonymized data) and collected without consent
anonymized data has limited marketing value
* pseudo-anonymization: replace PII with fake identifiers
* data minimization: limit stored / retained sensitive data
* tokenization: a digital token authorizes access instead of the original credentials
* data masking: hide sensitive data from unauthorized users

### data sovereignty

location of data and laws that apply to it

### Data destruction

#### Physical
paper, film, magnetic tape

* burning
* pulping
* shredding

#### Digital

failed or decommissioned storage devices

### Digital media sanitization

data is still recoverable with deleted files, repartitioned, or reformatted drives

disk wiping tools:
* ssd and hd: multiple disk overwrites
* hd only: degaussing (strong magnetic field)
* cryptographic destruction: destroying the key of an encrypted disk, making it impossible to access the decrypted data

# Cryptography

## Basics

* Cryptograpy: take data and make it confidential
* Obfuscation: Take something that makes sense and hide it to make it not make sense
* Encryption / decryption: obfuscating something, and then being able to return it back to its original

Classic cryptography components
* algorithm
* key for encryption

## Hashing

In charge of the integrity of the data. 
Hash is a mathematical function to check that the information has not changed between the encryption and the decrpytion, or the transfer of the data. 
Any piece of text, of whatever value, and whatever size, will be processed by the hash function, and the output will be the same size, and with a different value for each input. a will have an entire different value from b or aa, but the size of the output will be the same. 
A message digest is a numeric representation of a message computed by a cryptographic hash algorithm or a function.
If two different inputs have the same message digest, it is considered a collision, which makes the hashing algorithm not acceptable. 
Commonly used for passwords.

## Cryptographic attacks

Cryptanalysis: breaking cryptography
Attack the algorithm: attacking an algorithm such as AES would be too complicated. Instead, it can be tried to trick the user into using a weaker algorithm, and then crack the hash of the weaker algorithm.
Attack the implementation: the hashing algorithm may be strong, but the way it is used may be weak

## Password cracking

* Brute force: trying every possible combination until you get the password.
* Dictionary attack: uses a Dictionary with a lot of commonly used passwords, or just human sounding words for the brute force attack
* rainbow table: uses a precomputed table that contains the password hash value for each plain text character used during the authentication process.

* salting: using a random value (which may or may not be secret) that gets appended to the password before hashing, to make pre-hashed tables useless.

# Physical security

Physical security: physical controls to avoid damages to the physical assets, or them being stolen, corrupted, etc. 
Do not allow unauthorized people plugging in the network.
* key logger: deivce connected as the middle man between the system and the keyboard to store the typed keys and their order. 

## Personnel

guards
badges
visitor logs
robot sentries
reception

## facility security
### Location
undisclosed address
protection from natural disasters

signage
fencing
bollards / barricades
industrial camouflage
motion detection and video surveillance

## Environmental controls

### Server room airflow management

keep incoming cool air separated from outgoing warmer air
draw in cool air to equiment
draw hot air from equipment out
Use containment panels/curtains to keep cool and warm air from mixing
blanking panels: fill empty rack slots to optimize airflow

sensors such as temperature, pressure, humidity, noise, proximity

# Identity and account management

Identification: Stating your identity
authentication: confirming your identity (proving it)
authorization: once confirmed, what you have permissions to do. determines resources permissions, permissions granted. can only occur after authentication
accounting: auditing (monitoring of the user, what they access, what they do, failed logon attempts, changes and modifications)

## Multifactor authentication (MFA)
Using more than one factor of authentication

### Factors
* something you know
* something you have
* something you are

### Attributes

something you do (signature)
something you exhibit: personality traits, neurological behaviors, the way you walk, or talk, or behave, etc
someone you know
somewhere you are

## Authentication methods

* password vaults or managers. a master key protects all other passwords
* One-time password: unique password or code generated for a single use. static code sent via e-mail or sms text. valid for a short period
* Certificate based authentication: PKI certificates are issued by a trusted authority to an individual entity
* SSH public key authentication: sign in with username and password as well as private key
* Biometrics: fingerprint, retina, iris, facial, voice, bein, gait analysis

## Access control schemes

### Credential policies
Defines who gets access to what: employees, comtractors, devices, service accounts, administrator

### Attribute-based access control
uses attributes to determine permissions.
date of birth, device type, team

### Role based access control

a role is a collection of related permissions. role occupants get permissions of the role

### Rule based access control

Uses conditional access policies: MFA, device type, location

### Mandatory access control

resources are labeled: devices, files, databases, network ports, etc. 
permission assignments are based on resource labels and security clearance

### Discreationary access control

data custodian sets permissions at their discretion

## Account management

### User accounts

* unique account per user
* assign permissions to groups, and individuals to groups 
* principle of least privilege
* user account auditing
* disablement of accounts instead of deletion if a user leaves the organization

### account types
* user, device, service
* administrator/root
* privileged
* guest

### Account policies

They guide password policies, employee onboarding, account lockout
* time-based logins: enforce login/logout times 
* geolocation: where users can be located to access specific resources (geofencing), locates the user, geotagging (adding location metadata to files and social media posts)
* risky login: anything outside of the normal may be categorized as a risky login.

## Network authentication

* Password authentication protocol: outdated, cleartext transmissions
* microsoft challenge handshake authentication protocol
* Microsoft new technology LAN manager
* Kerberos: microsoft active directory authentication, Kerberos key distribution center, authentication service, ticket granting service, ticket granting ticket 

## Identity management system

### Single sign on 
user credentials are not requested after initial authentication
Protocols: OpenID, OAuth

### Identity federation

multiple resources that trust a single authentication source. 
Centralized trusted identity provider (IdP)
Security assertion markup language (SAML): token is a digital security token that proves identity

# Tools of the trade

## CLI

* Ping: basic command to test connections
* ipconfig (windows) / ifconfig (linux/mac): used to check configuration of your network in your device
* reverse shell: advanced persistent threat (APT). attacker has a way into the system repeatedly. netcat, metasploit, cobalt strike

### Linux Shell

case sensitive
shell scripts (.sh) must be flagged as executable
for security, dont sign in with root account
sudo is for elevated privileges
remotely accessible: secure shell (SSH) over TCP port 22

Commands for key gen: 
* ssh-keygen -t rsa: ssh-keygen is the command to create a ssh key. -t indicates the type of key, and the type, in this example, is RSA. 
It will generate a private key, and it will prompt for the name of the file, with one by default. It will also ask for a password, but by default, there is no password.
It will also generate a public key. 
* ls would not show the key, unless you use the -a flag, which shows hidden files and folders.
* ssh-copy-id: copies the ssh publick key into the authorized keys file. 
* mount: mounts a subdirectory to either a disk or remotely. 

### Windows Command Line

cmd.exe
may need to run with elevated privileges
batch file scripts: file extension is .bat 

### Windows PowerShell

runs on windows, linux, macos
object-oriented
may need to run with elevated privileges
PowerShell scripts: file extension is .ps1
uses libraries/modules that dictate available commands

## Network scanners

Attackers use this for reconnaissance
Very loud on the network (easily detected)
scan network nodes and shows: 
* ip address
* mac address
* operating system
* open ports
recommended periodic network scans to identify differences (rogue systems, new listening ports, etc.)
most common network scanner: 
nmap

## Network protocol analyzers

Capture network traffic.
* depends on network placement
* hardware or software level
* network switch port analyzer (SPAN) copies all VLAN traffic to one switch port
* wired and wireless capturing
* captures can be saved
* packets are easily forged with free tools such as hping3

## Log Files

Used for network, host, and device monitoring. 
Potential indicators of compromise (IoC)
Must ensure log files are secure. forward log entries to a centralized logging host, in case the system gets compromised, the logs are not. 

### Log Tools

Windows: event viewer, powershell
Linux: /var/log, logger, jorunalctl

### Centralized logging

* Simple Network Management Protocol (SNMP): bandwidth monitoring, software agent or built into firmware, snmp traps notify snmp management stations

#### Linux Centralized Logging 

Syslog / rsyslog
normally uses UDP port 5l4
filter trafic that gets sent 

#### Linux log forwarding

* modify /etc/rsyslog.conf to enable module(load="imudp") and input(type="imudp" port="514"). you can change the port number. this will enable the linux system to listen for logs (UDP)
* sudo service rsyslog restart: restarts the rsyslog service to accept the recent changes. 
* to send the logs, you need to modify the same file in the other system with a line including the logs you want to send (*.* to send everything) and a @{ip_address} to the direction you want to send them.

#### Windows Centralized Logging 

Event viewer subscriptions: send local log data to a collector server over the WinRM protocol 

### Security Information and Event Management (SIEM)

Sensors / collectors: logs, intrusion detection / prevention system, packet captures, antivirus
Enterprise-level centralized log ingestion service
Dashboard visualizations: alerts, packet captures, malware alerts, etc. identify trends and correlation

#### SIEM process

* data inputs
* log aggregation
* analysis 
* review reports

## Cybersecurity Benchmark tools 

* benchmarking: taking times / results in order to compare to the industry standard to see where you fit, to verify if your system is healthy or not. 
Industry leading security configuration standards. 
Define minimum level of security to meet standards or regulatory requirements. 
In the US: National Institute of Standards and Technology (NIST)
technical guidelines for federal agencies and other organizations.

NIST lifecycle: 
* identify: 
* protect: 
* detect: 
* respond: 
* recover: 

### CIS

Center for Internet Security 
Best practices for securely configuring a system. 

### DoD Cyber Exchange STIGs
From the US deparment of defense. 
Security technical implementation guides (STIGs)

### Security Content Automation Protocol (SCAP)

Collection of standards. 
Maintain the security of systems by automatically finding vulnerabilities in real-time. 

### Benchmark types

#### Agent-based

Software installed on devices to monitor and protect them. 
Continuous surveillance and action. 
Identify and handle security threats. 
Ensure organizational security policy compliance. 

#### Agentless

Dont require software on each device. 
Less intrusive.
Less impact on system performance. 
Rely on network connections. 
Can scan for vulnerabilities without direct system access. 

# Securing individual systems 

## Malware 

Software that is detrimental to the operation of a host. 
First example of this is a virus. 

### Virus

Pre-date the internet.
Program that can replicate only through definite user interaction. 
Activates once a user clicks or downloads. 
Fileless malware/virus: no file, lives only in memory. Difficult for anti-malware to detect. 

### Ransomware

Cryptomalware / cryptoransomware: uses encryption to lock a user out of a system.
Attacker hides your data until you pay a ransom. 

### Worm

Virus that, once started, replicates itself. 
More like a pathway for replication. 
Most of the malware that is seen nowadays.

### Trojan horse

A program that looks benign, but in fact hides a nefarious prrogram inside it. 
No replication by themselves. 
Remote access trojan (RAT): Maliciously takes control of a system remotely. 

### Backdoor

Not necessarily nefarious.
Created by developers as easy maintenances entry point. 
Can be exploited by attackers if left open by developers. 
Can be created in a program by hackers to gain access. 

### Potentially Unwanted Programs (PUPs)

Software that may have negative or undesirable effects. 
Crapware, adware, spyware, bloatware. 

### Bots / botnets

Distributed attack using remotely controlled malware controlling several computers, often running some kind of RAT. 
Hosts are called bots or zombies. 
One kind of botnet attack is a DDoS attack: Overload of traffic that makes resources unavailable for legitimate users. 
Command and control (C2 / C&C): Protocols that automate the control, not requiring human interaction after the initial programming. 

### Keylogger

Hardware: Device that plugs in between keyboard and computer to log keystrokes. Many have WAPs built in for remote access. 
Software: Program that logs keystrokes. Most anti-malware can find nefarious software keyloggers. 

### Rootkit

Can often be somewhat invisible.
Goal is to get root access to a system. 
Usually installed on the boot of the systems they are attacking. 

### Logic Bomb

Often a script set to execute.
Created with a timer to go off at a specific time or during a specific event on a system. 
Does not replicate. 

## Weak configurations

### Open permissions: 
* Open wireless networks
* Guest user accounts 
* No intruder lockout settings (failed login limits)
* Too many file or app permissions 

### Linux root account: 
* dont sign in with root account 
* use sudo to run privileged commands 
* Disallow remote access as root 
* use su to temporarily switch to root 

### Insecure cryptographic solutions 

Wi-fi wired equivalent privacy (WEP): Use WPA2 or WPA3
Digital Encryption Standard (DES): Use AES 
Secure Sockets Layer (SSL): Use TLS
Transport Layer Security: Secure after versions 1.2

### Change default settings 

IP address 
Open port numbers 
web server root filesystem location: directory traversal attacks 
username and password policies 

### On-premises

### Cloud solutions 

## Common attacks 

### 0-day attack
Vulnerability found by a researcher or attacker that is unknown by the vendor and the public. 
Zero day initiative: Encourages the private reporting of vulnerabilities to vendors. 

### DNS sinkholing

Return false DNS query results 

### Privilege escalation

Attacker acquires a higher level of access: Compromising an admin account that has a weak password. 

### Replay attack

Attacker intercepts and later retransmits or uses sensitive data. 

### Pointer / object dereference

Attacker manipulates memory pointers to point to unexpected memory locations. 
Normally causes software to crash (DoS attack).

### Error handling 

Improper handling can crash a system. 
Disclosure of too much information. 

### Dynamic Link Library (DLL) Injection

Attacker places malicious DLL in the file system. 
Legitimate running processes call malicious code within the DLL. 

### Resource exhaustion

Dos or DDoS
Memory leaks. 

### Race conditions 

Code runtime phenomenon
Action that might occur before security controls is in effect 
Based on timing

### Overflow attacks

* Memory injections 
* Buffer overflow

### Password attacks 

Online vs offline

Tools: 
* john the ripper
* cain and abel 
* hydra 

Dictionary: 
* uses common username / password files 
* tries thousands or millions of likely possibilities to login to a user account 

* Brute force: try every possible combination of characters. Multiple attempts should trigger an account lockout.
* Password Spraying: Blast many accounts with a best-guess common password before trying a new password. Slower (per user account) than traditional attacks, but less likely to trigger account lockouts. 

## Bots and botnets 

### Bot

Single infected device under attacker control. AKA Zombie 
Periodically talks to command and control (C2 / C&C) attacker server. 
Mitigate with IDS 
Attacker might have directions stored in a DNS TXT record.
Network IDS might detect this. 

### Botnet

Collection of infected devices under attacker control

## Disk RAID levels 

Redundant array of inexpensive disks 
Groups disks together to work as one, for better performance and high data availability. 
Hardware level and software level (slower and less reliable than hardware RAID)

### Storage Area Network (SAN)

Storage distributed on a network. 

### RAID levels 

* RAID 0: Disk striping: data is broken into stripes and each stripe is written to a separate disk in the array. Lose one disk, lose everything. Great for performance, but terrible for availability
* RAID 1: Disk mirroring: Data is entirely written to two separate disks. good for performance and availability
* RAID 5: Disk striping with distributed parity. Data stripes and the related parity are stored on separate disks. Very good for availability but not so good for performance.
* RAID 6: requires at least 4 disks. stores 2 parity stripes on each disk. can tolerate failure of 2 disks. 
* RAID 10: RAID level 1, then 0. Disk mirroring, then striping. Requires at least 4 disks. 

## Securing hardware 

## Securing endpoints 

## Securing data with encryption



# Securing the basic LAN

# Securing Wireless LANs

# Securing Virtal and Cloud Environments

# Securing Dedicated and Mobile systems

# Secure protocols and applications

# Testing infrastructure

# Business Security impact

# Dealing with incidents
