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

### Nmap

## Network protocol analyzers

# Securing individual systems 

# Securing the basic LAN

# Securing Wireless LANs

# Securing Virtal and Cloud Environments

# Securing Dedicated and Mobile systems

# Secure protocols and applications

# Testing infrastructure

# Business Security impact

# Dealing with incidents
