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

### Basics

* Cryptograpy: take data and make it confidential
* Obfuscation: Take something that makes sense and hide it to make it not make sense
* Encryption / decryption: obfuscating something, and then being able to return it back to its original

Classic cryptography components
* algorithm
* key for encryption

### Hashing

In charge of the integrity of the data. 
Hash is a mathematical function to check that the information has not changed between the encryption and the decrpytion, or the transfer of the data. 
Any piece of text, of whatever value, and whatever size, will be processed by the hash function, and the output will be the same size, and with a different value for each input. a will have an entire different value from b or aa, but the size of the output will be the same. 
A message digest is a numeric representation of a message computed by a cryptographic hash algorithm or a function.
If two different inputs have the same message digest, it is considered a collision, which makes the hashing algorithm not acceptable. 
Commonly used for passwords.

### Cryptographic attacks

### Password cracking
