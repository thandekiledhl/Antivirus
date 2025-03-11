# Antivirus
A simple Java antivirus scanner that checks files for threats using known signatures and file hashes. 
If a threat is found, the file gets moved to a quarantine folder.

✅ What It Does
Scans a folder for suspicious files.
Detects threats by:
Looking for malicious keywords (signatures).
Matching SHA-256 file hashes.
Moves any infected files to a quarantine folder.
🚀 How to Use
1. Compile the code:
bash
Copy
Edit
javac AdvancedAntivirus.java
2. Run the scanner:
bash
Copy
Edit
java AdvancedAntivirus
✏️ You can change the folders to scan/quarantine by editing these lines in the code:

java
Copy
Edit
String directoryPath = "C:\\Users";       // Folder to scan
String quarantinePath = "C:\\Users";      // Quarantine folder
📂 Folder Structure
css
Copy
Edit
AdvancedAntivirus/
├── AdvancedAntivirus.java     ← Java code
└── README.md                  ← This file
🔍 Sample Output
yaml
Copy
Edit
Scanning: report.docx [SHA-256: ...]
No threats found in file: report.docx

Scanning: trojan.txt [SHA-256: ...]
Threat found! (Signature-based detection)
File moved to quarantine: C:\Users\trojan.txt


