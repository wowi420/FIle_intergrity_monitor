
# File_Intergrity_Monitor

 ## Overview
 This is a module for my biggest project yet, an mini EDR (Endpoint Detection and Response).
 File_Intergrity_Monitor also known as FIM is one of basic parts of an EDR.
 A daemon Script that monitors files continously for preventing malicious file, made in python

 ## Components
 -Watchdog
 -logging
 -sys
 -hashlib
 -yaml
 -sqlite3
 -pathlib
 -datetime
 -Thread

 ## Core features 
 -Using watchdog to continously monitor the filesystem
 -using hashlib(sha256) to verify the file content
 -Configurable targets, use yaml to direct it on what to monitor(ex. /home, /etc,/bin), 
    note: always use list on "file:" so it wont iterate letter per letter
 
 ## How to config
 config filename: config.yml
 """

 file: ["/home"]
 time: 2026-09-07 19:16:16 <-- this line is useless for now so you can skip this one but i will use it in the near future

 """

 ## External Prequisites/Dependencies
 -watchdog
 -sqlite3
 -yaml/PyYaml

 ## Main Function
 The main function for this module is to assess threat from malicious file and software
 using hash signature

 ## known limitation & Future roadmap
 -SQL Parameterization: Note that filenames with special characters (like quotes) might currently break the time_checker query.
 -Unregistered Files: Note that brand-new files might be missed by the debouncer until the next baseline scan.
 -SELinux Constraints: Mention that running this on aggressively restricted distributions might result in AVC denials without specific policy exceptions.

 ## implementation
 (still on development)