# QRadar-ThreatIntel-Import
Automatic Threat Intel Importer

This repo contains custom QRadar scripts that I utilize in my home lab to automatically pull threat intelligence into the SIEM. I have released them for anyone to utilize in their own QRadar instance. If you have any questions you can create an issue for the GitHub project or open a question/reply on the IBM QRadar CE forms located at: https://ibm.biz/qradarceforums

# Scripts
  - AV_Reputation/AV_Reputation.sh
    - AV_Reputation_refSet.sh
  - ET_Reputation
    - ET_TOR_Reputation_refSet.sh
  - FH_Reputation
    - Greensnow_refSet.sh

# Cron Job Setup (Example: ET_Tor)
1. Using SSH, log in to the QRadar Console as the root user.
2. Crontab -e
3. Add the following to the end of the file
```
  # Custom Threat Intel Scripts
  0 0 * * 1 cd /opt/scripts/ET_Reputation/ && ./ET_TOR_Reputation_refSet.sh > /dev/null 2>&1
```
4. Exit and save by typing :wq!

# Notes
  - As I get more time I will develop addition scripts to parse newer threat feeds. If you have a request leave an issue on the repo with a link to the threat feed download and I will see if I can get the time to parse it!

# Change Log
  - 06-20-2019 - Fixed spelling in old scripts. Added threat list for greensnow (http://iplists.firehol.org/?ipset=greensnow)
  - 04-14-2019 - Fixed Readme for correct Cronjob steps
  - 02-16-2019 - Modified ET_TOR_Reputation script for parsing from Firehol instead of directly from the ET rules file.
  - 02-02-2019 - Created ET_TOR_Reputation script for importing known TOR nodes/relays. This script will parse the snort rule (.rules) file and upload all IPs to a reference set.
  - 01-29-2019 - Created a reference set version of (AV_Reputation) import script. This allows for avoiding the deploy changes and provides better performance.
  - 01-28-2019 - Initial Upload of AV_Reputation (AlienVault) import script.
