#!/bin/bash
# Garrett Beasley - QRadar AlienVault Threat Intel Importer - v0.4
# Place script in /opt/scripts/AV_Reputation/.

# Download Threat Feeds - AlienVault Bad IPs
echo "Downloading AlienVault Threat Intel"
wget -nv -O AV-Reputation.data http://reputation.alienvault.com/reputation.data

# Compute Date Timestamp
fileDateName=$(date +"%Y%m%d_%H%M%S")

# Check to see if AV-Reputation.data.old exists
if [ ! -f AV-Reputation.data.old ]; then
{
  # Notify the user that a old file is not found
  # Note: This only happens on the first run
	echo "Old file not found, Creating a placeholder file"

	# Create placeholder file
  touch AV-Reputation.data.old
}
fi

# Check to see if AV-Reputation.data exists (Download Successful?)
if [ ! -f AV-Reputation.data ]; then
{
	# Notify the user that a downloaded file was not found
	echo "The downloaded file (AV-Reputation.data) was not found. Please check the wget command/internet connection."

	# Pause the session for 5 seconds for the user to see the output
	sleep 5

	# Exit the script
	exit
}
fi

# Compute MD5 of current and old file
echo "Computing MD5 sums"
AVoldMD5=$(md5sum AV-Reputation.data.old | awk '{print $1}')
AVnewMD5=$(md5sum AV-Reputation.data | awk '{print $1}')

# Comparison Logic for threat intel
if [ "$AVoldMD5" != "$AVnewMD5" ]; then
{
  # Notify the user that the hashes do not match.
  echo "Hashes don't match"
  echo "Parsing new threat intel"

  # AV Reputation Parsing
  # Formatting Script (File comes in as a #)
  # Note: AV Threat intel does not utilize cidrs. This command will append /32 to the end of the line
  # Note2: This script assumes your not utilizing the remote network ID of 70 (Malicious Host) / 71 (Spamming).
  # Remote Network Fields: Group <space> Name <space> CIDR <space> Color <space> RRDB <space> Weight <space> Description <space> ID
  awk -F'#' '{print $4","$1}' AV-Reputation.data | sed 's/\b\s\b/_/g' | grep -E "^Malicious_Host," | sort -u | awk -F',' '{print $1" "$2}' | sed 's/^/AlienVault_Reputation /' | sed 's/$/\/32  70/g' > AV_Rep_Malicious_Host.data
  awk -F'#' '{print $4","$1}' AV-Reputation.data | sed 's/\b\s\b/_/g' | grep -E "^Spamming," | sort -u | awk -F',' '{print $1" "$2}' | sed 's/^/AlienVault_Reputation /' | sed 's/$/\/32  71/g' > AV_Rep_Spamming.data

  # Overwrite the old threat intel list with the currently parsed one
  mv -f AV-Reputation.data AV-Reputation.data.old

  # Backup current remote networks config
  yes | cp -i /store/configservices/staging/globalconfig/remotenet.conf /store/configservices/staging/globalconfig/remotenet.conf.old
  echo ""
  yes | cp -i /store/configservices/staging/globalconfig/remotenet.conf ./remotenet.conf.old
  echo ""
  # Command to restore file
  # cp /store/configservices/staging/globalconfig/remotenet.conf.old /store/configservices/staging/globalconfig/remotenet.conf

  # Remove old threat intel
  sed -i '/AlienVault_Reputation/d' /store/configservices/staging/globalconfig/remotenet.conf

  # Merge new threat intel into the remote networks config
  echo "" >> /store/configservices/staging/globalconfig/remotenet.conf
  echo "# AlienVault Reputation Threat Intel - Updated "$fileDateName" #" >> /store/configservices/staging/globalconfig/remotenet.conf
  echo "" >> /store/configservices/staging/globalconfig/remotenet.conf
  cat AV_Rep_*.data >> /store/configservices/staging/globalconfig/remotenet.conf

  # Remote parsed .data files
  rm -f AV_Rep_*.data

  # Notify the user that changes are being deployed.
  echo "QRadar will deploy changes. This can take up to 5 minutes for all services"

  # Deploy QRadar Changes
  /opt/qradar/upgrade/util/setup/upgrades/do_deploy.pl

  # Pause the session for 5 seconds for the user to see the output
  sleep 5

  # Exit the script
  exit
}

# This clause is invoked if the file hashes (AVoldMD5 and AVnewMD5) don't match
else
{
  # Notify the user that the hashes are the same.
  echo "Hashes match, You currently have the latest threat intel."

  # Remove the currently downloaded file
  rm -f AV-Reputation.data

  # Pause the session for 5 seconds for the user to see the output
  sleep 5

  # Exit the script
  exit
}
fi
