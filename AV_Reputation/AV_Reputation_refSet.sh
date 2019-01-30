#!/bin/bash
# Garrett Beasley - QRadar AlienVault Threat Intel Importer (RefSet) - v0.2
# Place script in /opt/scripts/AV_Reputation/.

# Download Threat Feeds - AlienVault Bad IPs
echo "Downloading AlienVault Threat Intel"
wget -nv -O AV-Reputation.data http://reputation.alienvault.com/reputation.data

# Get script location
scriptDir=$(pwd)

# Reference Set Name
refSetName=AV_Reputation

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

# Check to see if AV-Reputation.refSet exists
# This file is responsible for creating the reference set for the first time
# Note: This file should not get removed, when it's not present the reference set is created.
if [ ! -f .AV-Reputation.refSet ]; then
{
  # Notify the user that a old file is not found
  # Note: This only happens on the first run
	echo ".AV-Reputation.refSet was not found, this indicates the refernce set was not created"
	echo "Creating reference set $refSetName"

	# Create placeholder file
  touch .AV-Reputation.refSet
	echo "# AV-Reputation.refSet" >> .AV-Reputation.refSet
	echo "# This file is used to let the script know that the reference set ($refSetName) is created already." >> .AV-Reputation.refSet

	# Create the
	/opt/qradar/bin/ReferenceSetUtil.sh create "$refSetName" IP
}
fi

# Compute MD5 of current and old file
echo "Computing MD5 sums"
AVoldMD5=$(md5sum AV-Reputation.data.old | awk '{print $1}')
AVnewMD5=$(md5sum AV-Reputation.data | awk '{print $1}')

# Comparison Logic for threat intel
if [ "$AVoldMD5" != "$AVnewMD5" ]; then
{
  # Notify the user that the hashes do not match
  echo "Hashes don't match"
  echo "Parsing new threat intel"

  # AV Reputation Parsing
  # Formatting Script (File comes in as a #)
	# You can disable bits of the threat intel by commenting out each line (# awk -F'#' ***)
	awk -F'#' '{print $4","$1}' AV-Reputation.data | sed 's/\b\s\b/_/g' | grep -E "^Malicious_Host," | sort -u | awk -F',' '{print $2}' > AV_Rep_Malicious_Host.data
  awk -F'#' '{print $4","$1}' AV-Reputation.data | sed 's/\b\s\b/_/g' | grep -E "^Spamming," | sort -u | awk -F',' '{print $2}' > AV_Rep_Spamming.data

  # Overwrite the old threat intel list with the currently parsed one
  mv -f AV-Reputation.data AV-Reputation.data.old

  # Remove old threat intel from reference set (AV_Reputation)
	# Note: This will remove everything from the reference set
	echo "Clearing the reference set $refSetName"
  /opt/qradar/bin/ReferenceSetUtil.sh purge "$refSetName"

  # Merge new threat intel into the reference set (AV_Reputation)
	for filename in $scriptDir/AV_Rep_*.data; do
	    [ -e "$filename" ] || continue

			# Notify the user that the import is starting for the file/refSetName
			echo ""
			echo "Importing the file $filename" into the reference set $refSetName
			echo ""

			# Imports data for each AV_Rep_*.data file found (parsed threat intel)
			/opt/qradar/bin/ReferenceSetUtil.sh load "$refSetName" $filename

	done

  # Remote parsed .data files
  rm -f AV_Rep_*.data

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
