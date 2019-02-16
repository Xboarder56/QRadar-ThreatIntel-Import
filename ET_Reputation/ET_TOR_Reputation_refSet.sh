#!/bin/bash
# Garrett Beasley - QRadar ET Firehole Intel Importer (RefSet)
# Place script in /opt/scripts/ET_Reputation/.

# Download Threat Feeds - Emering Threats Intel
echo "Downloading Emering Threats Intel from Firehole"
wget -nv -O et_tor.ipset https://iplists.firehol.org/files/et_tor.ipset

# Get script location
scriptDir=$(pwd)

# Compute Date Timestamp
fileDateName=$(date +"%Y%m%d_%H%M%S")

# Reference Set Name
refSetName=ET_Tor

# Check to see if et_tor.ipset.old exists
if [ ! -f et_tor.ipset.old ]; then
{
	# Notify the user that a old file is not found
	# Note: This only happens on the first run
	echo "Old file not found, Creating a placeholder file"

	# Create placeholder file
	touch et_tor.ipset.old
}
fi

# Check to see if et_tor.ipset exists (Download Successful?)
if [ ! -f et_tor.ipset ]; then
{
	# Notify the user that a downloaded file was not found
	echo "The downloaded file (et_tor.ipset) was not found. Please check the wget command/internet connection."

	# Pause the session for 5 seconds for the user to see the output
	sleep 5

	# Exit the script
	exit
}
fi

# Check to see if .et_tor.refSet exists
# This file is responsible for creating the reference set for the first time
# Note: This file should not get removed, when it's not present the reference set is created.
if [ ! -f .et_tor.refSet ]; then
{
  # Notify the user that a old file is not found
  # Note: This only happens on the first run
	echo ".et_tor.refSet was not found, this indicates the refernce set was not created"
	echo "Creating reference set $refSetName"

	# Create placeholder file
  touch .et_tor.refSet
	echo "# et_tor.refSet" >> .et_tor.refSet
  echo "# Created - ($fileDateName)" >> .et_tor.refSet
	echo "# This file is used to let the script know that the reference set ($refSetName) is created already. " >> .et_tor.refSet

	# Create the
	/opt/qradar/bin/ReferenceSetUtil.sh create "$refSetName" IP
}
fi

# Compute MD5 of current and old file
echo "Computing MD5 sums"
TIoldMD5=$(md5sum et_tor.ipset.old | awk '{print $1}')
TInewMD5=$(md5sum et_tor.ipset | awk '{print $1}')

# Comparison Logic for threat intel
if [ "$TIoldMD5" != "$TInewMD5" ]; then
{
  # Notify the user that the hashes do not match
  echo "Hashes don't match"
  echo "Parsing new threat intel"

  # Firehole IP List Reputation Parsing
  # Formatting Script (File comes in as a snort rule)
	# You can disable bits of the threat intel by commenting out each line (# grep -v ***)
  grep -v '#' et_tor.ipset | awk '{print $1}' | sort -nu > et_tor_parsed.ipset


  # Overwrite the old threat intel list with the currently parsed one
  mv -f et_tor.ipset et_tor.ipset.old

  # Remove old threat intel from reference set (emerging-tor)
	# Note: This will remove everything from the reference set
	echo "Clearing the reference set $refSetName"
  /opt/qradar/bin/ReferenceSetUtil.sh purge "$refSetName"

	# Notify the user that the import is starting for the file/refSetName
	echo ""
	echo "Importing the file et_tor_parsed.ipset into the reference set" $refSetName
	echo ""

	# Imports data for each et_tor_parsed.ipset file found (parsed threat intel)
	/opt/qradar/bin/ReferenceSetUtil.sh load "$refSetName" "$scriptDir/et_tor_parsed.ipset"

  # Remote parsed .data files
  rm -f et_tor_parsed.ipset

  # Pause the session for 5 seconds for the user to see the output
  sleep 5

  # Exit the script
  exit
}

# This clause is invoked if the file hashes (TIoldMD5 and TInewMD5) don't match
else
{
  # Notify the user that the hashes are the same.
  echo "Hashes match, You currently have the latest threat intel."

  # Remove the currently downloaded file
  rm -f et_tor.ipset

  # Pause the session for 5 seconds for the user to see the output
  sleep 5

  # Exit the script
  exit
}
fi
