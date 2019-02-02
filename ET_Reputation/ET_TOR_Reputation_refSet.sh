#!/bin/bash
# Garrett Beasley - QRadar Emering Threats Intel Importer (RefSet)
# Place script in /opt/scripts/ET_Reputation/.

# Download Threat Feeds - Emering Threats Intel
echo "Downloading Emering Threats Intel"
wget -nv -O emerging-tor.rules http://rules.emergingthreats.net/blockrules/emerging-tor.rules

# Get script location
scriptDir=$(pwd)

# Compute Date Timestamp
fileDateName=$(date +"%Y%m%d_%H%M%S")

# Reference Set Name
refSetName=ET_Tor

# Check to see if emerging-tor.rules.old exists
if [ ! -f emerging-tor.rules.old ]; then
{
	# Notify the user that a old file is not found
	# Note: This only happens on the first run
	echo "Old file not found, Creating a placeholder file"

	# Create placeholder file
	touch emerging-tor.rules.old
}
fi

# Check to see if emerging-tor.rules exists (Download Successful?)
if [ ! -f emerging-tor.rules ]; then
{
	# Notify the user that a downloaded file was not found
	echo "The downloaded file (emerging-tor.rules) was not found. Please check the wget command/internet connection."

	# Pause the session for 5 seconds for the user to see the output
	sleep 5

	# Exit the script
	exit
}
fi

# Check to see if .emerging-tor.refSet exists
# This file is responsible for creating the reference set for the first time
# Note: This file should not get removed, when it's not present the reference set is created.
if [ ! -f .emerging-tor.refSet ]; then
{
  # Notify the user that a old file is not found
  # Note: This only happens on the first run
	echo ".emerging-tor.refSet was not found, this indicates the refernce set was not created"
	echo "Creating reference set $refSetName"

	# Create placeholder file
  touch .emerging-tor.refSet
	echo "# emerging-tor.refSet" >> .emerging-tor.refSet
  echo "# Created - ($fileDateName)" >> .emerging-tor.refSet
	echo "# This file is used to let the script know that the reference set ($refSetName) is created already. " >> .emerging-tor.refSet

	# Create the
	/opt/qradar/bin/ReferenceSetUtil.sh create "$refSetName" IP
}
fi

# Compute MD5 of current and old file
echo "Computing MD5 sums"
TIoldMD5=$(md5sum emerging-tor.rules.old | awk '{print $1}')
TInewMD5=$(md5sum emerging-tor.rules | awk '{print $1}')

# Comparison Logic for threat intel
if [ "$TIoldMD5" != "$TInewMD5" ]; then
{
  # Notify the user that the hashes do not match
  echo "Hashes don't match"
  echo "Parsing new threat intel"

  # Emering Threats Reputation Parsing
  # Formatting Script (File comes in as a snort rule)
	# You can disable bits of the threat intel by commenting out each line (# sed -n ***)
  sed -n 's/.*\[\([^ ].*\)\].*/\1/p' emerging-tor.rules | tr , '\n' | sort -nu >> ET_Tor_Parsed.data


  # Overwrite the old threat intel list with the currently parsed one
  mv -f emerging-tor.rules emerging-tor.rules.old

  # Remove old threat intel from reference set (emerging-tor)
	# Note: This will remove everything from the reference set
	echo "Clearing the reference set $refSetName"
  /opt/qradar/bin/ReferenceSetUtil.sh purge "$refSetName"

  # Merge new threat intel into the reference set (ET_Tor)
	for filename in $scriptDir/ET_Tor_Parsed.data; do
	    [ -e "$filename" ] || continue

			# Notify the user that the import is starting for the file/refSetName
			echo ""
			echo "Importing the file $filename" into the reference set $refSetName
			echo ""

			# Imports data for each ET_*_Parsed.data file found (parsed threat intel)
			/opt/qradar/bin/ReferenceSetUtil.sh load "$refSetName" $filename

	done

  # Remote parsed .data files
  rm -f ET_Tor_Parsed.data

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
  rm -f emerging-tor.rules

  # Pause the session for 5 seconds for the user to see the output
  sleep 5

  # Exit the script
  exit
}
fi
