## Resolve missing hostnames in Tetration Inventory

This script searches the Tetration host inventory for any entries missing a hostname.  The hostname is resolved via a reverse DNS lookup and added to the selected user annotation field

## Pre-requisites
*Python 2.7.x*

This script requires the following pip libraries be installed

- tetpyclient
- dns