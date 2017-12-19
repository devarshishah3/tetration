## Infoblox Tetration Integration Script

This script provides a set of manual and automated actions for creating and streaming inventory filters and user annotations to Tetration from Infoblox

## Pre-requisites
*Python 2.7.x*

This script requires the following pip libraries be installed

- tetpyclient
- infoblox-client

<pre>
pip install -r requirements.txt
</pre>

## How to use the Script

This Script supports two types of modes

1. Manual setup actions (One time tasks for setting up initial integration):
    * creating inventory filter csv file
    * associating inheritable extensible attributes with parent networks
    * exporting networks from infoblox to csv
2. Recurring actions (Ran routinely at defined poll interval)
    * update inventory filters
    * update annotations

All settings and customization options for recurring tasks should be made in the settings.yml file
