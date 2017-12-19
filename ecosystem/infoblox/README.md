## Infoblox Tetration Integration Script

This script provides a set of manual and automated actions for creating and streaming inventory filters and user annotations to Tetration from Infoblox

## Pre-requisites
*Python 2.7.x*

This script requires the following pip libraries be installed

- tetpyclient
- infoblox-client

To install all pip requirements issue the following command within your virtualenv:
<pre>
pip install -r requirements.txt
</pre>

## How to use the Script

This Script supports two types of modes

1. Manual setup actions: (One time tasks for setting up initial integration):
    * creating inventory filter csv file
    * exporting networks from infoblox to csv
    * associating inheritable extensible attributes with parent networks
2. Recurring actions: (Ran routinely at defined poll interval)
    * update inventory filters
    * update annotations

All settings and customization options for recurring tasks should be made in the settings.yml file.  Manual tasks also require that the *Infoblox* and *Tetration* sections of the settings.yml file be configured

## Usage Examples
<b>Manual Actions</b>

*Create Inventory Filter CSV*

Run this manual action if you want to manually adjust inventory filter definitions before pushing to tetration
<pre>
python infoblox-integration.py --createFilterCsv 'filters.csv'
</pre>

*Create Network CSV*

Run this manual action to generate a csv of all defined networks that can then be modified to restrict what networks annotations are created for. 
<pre>
python infoblox-integration.py --createNetworkCsv 'networks.csv'
</pre>

*Apply Extensible Attribute to network(s)*

Run this manual action to add an inheritable extensible attribute to a list of networks (this requires elevated account privileges)
<pre>
python infoblox-integration.py --importEaCsv 'networks.csv' --importEaName 'Location' --importEaValue 'US-DC-1'
</pre>

<b>Recurring Actions</b>

All settings/options for recurring actions should be made in the settings.yml file
<pre>
python infoblox-integration.py
</pre>