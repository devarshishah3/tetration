## Create Inventory Filters by subnet labels

This script will parse the provided csv file to create inventory filters based on subnets.  The Inventory Filter will be named according to the "Comment" field

## Pre-requisites
*Python 2.7.x*

This script requires the following pip libraries be installed

- tetpyclient

## Example Usage
```
python --url 'https://<tetration ip or hostname>' --credential '<path to credential json>' --csv '<path to csv>'
```