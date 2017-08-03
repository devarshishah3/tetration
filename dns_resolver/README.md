## Resolve missing hostnames in Tetration Inventory

This script searches the Tetration host inventory for any entries missing a hostname.  The hostname is resolved via a reverse DNS lookup and added to the selected user annotation field

## Pre-requisites
*Python 2.7.x*

This script requires the following pip libraries be installed

- tetpyclient
- dns

## Example Usage
```
################################################################################################
# Arguments:                                                                                   #
#                                                                                              #
# The following arguments can be passed into the script or defined within the script by        #
# variable name                                                                                #
#                                                                                              #
# ArgName (Script Variable Name)                                                               #
# --url (TETRATION_API_URL): Tetration URL Ex: https://<Tetration IP>                          #
# --credential (TETRATION_API_CRED_PATH): Path to credentials.json                             #
# --annotation (TETRATION_HOST_NAME_USER_ANNOTATION): User Annotation field to track hostnames #
# --scope (TETRATION_SCOPE_NAME): Scope name used for inventory search                         #
# --limit (TETRATION_SEARCH_LIMIT): Pagination limit for inventory search                      #
################################################################################################

python --url 'https://<tetration ip or hostname>' --credential '<path to credential json>' --annotation 'Owner' --scope 'Default' --limit 100

```