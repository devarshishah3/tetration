## vCenter Tetration Integration Script

This script creates inventory annotations from a specified vCenter datacenter.  Annotations can be created for all VMs using the initFlag and dynamically updated based on subscribed vCenter events using the subscribeFlag.

## Pre-requisites
### Golang

Golang install doc https://golang.org/doc/install

This script requires the following non-standard Go packages

- github.com/vmware/govmomi
- github.com/vmware/govmomi/event
- github.com/vmware/govmomi/find
- github.com/vmware/govmomi/object
- github.com/vmware/govmomi/property
- github.com/vmware/govmomi/vim25/mo
- github.com/vmware/govmomi/vim25/types
- golang.org/x/net/context

## Installation
First, clone this git repository
<pre>
git clone https://github.com/techBeck03/tetration.git
cd tetration/ecosystem/vmware
</pre>

Next, install all go requirements with the following command:
<pre>
go get github.com/techBeck03/tetration/ecosystem/vmware
</pre>

## How to use the Script

This script creates the following annotations for all VMs under a specified Datacenter
- VM Location (ESX Host / Cluster)
- VM Tags (tag1Name=tag1Value;tag2Name=tag2Value;)
- VM Network (Network1,Network2,Network3)

There are two types of actions that can be performed:
1. Initialize Annotations - creates annotations for all VMs
2. Subscription Based Updates - dynamically updates annotations based on the following events:
    * VM Tag Changed
    * VM Name Changed
    * vMotion Occurred

### Configure Connection Settings
Before running the script edit the example.settings.json and rename to settings.json

<pre>
{
    "vcenter": {
        "url": "https://vcenter.domain.com/sdk",
        "username": "someone@domain.com",
        "password": "",
        "datacenter": "Example-DC"
    },
    "tetration": {
        "url":"https://tetrationcluster.domain.com",
        "key":"",
        "secret":""
    },
    "insecure": true
}
</pre>

### Usage Examples
Initialize Annotations
<pre>
go run main.go -init
</pre>

Subscribe to vCenter events for dynamic annotation updates
<pre>
go run main.go -subscribe
</pre>

Initialize Annotations and Subscribe to vCenter Events
<pre>
go run main.go -init -subscribe
</pre>