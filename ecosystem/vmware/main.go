package main

// required import packages
import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	goh4 "github.com/remiphilippe/goh4"
	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/event"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
	"golang.org/x/net/context"
	"io/ioutil"
	"net/url"
	"os"
	"reflect"
	"sort"
	"text/tabwriter"
	"time"
	"strings"
)

// how often annotation updates are streamed to tetration
const EXPORT_INTERVAL = time.Minute

type VCenter struct {
	Username   string
	Password   string
	URL        string
	Datacenter string
}

type Tetration struct {
	URL    string
	Key    string
	Secret string
}

type Settings struct {
	VCenter   VCenter
	Tetration Tetration
	Insecure  bool
}

func (vc *VCenter) GetURL() (*url.URL, error) {
	u, err := url.Parse(vc.URL)
	u.User = url.UserPassword(vc.Username, vc.Password)
	return u, err
}

type ByName []mo.VirtualMachine

func (n ByName) Len() int           { return len(n) }
func (n ByName) Swap(i, j int)      { n[i], n[j] = n[j], n[i] }
func (n ByName) Less(i, j int) bool { return n[i].Name < n[j].Name }

func exit(err error) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	os.Exit(1)
}

var initDescription = "Initialize VM Inventory and Tags"
var initFlag = flag.Bool("init", false, initDescription)

var subscribeDescription = "Subscribe to VM events (rename and edit tags)"
var subscribeFlag = flag.Bool("subscribe", false, subscribeDescription)

func main() {
	flag.Parse()
	// read settings from settings.json
	fmt.Println("Loading settings.json")
	file, e := ioutil.ReadFile("./settings.json")
	if e != nil {
		fmt.Printf("File error: %v\n", e)
		os.Exit(1)
	}
	var settings Settings
	json.Unmarshal(file, &settings)
	fmt.Printf("Settings Loaded:\n")
	fmt.Printf(" vCenter:\n")
	fmt.Printf("  %s: %s\n", "URL", settings.VCenter.URL)
	fmt.Printf("  %s: %s\n", "Username", settings.VCenter.Username)
	fmt.Printf("  %s: <hidden>\n", "Password")
	fmt.Printf("  %s: %s\n", "Datacenter", settings.VCenter.Datacenter)

	// create new tetration api client
	h4 := new(goh4.H4)
	h4.Secret = settings.Tetration.Secret
	h4.Key = settings.Tetration.Key
	h4.Endpoint = settings.Tetration.URL
	h4.Verify = !settings.Insecure
	h4.Prefix = "/openapi/v1"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	vcenter, err := settings.VCenter.GetURL()

	// Connect and log in to ESX or vCenter
	c, err := govmomi.NewClient(ctx, vcenter, settings.Insecure)
	if err != nil {
		exit(err)
	}

	f := find.NewFinder(c.Client, true)

	// Find one and only datacenter
	dc, err := f.Datacenter(ctx, settings.VCenter.Datacenter)
	if err != nil {
		exit(err)
	}

	// Make future calls local to this datacenter
	f.SetDatacenter(dc)

	// Find virtual machines in datacenter
	vms, err := f.VirtualMachineList(ctx, "*")
	if err != nil {
		exit(err)
	}

	pc := property.DefaultCollector(c.Client)

	// Convert VMs into list of references
	var refs []types.ManagedObjectReference
	for _, vm := range vms {
		refs = append(refs, vm.Reference())
	}

	// Retrieve name property for all vms
	var vmt []mo.VirtualMachine
	err = pc.Retrieve(ctx, refs, nil, &vmt)
	if err != nil {
		exit(err)
	}
	// Retrieve Host and Cluster of VM
	GetHost := func(hostMo types.ManagedObjectReference) (string, string){
		var host mo.HostSystem
		err = pc.RetrieveOne(ctx,hostMo,nil, &host)
		if err != nil {
			exit(err)
		}
		var clusterName string
		if host.Parent != nil && host.Parent.Type == "ClusterComputeResource" {
			var cluster mo.ClusterComputeResource

			err = pc.RetrieveOne(ctx,host.Parent.Reference(),nil, &cluster)
			if err != nil {
				exit(err)
			}
			clusterName = cluster.Name
		}else{
			clusterName = ""
		}
		
		return host.Name, clusterName
	}
	// Retrieve port group information
	GetNetworks := func(networkMos []types.ManagedObjectReference) (string){
		var networks string
		for _, networkMo := range networkMos{
			if networkMo.Type == "DistributedVirtualPortgroup" {
				var network mo.DistributedVirtualPortgroup
				err = pc.RetrieveOne(ctx,networkMo.Reference(),nil, &network)
				if err != nil {
					exit(err)
				}
				networks = networks + network.Name + ", "
			}
		}
		return strings.TrimSuffix(networks,", ")
	}

	// Use Custom Field Manager to Retrieve int32 -> string mappings for Custom Fields

	fields := make(map[int32]string)
	getFields := func() {
		mgr := object.NewCustomFieldsManager(c.Client)
		var customFields []types.CustomFieldDef
		customFields, err = mgr.Field(ctx)
		if err != nil {
			exit(err)
		}
		for _, field := range customFields {
			fields[field.Key] = field.Name
		}
	}
	getFields()

	// CSV writer
	body := new(bytes.Buffer)
	w := csv.NewWriter(body)
	w.Write([]string{"IP", "VRF", "VM Name", "VM Tags", "VM Location", "VM Network"})

	// Tab writer for nicely formatted output
	tw := tabwriter.NewWriter(os.Stdout, 2, 0, 2, ' ', 0)

	// grab all VM information if initFlag is set
	if *initFlag {
		fmt.Println("Virtual machines found:", len(vmt))
		sort.Sort(ByName(vmt))
		for _, vm := range vmt {
			addr := ""
			if vm.Guest != nil && &vm.Guest.IpAddress != nil {
				host,cluster := GetHost(vm.Runtime.Host.Reference())
				network := GetNetworks(vm.Network)
				addr = vm.Guest.IpAddress
				fmt.Fprintf(tw, "%s\t-\t%v\n", addr, vm.Name)
				b := new(bytes.Buffer)
				if len(vm.CustomValue) > 0 {
					fmt.Fprintf(tw, "\tTags\n")
					fmt.Fprintf(tw, "\t==========================\n")
					for _, kv := range vm.CustomValue {
						ref := reflect.ValueOf(kv).Elem()
						val := ref.FieldByName("Value")
						key, ok := fields[kv.GetCustomFieldValue().Key]
						if !ok {
							getFields()
							key = fields[kv.GetCustomFieldValue().Key]
						}

						pair := fmt.Sprintf("%s=%s", key, val)
						fmt.Fprintf(tw, "\t%s\n", pair)
						b.WriteString(pair)
						b.WriteString(";")
					}
				}
				w.Write([]string{addr, "Default", vm.Name, b.String(), host + "/" + cluster, network})
			}

		}
		tw.Flush()
		w.Flush()
	
		fmt.Print("\nUploading current inventory...")
	
		response := h4.Upload(body.Bytes(), true, true)
	
		fmt.Fprintf(tw, " ...%s\n", response)
	}
	// subscribe to change events if subscribeFlag is set
	if *subscribeFlag {
		fmt.Println("=================================")
		fmt.Println("Subscribing to VM events")
		fmt.Println("=================================")

		rows := make(chan []string, 1)
		handleEvent := func(ref types.ManagedObjectReference, events []types.BaseEvent) (err error) {
			for _, event := range events {
				switch event.(type) {
				case *types.CustomFieldValueChangedEvent, *types.VmRenamedEvent, *types.VmMigratedEvent:
					if event.GetEvent().Vm == nil{
						break
					}
					vmRef := event.GetEvent().Vm.Vm.Reference()
					var vm mo.VirtualMachine
					pc.RetrieveOne(ctx, vmRef, []string{"name", "guest.ipAddress", "customValue"}, &vm)

					if vm.Guest != nil && &vm.Guest.IpAddress != nil {
						addr := vm.Guest.IpAddress
						host,cluster := GetHost(vm.Runtime.Host.Reference())
						network := GetNetworks(vm.Network)
						b := new(bytes.Buffer)
						if len(vm.CustomValue) > 0 {
							for _, kv := range vm.CustomValue {
								ref := reflect.ValueOf(kv).Elem()
								val := ref.FieldByName("Value")
								key, ok := fields[kv.GetCustomFieldValue().Key]
								if !ok {
									getFields()
									key = fields[kv.GetCustomFieldValue().Key]
								}

								pair := fmt.Sprintf("%s=%s", key, val)
								fmt.Fprintf(tw, "\t%s\n", pair)
								b.WriteString(pair)
								b.WriteString(";")
							}
						}
						rows <- []string{addr, "Default", vm.Name, b.String(), host + "/" + cluster, network}
						fmt.Printf("Found eligible event for VM: %s (IP: %s) (Tags: %s)\n", vm.Name, addr, b.String())
					}
				}
			}
			return nil
		}

		go func() {
			written := false
			body.Reset()
			w.Write([]string{"IP", "VRF", "VM Name", "VM Tags", "VM Location", "VM Network"})
			for {
				select {
				case row := <-rows:
					w.Write(row)
					written = true
				case <-time.After(EXPORT_INTERVAL):
					if written {
						fmt.Print("Exporting...")
						w.Flush()
						response := h4.Upload(body.Bytes(), true, true)
						fmt.Printf(" ...%s\n", response)
						body.Reset()
						w.Write([]string{"IP", "VRF", "VM Name", "VM Tags", "VM Location", "VM Network"})
						written = false
					}
				}
			}
		}()

		// Setting up the event manager
		refs = []types.ManagedObjectReference{dc.Reference()}
		eventManager := event.NewManager(c.Client)
		err = eventManager.Events(ctx, refs, 10, true, false, handleEvent)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}
	}
}