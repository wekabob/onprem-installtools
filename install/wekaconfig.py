import argparse
import copy
import ipaddress
import socket
import sys
import time
from pprint import pprint
import npyscreen
import wekalib.exceptions

from wekalib.wekaapi import WekaApi

class WekaInterface(ipaddress.IPv4Interface):
    def __init__(self, type, name, address):
        self.type = type
        self.name = name
        super(WekaInterface, self).__init__(address)

class STEMHost(object):
    def __init__(self, name, info_hw):
        self.name = name
        self.num_cores = len(info_hw['cores'])
        self.cpu_model = info_hw['cores'][0]['model']
        self.drives = dict()
        self.nics = dict()
        self.version = info_hw['version']
        self.info_hw = info_hw  # save a copy in case we need it

        for drive in info_hw['disks']:
            if drive['type'] == "DISK" and not drive['isRotational'] and not drive['isMounted'] and \
                    len(drive['pciAddr']) > 0:
                self.drives[drive['devName']] = drive['pciAddr']

        for net_adapter in info_hw['net']['interfaces']:
            if (net_adapter['mtu'] > 4000 and net_adapter['mtu'] < 10000) and len(net_adapter['ip4']) > 0:
                details = self.find_interface_details(net_adapter['name'])
                if details['validationCode'] == "OK" and details['linkDetected']:
                    self.nics[net_adapter['name']] = \
                                WekaInterface(net_adapter['linkLayer'],
                                              details['interface_alias'],
                                              f"{net_adapter['ip4']}/{net_adapter['ip4Netmask']}")

    def find_interface_details(self, iface):
        for eth in self.info_hw['eths']:
            if eth['interface_alias'] == iface:
                return eth
        return None

    def __str__(self):
        return self.name

def testResolve(hostname):
    try:
        socket.gethostbyname(hostname)
    except socket.gaierror:
        return False
    except Exception as exc:
        raise
    return True


def beacon_hosts(host):
    api = WekaApi(host, scheme="http", verify_cert=False)
    try:
        host_status = api.weka_api_command("status", parms={})
    except wekalib.exceptions.LoginError:
        print(f"{host}: Login failure.  Is this host already part of a cluster?")
        sys.exit(1)
    except wekalib.exceptions.CommunicationError:
        print(f"{host}: Unable to communicate with {host}")
        sys.exit(1)
        # long-term, ask for admin password so we can reset/reconfigure the cluster
    # pprint(host_status)

    if host_status['is_cluster']:
        print(f"host {host} is already part of a cluster")
        sys.exit(1)

    #print(f"Host {host} is a STEM-mode instance running release {host_status['release']}")

    beacons = api.weka_api_command("cluster_list_beacons", parms={})
    # pprint(beacons)   # a dict of {ipaddr:hostname}

    stem_beacons = dict()
    for ip, hostname in beacons.items():
        if hostname not in stem_beacons:
            stem_beacons[hostname] = [ip]
        else:
            stem_beacons[hostname].append(ip)

    return stem_beacons


def find_valid_hosts(beacons):
    good_hosts = dict()
    errors = False
    for host in beacons:
        if not testResolve(host):
            print(f"Host {host} does not resolve.  Is it in DNS/hosts?")
            errors = True
            continue

        host_api = WekaApi(host, scheme="http", verify_cert=False)
        try:
            machine_info = host_api.weka_api_command("machine_query_info", parms={})
        except wekalib.exceptions.LoginError:
            print(f"host {host} failed login?")
            errors = True
            continue
        except wekalib.exceptions.CommunicationError:
            print(f"Error communicating with host {host}")
            errors = True
            continue

        # pprint(machine_info)
        print(f"Host {host} is a STEM-mode instance running release {machine_info['version']}")
        good_hosts[host] = STEMHost(host, machine_info)

    if errors:
        print("Some STEM-mode hosts could not be contacted.  Are they in DNS?")
        time.sleep(5.0)
    return good_hosts


def scan_hosts(host):
    stem_beacons = beacon_hosts(host)
    valid_hosts = find_valid_hosts(stem_beacons)
    return valid_hosts


class CoresTextWidget(npyscreen.TitleText):
    def __init__(self, screen, fieldname='', **keywords):
        self.fieldname = fieldname
        super(CoresTextWidget, self).__init__(screen, **keywords)

    def edit(self):
        self.last_value = copy.deepcopy(self.value)
        super(CoresTextWidget, self).edit()
        if not str.isnumeric(self.value):
            self.value = self.last_value
            self.display()
        if int(self.value) > 19:
            # out of range - reject value
            self.value = self.last_value
            self.display()
            return
        if self.fieldname == "fe":
            self.parent.num_fe_cores = int(self.value)
            if self.parent.num_fe_cores <= 0:
                self.parent.num_fe_cores = 1  # have to have one
            self.parent.num_compute_cores = 19 - self.parent.num_fe_cores - self.parent.num_drives_cores
            if self.parent.num_compute_cores < 0:
                self.parent.num_compute_cores = 0
                self.parent.num_drives_cores = 19 - self.parent.num_fe_cores
        elif self.fieldname == "compute":
            self.parent.num_compute_cores = int(self.value)
            if self.parent.num_compute_cores <= 0:
                self.parent.num_compute_cores = 0
            self.parent.num_fe_cores = 19 - self.parent.num_compute_cores - self.parent.num_drives_cores
            if self.parent.num_fe_cores < 0:
                self.parent.num_fe_cores = 0
                self.parent.num_drives_cores = 19 - self.parent.num_compute_cores
        elif self.fieldname == "drives":
            self.parent.num_drives_cores = int(self.value)
            if self.parent.num_drives_cores <= 0:
                self.parent.num_drives_cores = self.parent.analyse_drives()
            self.parent.num_compute_cores = 19 - self.parent.num_drives_cores - self.parent.num_fe_cores
            if self.parent.num_compute_cores < 0:
                self.parent.num_compute_cores = 0
                self.parent.num_fe_cores = 19 - self.parent.num_drives_cores
        # set self.value again
        self.parent.fe_cores.set_value(str(self.parent.num_fe_cores))
        self.parent.compute_cores.set_value(str(self.parent.num_compute_cores))
        self.parent.drives_cores.set_value(str(self.parent.num_drives_cores))
        return


class SelectCores(npyscreen.ActionFormV2):
    def create(self):
        self.num_fe_cores = 1

    def beforeEditing(self):
        self.total_cores = self.analyse_cores()
        self.usable_cores = self.total_cores - 5  # leave at least 5 cores for the OS, etc
        if self.usable_cores > 19:
            self.usable_cores = 19

        # set defaults
        self.num_drives_cores = self.analyse_drives()
        self.num_compute_cores = self.usable_cores - self.num_drives_cores - self.num_fe_cores

        self.fe_cores = self.add(CoresTextWidget, fieldname="fe", name="FE Cores:", value=str(self.num_fe_cores))
        self.compute_cores = self.add(CoresTextWidget, fieldname="compute", name="COMPUTE Cores:",
                                      value=str(self.num_compute_cores), use_two_lines=False)
        self.drives_cores = self.add(CoresTextWidget, fieldname="drives", name="DRIVES Cores:",
                                     value=str(self.num_drives_cores))

        # set field exit handlers so we can recalc on-the-fly

    def afterEditing(self):
        if self.pressed == "OK":
            self.parentApp.setNextForm(None)
        else:
            self.parentApp.setNextForm(None) # exit gracefully, they hit Cancel

    def on_ok(self):
        self.pressed = "OK"

    def on_cancel(self):
        self.pressed = "CANCEL"

    def analyse_cores(self):
        # let's gather together the info
        host_cores = dict()
        for hostname in self.parentApp.selected_hosts:
            host_cores[hostname] = self.parentApp.target_hosts[hostname].num_cores

        # are they all the same?
        reference_cores = 0
        errors = False
        for cores in host_cores.values():
            if reference_cores == 0:
                reference_cores = cores
                continue
            else:
                if cores != reference_cores:
                    # Error!   hosts have different number of cores!
                    errors = True
                    break

        if errors:
            # make noise
            pass

        return reference_cores

    def analyse_drives(self):
        # let's gather together the info
        num_drives = dict()
        for hostname in self.parentApp.selected_hosts:
            num_drives[hostname] = len(self.parentApp.target_hosts[hostname].drives)

        reference_drives = 0
        errors = False
        for drives in num_drives.values():
            if reference_drives == 0:
                reference_drives = drives
                continue
            else:
                if drives != reference_drives:
                    errors = True
                    break
        if errors:
            # make noise
            pass

        return reference_drives


class SelectHosts(npyscreen.ActionFormV2):
    def create(self):
        self.selected_hosts = None
        pass

    def beforeEditing(self):
        self.possible_hosts = self.hosts_on_dp() # list of STEMHost objects
        hostlist = list()
        for host in self.possible_hosts:
            hostlist.append(str(host))
        self.sorted_hosts = sorted(hostlist)
        if self.selected_hosts is None:
            self.selected_hosts = self.add(npyscreen.TitleMultiSelect, scroll_exit=True, max_height=15,
                                           value=list(range(0,len(self.sorted_hosts))),
                                           name='Select Hosts:',
                                           values=self.sorted_hosts)

    def afterEditing(self):
        if self.pressed == "OK":
            if len(self.selected_hosts.value) < 5:
                # they didn't select any
                npyscreen.notify_wait("You must select at least 5 hosts", title='ERROR')
                self.parentApp.setNextForm("Hosts")
                return
            for index in self.selected_hosts.value:
                self.parentApp.selected_hosts.append(self.sorted_hosts[index])
            self.parentApp.setNextForm("SelectCores")
        else:
            self.parentApp.setNextForm(None) # exit gracefully, they hit Cancel

    def on_ok(self):
        self.pressed = "OK"

    def on_cancel(self):
        self.pressed = "CANCEL"

    def hosts_on_dp(self):
        selected_hosts = list()
        # dps is a list of IPv4Network objects that were selected
        dps = self.parentApp.selected_dps
        # hosts is a list of STEMHost objects that we're considering
        hosts = self.parentApp.target_hosts
        for dp in dps:  # dp is a IPv4Network object
            for host in hosts.values():
                for nic in host.nics.values():
                    if dp == nic.network:
                        selected_hosts.append(host)

        return selected_hosts

class SelectDPNetworks(npyscreen.ActionFormV2):
    def create(self):
        self.possible_dps = self.guess_networks(self.parentApp.target_hosts)
        self.dataplane_networks = self.add(npyscreen.TitleMultiSelect, scroll_exit=True, max_height=3,
                                           name='Select DP Networks:',
                                           values=self.possible_dps)

    def afterEditing(self):
        # DP networks selected are self.dataplane_networks.value (a list of indices)
        if self.pressed == "OK":
            if len(self.dataplane_networks.value) == 0:
                # they didn't select any
                npyscreen.notify_wait("You must select at least one dataplane network", title='ERROR')
                self.parentApp.setNextForm("MAIN")
                return
            for index in self.dataplane_networks.value:
                # save the IPv4Network objects corresponding to the selected items
                self.parentApp.selected_dps.append(self.nets[index])
            self.parentApp.setNextForm("Hosts")    # for testing, just exit
        else:
            self.parentApp.setNextForm(None)

    def on_ok(self):
        self.pressed = "OK"

    def on_cancel(self):
        self.pressed = "CANCEL"


    def guess_networks(self, hostlist):
        # make a unique list of networks
        self.nets = list()
        output = list()
        for host in hostlist.values():
            for iface in host.nics.values():
                #network = ipaddress.IPv4Network(f"{iface['ip4']}/{iface['mask']}", strict=False)
                network = iface.network
                if network not in self.nets:
                    self.nets.append(network)
                    output.append(f"{iface.type}: {network}")

        return output


class WekaConfigApp(npyscreen.NPSAppManaged):
    def __init__(self):

        parser = argparse.ArgumentParser(description="Weka Cluster Configurator")
        parser.add_argument("host", type=str, nargs="?", help="a host to talk to", default="localhost")
        parser.add_argument("-v", "--verbosity", action="count", default=0, help="increase output verbosity")
        parser.add_argument("--version", dest="version", default=False, action="store_true",
                            help="Display version number")
        args = parser.parse_args()
        print(f"target host is {args.host}")
        self.host = args.host
        self.target_hosts = scan_hosts(self.host)
        self.selected_dps = list()
        self.selected_hosts = list()

        super(WekaConfigApp, self).__init__()

    def onStart(self):
        self.addForm("MAIN", SelectDPNetworks, "Weka Configurator")
        self.addForm("Hosts", SelectHosts, "Weka Configurator")
        self.addForm("SelectCores", SelectCores, "Weka Configurator")

    # on exit of application - when next form is None
    def onCleanExit(self):
        print(f"selected dp networks are: {self.selected_dps}")


if __name__ == '__main__':
    config = WekaConfigApp()
    config.run()
    #main()