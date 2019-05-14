import csv
from collections import OrderedDict

# TODO: Filter for HIGH/CRITICAL risk and produce an excel with report by Vulnerabilities, containing solutions and all hosts affected.

networks_hosts_count = {}
ports_protocols = {}
high_critical_ports_protocols = {}
all_hosts = set()
misconfigured_count = 0
outdated_count = 0

with open('test.csv') as csv_file:
    csv_reader = csv.DictReader(csv_file, delimiter=',')
    counter = 0
    total_vulns = 0
    for row in csv_reader:
        if counter == 0:
            print('Column names are '.format(",".join(row)))
        else:
            host = row['Host']
            risk = row['Risk']
            port = row['Port']
            solution = row['Solution']
            protocol = row['Protocol']
            network = '.'.join(host.split('.')[:-1])
            if network not in networks_hosts_count:
                networks_hosts_count[network] = {'None': 0, 'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0, 'Hosts': 0}
            if host not in all_hosts:
                all_hosts.add(host)
                networks_hosts_count[network]['Hosts'] += 1
            networks_hosts_count[network][risk] += 1
            if risk != 'None':
                total_vulns += 1
                if port != '0':
                    if port not in ports_protocols:
                        ports_protocols[port] = {}
                        ports_protocols[port][protocol] = 1
                    elif protocol not in ports_protocols[port]:
                        ports_protocols[port][protocol] = 1
                    else:
                        ports_protocols[port][protocol] += 1
                if risk == 'Critical' or risk == 'High':
                    if port != 0:
                        if port not in high_critical_ports_protocols:
                            high_critical_ports_protocols[port] = {}
                            high_critical_ports_protocols[port][protocol] = 1
                        elif protocol not in high_critical_ports_protocols[port]:
                            high_critical_ports_protocols[port][protocol] = 1
                        else:
                            high_critical_ports_protocols[port][protocol] += 1
                if 'update' in solution or 'Update' in solution or 'upgrade' in solution or 'Upgrade' in solution:
                    outdated_count += 1
                else:
                    misconfigured_count += 1

        counter += 1

if len(networks_hosts_count) < 2:
    print('\n\nScanned {} hosts in {} network'.format(len(all_hosts), len(networks_hosts_count)))
else:
    print('\n\nScanned {} hosts in {} networks'.format(len(all_hosts), len(networks_hosts_count)))

for network in networks_hosts_count:
    print(
        '\n\n\nNetwork {}.X\t\tHosts:\t{}\t\tInfo:\t{}\n\n\tLow:\t\t{}\n\tMedium:\t\t{}\n\tHigh:\t\t{'
        '}\n\tCritical:\t{}\n\n\tTotal vulns: {}'.format(
            network, networks_hosts_count[network]['Hosts'], networks_hosts_count[network]['None'],
            networks_hosts_count[network]['Low'],
            networks_hosts_count[network]['Medium'], networks_hosts_count[network]['High'],
            networks_hosts_count[network]['Critical'], total_vulns))

print('\n\n\nVulnerabilities by port:\n')
ports_protocols = OrderedDict(sorted(ports_protocols.items(), key=lambda x: int(x[0])))
for port in ports_protocols:
    for protocol in ports_protocols[port]:
        print('\t{}\t{}  \t\t--> {}'.format(port, protocol, ports_protocols[port][protocol]))

print('\n\n\nCritical / High vulnerabilities by port:\n')
high_critical_ports_protocols = OrderedDict(sorted(high_critical_ports_protocols.items(), key=lambda x: int(x[0])))
for port in high_critical_ports_protocols:
    for protocol in high_critical_ports_protocols[port]:
        print('\t{} {}  \t\t--> {}'.format(port, protocol, high_critical_ports_protocols[port][protocol]))

other_causes_count = total_vulns - misconfigured_count - outdated_count
print(
    '\n\n\n\nFollowing data is not accurate!!!\n\n\tMisconfigurations:\t{}\n\tOutdated software:\t{}\n\tOther causes:\t{}'.format(
        misconfigured_count, outdated_count, other_causes_count))
