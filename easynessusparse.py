import csv
from collections import OrderedDict

# TODO: Filter for HIGH/CRITICAL risk and produce an excel with report by Vulnerabilities, containing solutions and all hosts affected.
# TODO: Protocol doesn't work beacause it set TCP or UDP for each port and set only first time (maybe same port some udp and some tcp and only first protocol met on that port will be saved)

networks_hosts_count = {}
ports_count = {}
ports_protocols = {}
high_critical_ports_count = {}
high_critical_ports_protocols = {}
all_hosts = set()
misconfigured_count = 0
outdated_count = 0

with open('test.csv.csv') as csv_file:
    csv_reader = csv.DictReader(csv_file, delimiter=',')
    counter = 0
    for row in csv_reader:
        if counter == 0:
            print(f'Column names are {",".join(row)}')
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
                if port != '0' and port not in ports_count:
                    ports_count[port] = 1
                    ports_protocols[port] = protocol
                elif port != '0':
                    ports_count[port] += 1
                if risk == 'Critical' or risk == 'High':
                    if port != '0' and port not in high_critical_ports_count:
                        high_critical_ports_count[port] = 1
                        high_critical_ports_protocols[port] = protocol
                    elif port != '0':
                        high_critical_ports_count[port] += 1
                    # f = open('/home/francesco/Desktop/prova.txt', 'a')
                    # f.write(row['Name'] + ',' + host + '\n')
                    # f.close
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
    total_vulns = 0
    for x in networks_hosts_count[network]:
        if x != 'None':
            total_vulns += networks_hosts_count[network][x]
    print(
        '\n\n\nNetwork {}.X\t\tHosts:\t{}\t\tInfo:\t{}\n\n\tLow:\t\t{}\n\tMedium:\t\t{}\n\tHigh:\t\t{'
        '}\n\tCritical:\t{}\n\n\tTotal vulns: {}'.format(
            network, networks_hosts_count[network]['Hosts'], networks_hosts_count[network]['None'],
            networks_hosts_count[network]['Low'],
            networks_hosts_count[network]['Medium'], networks_hosts_count[network]['High'],
            networks_hosts_count[network]['Critical'], total_vulns))

print('\n\n\nTotal vulnerabilities by port:\n')
counter = 0
sorted_ports = OrderedDict(sorted(ports_count.items(), key=lambda t: t[1], reverse=True))
for port in sorted_ports:
    if counter < 10:
        print('\t{} {}  \t\t--> {}'.format(ports_protocols[port], port, sorted_ports[port]))
    else:
        break
    counter += 1

print('\n\n\nCritical / High vulnerabilities by port:\n')
counter = 0
sorted_ports = OrderedDict(sorted(high_critical_ports_count.items(), key=lambda t: t[1], reverse=True))
for port in sorted_ports:
    if counter < 10:
        print('\t{} {}  \t\t--> {}'.format(high_critical_ports_protocols[port], port, sorted_ports[port]))
    else:
        break
    counter += 1

other_causes_count = total_vulns - misconfigured_count - outdated_count
print(
    '\n\n\n\nFollowing data is an approximation!!!\n\tMisconfigurations:\t{}\n\tOutdated software:\t{}\n\tOther causes:\t{}'.format(
        misconfigured_count, outdated_count, other_causes_count))
