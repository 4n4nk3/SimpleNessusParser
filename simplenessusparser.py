import csv
from collections import OrderedDict
import xlsxwriter

# TODO: Filter for HIGH/CRITICAL risk and produce an excel with report by Vulnerabilities, containing solutions and all hosts affected.

networks_hosts_count = {}
ports_protocols = {}
high_critical_ports_protocols = {}
high_critical_detailed = {}
all_hosts = set()
misconfigured_count = 0
outdated_count = 0

cols_replacements = (('0', 'A'), ('1', 'B'), ('2', 'C'), ('3', 'D'), ('4', 'E'), ('5', 'F'), ('6', 'G'))

def col_replace(col):
    for old, new in cols_replacements:
        col = str(col).replace(old, new)
    return col

with open('test.csv') as csv_file:
    csv_reader = csv.DictReader(csv_file, delimiter=',')
    counter = 0
    total_vulns = 0
    for row in csv_reader:
        if counter > 0:
            name = row['Name']
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
                        if name not in high_critical_detailed:
                            high_critical_detailed[name] = {}
                            high_critical_detailed[name]['counter'] = 1
                            high_critical_detailed[name]['hosts'] = set()
                            high_critical_detailed[name]['hosts'].add(host)
                            high_critical_detailed[name]['solution'] = solution
                        else:
                            high_critical_detailed[name]['counter'] += 1
                            high_critical_detailed[name]['hosts'].add(host)
                if 'update' in solution or 'Update' in solution or 'upgrade' in solution or 'Upgrade' in solution:
                    outdated_count += 1
                else:
                    misconfigured_count += 1
        counter += 1

row = 0
col = 0

workbook = xlsxwriter.Workbook('High_Critical.xlsx')
worksheet = workbook.add_worksheet()

worksheet.write(row, col, 'Hosts')
col += 1
worksheet.write(row, col, len(all_hosts))
col += 2
worksheet.write(row, col, 'Networks')
col += 1
worksheet.write(row, col, len(networks_hosts_count))

row += 2
col = 0

for network in networks_hosts_count:
    worksheet.write(row, col, 'Network')
    col += 1
    worksheet.write(row, col, network)
    col += 2
    worksheet.write(row, col, 'Hosts')
    col += 1
    worksheet.write(row, col, networks_hosts_count[network]['Hosts'])
    col = 1
    row += 2
    worksheet.write(row, col, 'Info')
    col += 1
    worksheet.write(row, col, networks_hosts_count[network]['None'])
    col = 1
    row += 1
    worksheet.write(row, col, 'Low')
    col += 1
    worksheet.write(row, col, networks_hosts_count[network]['Low'])
    col = 1
    row += 1
    worksheet.write(row, col, 'Medium')
    col += 1
    worksheet.write(row, col, networks_hosts_count[network]['Medium'])
    col = 1
    row += 1
    worksheet.write(row, col, 'High')
    col += 1
    worksheet.write(row, col, networks_hosts_count[network]['High'])
    col = 1
    row += 1
    worksheet.write(row, col, 'Critical')
    col += 1
    worksheet.write(row, col, networks_hosts_count[network]['Critical'])
    col = 1
    row += 1
    worksheet.write(row, col, 'Total')
    col += 1
    worksheet.write(row, col, '=SUM({}{}:{}{})'.format(col_replace(col), row-4, col_replace(col), row))
    col = 0
    row += 2

row += 1

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

print(high_critical_detailed)


for vuln in high_critical_detailed:
    print(vuln)
"""
for item, cost in (high_critical_detailed):
    worksheet.write(row, col,     item)
    worksheet.write(row, col + 1, cost)
    row += 1

worksheet.write(row, 0, 'Total')
worksheet.write(row, 1, '=SUM(B1:B4)')
"""
workbook.close()
