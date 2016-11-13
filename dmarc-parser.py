#	prints simple DMARC report stats to stdout and a detailed list of auth. domains / IPs / results to dmarc_stats.txt
#	each e-mail marked as 'blocked' if any spamfilter didn't mark it 'pass', otherwise marked as 'allowed'
import xml.etree.ElementTree as ET

records = []

NUM_FILES = 257
#	parses files named [000,001,..,NUM_FILES-1].xml
for i in range(0,NUM_FILES):
	filename = str(i//100)+str((i//10)%10)+str(i%10)
	cur_tree = ET.parse(filename+'.xml')
	root = cur_tree.getroot()
	for record in root:
		if record.tag == 'record': records.append(record)

records_allowed, records_blocked = [], []

for rec in records:
	is_blocked = False
	for result in rec.iter('result'):
		if result.text != 'pass': is_blocked = True
	if is_blocked: records_blocked.append(rec)
	else: records_allowed.append(rec)





domains_allowed = {}
ip_stats = {}

for rec in records_allowed:
	for c in rec.iter('count'):
		for d in rec.iter('domain'):
			if d.text not in domains_allowed: domains_allowed[d.text] = 0
			domains_allowed[d.text] += int(c.text)

print("Allowed e-mails come from the following domains: "+str(domains_allowed))


domains_blocked = {}
for rec in records_blocked:
	for c in rec.iter('count'):
		for d in rec.iter('domain'):
			if d.text not in domains_blocked: domains_blocked[d.text] = 0
			domains_blocked[d.text] += int(c.text)

print("Blocked e-mails come from the following domains: "+str(domains_blocked))



domains_overlap = {}
for d in domains_allowed:
	if d in domains_blocked: domains_overlap[d] = ''
print("The following domains appear among both allowed and blocked e-mails: "+str(domains_overlap))




# print domain stats
out = open('dmarc_stats.txt','w')

stats_dict = {}
for rec in records:
	is_blocked = False
	for result in rec.iter('result'):
		if result.text != 'pass': is_blocked = True
	cnt = 0
	for c in rec.iter('count'): cnt = int(c.text)
	ip = ''
	for x in rec.iter('source_ip'): ip = x.text
	for d in rec.iter('domain'):
		if d.text not in stats_dict: stats_dict[d.text] = [0,{}]
		stats_dict[d.text][0] +=cnt
		if ip not in stats_dict[d.text][1]: stats_dict[d.text][1][ip] = [0,0]
		if is_blocked: stats_dict[d.text][1][ip][1] += cnt
		else: stats_dict[d.text][1][ip][0] += cnt

stats = sorted(stats_dict.items(), key = lambda x: x[1][0])
for d,s in stats: 
	head = ('{0: <50}'.format("Domain "+str(d)+":"))+str(len(s[1]))+" IPs,\t"
	if s[0] < 10**4: head = head + '\t'
	if d in domains_allowed: head = head + str(domains_allowed[d])+" e-mails allowed,\t"
	else: head = head + "0 e-mails allowed,\t"
	if d in domains_blocked: head = head + str(domains_blocked[d])+" e-mails blocked\n"
	else: head = head + "0 e-mails blocked\n"
	out.write(head)
	statsd = sorted(s[1].items(), key = lambda x: x[1][0]+x[1][1])
	for ip,sd in statsd: 
		entry = ('{0: <30}'.format(ip))+str(sd[0])+" allowed, "+str(sd[1])+" blocked\n"
		out.write(entry)
	out.write("\n")

out.close()





for rec in records_allowed:
	for c in rec.iter('count'):
		for ip in rec.iter('source_ip'):
			if ip.text not in ip_stats: ip_stats[ip.text] = [0,0]
			ip_stats[ip.text][0] += int(c.text)
for rec in records_blocked:
	for c in rec.iter('count'):
		for ip in rec.iter('source_ip'):
			if ip.text not in ip_stats: ip_stats[ip.text] = [0,0]
			ip_stats[ip.text][1] += int(c.text)

print(str(len(ip_stats))+" IPs")
cnt_ip_freq = 0
cnt_ip_ntriv = 0
for ip,occ in ip_stats.items():
	if occ[0]+occ[1] > 1: cnt_ip_ntriv += 1
	if occ[0]+occ[1] > 7: cnt_ip_freq += 1
print(str(cnt_ip_ntriv)+" IPs with more than 1 entry")
print(str(cnt_ip_freq)+" IPs with more than 7 entries")





cnt_records_allowed, cnt_records_blocked = 0, 0
for rec in records_allowed:
	for c in rec.iter('count'):
		cnt_records_allowed += int(c.text)
for rec in records_blocked:
	for c in rec.iter('count'):
		cnt_records_blocked += int(c.text)
print("Fully allowed messages: "+str(cnt_records_allowed))
print("Not fully allowed messages: "+str(cnt_records_blocked))




records_strange_header = []

for rec in records:
	for t in rec.iter('header_from'):
		if t.text != 'fykos.cz': records_strange_header.append(rec)

print("Messages with header different from fykos.cz: "+str(len(records_strange_header)))

