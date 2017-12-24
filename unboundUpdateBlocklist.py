#!/usr/bin/env python3

import sys,requests,os,re,subprocess
from jinja2 import Template

urls = [
{"name": "hosts", "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"},
{"name": "justdomains", "url": "https://mirror1.malwaredomains.com/files/justdomains"},
{"name": "cameleonhosts", "url":"http://sysctl.org/cameleon/hosts"},
{"name": "zeustracker", "url": "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist"},
{"name": "disconnectme-1", "url": "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt"},
{"name": "disconnectme-2", "url": "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt"},
{"name":"ad_servers", "url": "https://hosts-file.net/ad_servers.txt"}
]

def readWhitelist():
    try:
        with open('/usr/local/src/dns-resolver/whitelist') as fh:
            whitelist = fh.readlines()
        return whitelist
    except:
        return []

def searchIP(string):
    pattern = "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
    ip = re.match(pattern,string)
    if ip:
        return ip.group(0)
    return None

def searchFQDN(string, where="end"):
    pattern = "(?=.{4,253})(((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63})"
    fqdn = re.search(pattern,string)
    if fqdn:
        return fqdn.group(0)
    return None

def getURL(url):
    r = requests.get(url['url'])
    if r.status_code != 200:
        return False, r.text

    dump = False
    if dump:
        with open("/tmp/%s" % url['name'],'w') as fh:
            fh.write(r.text)
    return True,r.text

def normalizeIntel(string, fqdns = [], ips = []):
    whitelist = readWhitelist()
    for i in string.split("\n"):
        i = i.strip()
        if not re.match("^$",i) and not re.match("^#",i):
            ip = searchIP(i)
            if ip not in ips and ip and ip not in whitelist:
                ips.append(ip)
            fqdn = searchFQDN(i)
            if fqdn not in fqdns and fqdn and fqdn not in whitelist:
                fqdns.append(fqdn)
    return ips,fqdns

def makeUnboundConfig(fqdns):
    template = Template('server:\n{% for fqdn in fqdns %} local-zone: "{{ fqdn }}" static\n{% endfor %}')
    config = template.render(fqdns=fqdns)
    return config

def saveUnboundConfig(config, name):
    try:
        p = "/etc/unbound/unbound.conf.d/800-%s.conf" % name
        with open(p,"w") as fh:
            fh.write(config)
        return True
    except:
        return False

def restartUnbound():
    checkconfig = subprocess.run(["/usr/sbin/unbound-checkconf"], stdout=subprocess.PIPE, stderr=subprocess.PIPE) 
    if checkconfig.returncode:
        print("New unbound config not valid:")
        print("%s\n%s"%(checkconfig.stdout,checkconfig.stderr))
        return False
    subprocess.run(["systemctl","reload","unbound"])

def main(fqdns = [], ips = [], combos = [], unblocklist = []):
    for url in urls:
        intel_unstruct = getURL(url)
        if intel_unstruct[0]:
            ipaddresses,domains = normalizeIntel(intel_unstruct[1])
            if domains:
                for d in domains:
                    if d not in fqdns:
                        fqdns.append(d)
            
    config = saveUnboundConfig(makeUnboundConfig(fqdns), "blockhosts")
    restartUnbound()


if __name__ == "__main__":
    main()
