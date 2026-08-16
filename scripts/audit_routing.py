#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Routing-integrity audit for the HTB skill tree.

The skill registry keys skills by the frontmatter `name`; T1 cards appear in
the model catalog, T2/T3 are hidden and loaded by name. A routing bug is any
of: duplicate/colliding names, a MAPPING entry with no card on disk (index
advertises a name that cannot load), a card missing from MAPPING (no tier
metadata), tier metadata disagreeing with disable-model-invocation, a stale
htb-skill-index, or a cross-card reference pointing at a name that does not
exist.

Usage:
    python scripts/audit_routing.py [skills-dir]

Exit code 1 when any ERROR is found; warnings are advisory. Runs read-only
(never rewrites cards); run scripts/triage_skills.py to regenerate the index
when it is stale.

Recommended chain (idempotent, run after any edit):
    python scripts/fix_yaml.py skills
    python scripts/triage_skills.py skills
    python scripts/audit_routing.py skills
"""
import os
import re
import sys

SKILLS = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', 'skills')
SKILLS = os.path.abspath(SKILLS)

try:
    import yaml
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

try:
    import triage_skills as triage
except ImportError:
    triage = None

INDEX_NAME = 'htb-skill-index'
MAPPING = {}
REMOVE = set()
DOMAIN_LABEL = {}

if triage is not None:
    MAPPING = dict(triage.MAPPING)
    REMOVE = set(triage.REMOVE)
    DOMAIN_LABEL = dict(triage.DOMAIN_LABEL)

FIELD_RE = re.compile(r'^([A-Za-z][\w-]*)\s*:(.*)$')
BACKTICK_RE = re.compile(r'`([^`\n]+)`')
WIKILINK_RE = re.compile(r'\[\[([^\]\n]+)\]\]')
# 中文路由关键词 + 紧随其后的（可带反引号/括号的）技能名 token
CJK_KW_RE = re.compile(
    r'(?:加载|详见|参见|参考|查询|切换|路由|调用|先读|先看|查看|见|查)'
    r'\s*[`『「（(]?\s*([a-z][a-z0-9-]{2,})')
# 英文路由关键词：必须是一个独立单词（前面不能贴着字母），且后面至少要有一个空格；
# 只认含连字符的 token（单英文词噪声太大，且技能名几乎都带连字符）。
LATIN_KW_RE = re.compile(
    r'(?<![a-z0-9])(?:load|see|check|use)\s+[`『「（(]?\s*'
    r'([a-z][a-z0-9-]*-[a-z0-9-]+)')
NAME_TOKEN_RE = re.compile(r'^[a-z0-9][a-z0-9-]*$')

# 合法出现在正文里的工具/技术/协议 token（非技能名）。命中名单即视为已解析；
# 名单外且形似技能名（小写连字符 token）的引用会被列为 DANGLING 候选逐一复核。
WHITELIST = set('''
gtfobins hacktricks payloadallthethings linpeas winpeas pspy linux-smart-enumeration
lse unix-privesc-check chisel ligolo ligolo-ng socat plink netcat nc ncat nmap masscan
rustscan ffuf gobuster feroxbuster dirsearch wfuzz dirb nikto nuclei sqlmap burp burpsuite
zap metasploit msfconsole msfvenom searchsploit exploitdb responder impacket ntlmrelayx
secretsdump mimikatz bloodhound sharphound powerview powersploit rubeus kerbrute certipy
petitpotam coercer adidnsdump ldapsearch ldapdomaindump windapsearch smbclient smbmap
enum4linux enum4linux-ng netexec crackmapexec evil-winrm psexec wmiexec smbexec atexec
dcomexec hashcat john hydra medusa patator crowbar cewl crunch rsmangler kwprocessor
rsync redis redis-cli memcached mongosh mysql mysqldump psql sqlplus sqlcmd oracle
mariadb postgres postgresql mongodb cassandra couchdb couchbase elasticsearch kibana
logstash kafka zookeeper rabbitmq activemq mqtt mosquitto amqp stomp websocket graphql
grpc protobuf thrift dns dhcp ntp snmp snmpwalk tftp ftp ftps sftp ssh scp telnet rsh
rlogin smtp sendmail imap pop3 ldap ldaps kerberos krb5 ntlm smb smb2 netbios winrm rpc
rpcdump msrpc wmi dcom rdp vnc x11 xrdp http https http2 http3 wsgi asgi cgi fastcgi
ajp tomcat jboss wildfly weblogic websphere glassfish jetty nginx apache apache2
lighttpd caddy haproxy envoy traefik iis gunicorn uwsgi php php-fpm java jvm python
node nodejs javascript typescript dotnet aspnet golang ruby rails perl bash zsh dash
ksh powershell pwsh cmd yaml json xml html css vue react angular flask django fastapi
spring springboot laravel symfony wordpress joomla drupal magento prestashop gitlab
github git svn mercurial curl wget base64 hex urlencode urldecode xss ssti ssrf csrf
xxe lfi rfi idor jwt jws jwe oauth oauth2 oidc saml sso mfa otp totp hotp tls ssl tcp
udp icmp ipv4 ipv6 arp vlan vpn wireguard openvpn ipsec docker dockerfile containerd
runc cri-o podman kubernetes k8s k3s minikube kind helm etcd istio nomad consul vault
terraform ansible puppet chef saltstack jenkins teamcity bamboo gitlab-ci github-actions
argo airflow superset grafana prometheus nagios zabbix fluentd splunk elk aws azure gcp
aliyun s3 sqs sns lambda ec2 ecs eks ecr iam sts cognito cloudfront route53
cloudformation codebuild codepipeline codecommit secretsmanager kms parameter-store ssm
dynamodb rds aurora redshift glacier vpc ebs efs elb alb nlb api-gateway localstack
minio ceph openstack nova neutron keystone swift glance cinder freeipa keycloak okta
auth0 adfs entra azuread office365 exchange owa outlook sharepoint onedrive teams
mssql sqlite db2 sybase informix vertica clickhouse snowflake bigquery firestore realm
neo4j cypher sparql h2 derby hsqldb jackson fastjson xstream ysoserial marshalsec
gadget struts struts2 log4j log4shell jndi rmi jmx jolokia spring4shell shellshock
heartbleed pwnkit polkit dirtycow dirty-pipe ghostcat spectre meltdown retpoline
regsvr32 rundll32 certutil bitsadmin wmic schtasks netsh attrib icacls cacls takeown
robocopy xcopy findstr tasklist taskkill ipconfig whoami netstat route nslookup
cscript wscript mshta msbuild cmstp odbcconf dll exe elf shellcode rop ret2libc aslr
dep canary pie got plt seh veh syscall syscalls ptrace seccomp landlock apparmor
selinux capabilities setuid setgid suid sgid chroot pivot-root overlayfs fuse tmpfs
procfs sysfs devfs cgroup cgroups namespace namespaces user-namespace cron crontab
systemd dbus udev init sysvinit upstart su sudo doas pkexec gosu nsenter unshare lxc
lxd qemu kvm vmware virtualbox hyper-v xen firecracker gvisor ebpf squid proxy socks
socks5 http-proxy squid.conf vhost vhosts virtual-host subdomain subdomains sslstrip
arp-spoof mitm dnscat2 dnscat iodine dns2tcp ptunnel sshuttle proxychains
proxychains4 metasploit-framework meterpreter msf shell nohup screen tmux awk sed
grep tar zip gzip bzip2 xz dd strings strace ltrace objdump gdb readelf file
binwalk foremost exiftool steghide stegsolve zsteg jadx apktool frida objection
ghidra ida radare2 rizin r2 angr pwntools ropper one-gadget gadget libc musl glibc
ubifs squashfs cramfs cpio initramfs busybox dropbear telnetd smbd nfsd rpcbind
mountd nfs rpc-statd postfix exim dovecot proftpd vsftpd pure-ftpd freeradius
openvpn tinc pptp l2tp ipsec ike isakmp sip voip asterisk rtp stun turn webrtc
icecast shoutcast rtsp ffmpeg mplayer vlc exim4 opensmtpd apache-tomcat catalina
manager-webapp jsp servlet filter struts-ognl ognl spel jexl mvel velocity freemarker
thymeleaf mustache handlebars ejs pug jade nunjucks jinja2 twig smarty blade erb
erb-templates haml slim liquid soap wsdl uddi axis cxf metro jax-ws jax-rs rest
restful openapi swagger soapui postman insomnium insomnia grpcurl buf protoc
thrift-compiler avro parquet orc arrow delta iceberg duckdb sqlcipher walite
sqlite3 mysql-server mariadb-server postgres-server oracle-db mssql-server
mongod redis-server etcd-server consul-server nomad-server kafka-server
zookeeper-server rabbitmq-server activemq-server hornetq artemis amq webmethods
tibco mule mulesoft krayin bagisto opencart prestashop woo magento2 shopware
cscart sylius spree solidus drupal8 drupal9 drupal10 typo3 concrete5 modx
processwire octobercms wintercms craftcms statamic grav bolt kirby getsimple
bludit dotclear spip serendipity pivotx nucleus textpattern movable-type
expressionengine silverstripe pyrocms codeigniter cakephp yii yii2 zend laminas
slim phalcon fuelphp kohana koseven microdot bottle cherrypy pyramid falcon
tornado sanic aiohttp starlette quart litestar ember backbone marionette knockout
svelte alpine htmx livewire inertia nuxt nextjs remix sveltekit astro gatsby
gridsome hugo jekyll hexo pelican nikola mkdocs docusaurus vuepress vitepress
wordpress-plugin joomla-extension drupal-module magento-extension typo3-extension
chrome chromium firefox safari edge ie internet-explorer cdp devtools-protocol
headless-chrome puppeteer playwright selenium webdriver chromedriver geckodriver
phantomjs zombiejs jsdom domino cheerio axios got superagent node-fetch requests
urllib httpx aiohttp-client curl-impersonate cfscrape cloudscraper flare-solverr
waf modsecurity aws-waf cloudflare cloudfront akamai imperva f5 barracuda
fortinet paloalto checkpoint sophos crowdstrike sentinelone defender mde edr av
antivirus amsi clm applocker wdac acg ppl lsass dpapi credman vaultcmd keepass
keepassxc lastpass bitwarden onepassword passwd shadow gshadow master-passwd
sudoers ldap.conf krb5.conf smb.conf sshd-config ssh-config authorized-keys
known-hosts id-rsa id-ecdsa id-ed25519 ssh-agent ssh-add pageant plink-agent
keytab ccache ticket-granting-ticket service-ticket golden-ticket silver-ticket
diamond-ticket sapphire-ticket skeleton-key overpass-the-hash pass-the-hash
pass-the-ticket pass-the-key asrep-roasting kerberoasting asreproast
kerberoast getnpusers gettgt get-st get-tgt spn upn samaccountname
userprincipalname objectguid objectsid dn distinguishedname cn ou dc domain
forest tree trust child-domain parent-domain cross-forest adcs ca certificate
certification-authority enrollment-web esc1 esc2 esc3 esc4 esc5 esc6 esc7 esc8
esc9 esc10 esc11 esc12 esc13 esc14 esc15 ntlmv1 ntlmv2 lmhash nthash net-ntlm
ntlmssp spnego gssapi sasl digest basic auth ntlm-auth kerberos-auth
certificate-auth smartcard fido2 webauthn passkey totp-app authenticator
duo push-notification sms-otp email-otp backup-codes recovery-key security-key
yubikey nitrokey solo titan-key feitian yubico pam pam.d sshd vsftpd su
system-auth password-auth login.defs issue.net motd banner grab vuln
vulnerability exploit payload shell reverse-shell bind-shell web-shell
webshell cmd.php cmd.jsp cmd.aspx cmdshell pwn shellz pty tty pts tty-spawn
upgrade-shell full-tty python-pty socat-exec script-dev-tty stty raw
stty-raw echo printf dd nc-traditional busybox-nc php-shell perl-shell
ruby-shell awk-shell telnet-shell openssl-shell msfvenom-payload shellcode-loader
dll-injection reflective-dll process-injection process-hollowing
thread-hijacking atom-bombing early-bird apc-injection iat-hook inline-hook
syscall-hook ssdt-hook vmt-hook detox dll-sideloading dll-proxying
search-order-hijacking phantom-dll relative-path weak-permissions service-perms
unquoted-service-path alwaysinstallelevated auto-logon saved-creds
credential-manager token-impersonation token-duplication seimpersonate
sedebug seassignprimary senableprivilege setakeownership serestore sebackup
seloaddriver seshutdown sesystemtime seprofilesingleprocess seincreasequota
semachineaccount secreatepermanent sesynagent seundock setcb setimezone
selockmemory secreatepagefile secreateglobal sesecurity seunsolicitedinput
sedenyinteractivelogon sedenyremotelogon setrustedcredmanaccess serelabel
secreate symbolic-link privileged-mode cap-add cap-drop device tmpfs-mount
docker-socket docker.sock podman.sock cri.sock containerd.sock crio.sock
kubelet kube-apiserver kube-proxy kube-controller-manager kube-scheduler
core-dns flannel calico cilium weave ovs openvswitch cni multus macvlan ipvlan
vxlan geneve gre wireguard-tunnel ipip sit tun tap bridge veth pair
network-namespace pid-namespace mount-namespace uts-namespace ipc-namespace
user-namespace time-namespace cgroup-namespace userns-remap rootless
rootlesskit slirp4netns pasta passt uidmap newuidmap newgidmap subuid subgid
shadow-utils useradd usermod groupadd passwd chpasswd vipw vigr pwck grpck
lastlog faillog tallylog wtmp btmp utmp last lastb ac accton sa sar sysstat
iostat vmstat mpstat pidstat dstat atop htop glances btop nmon collectl
perf ftrace trace-cmd bpftrace bcc systemtap dtrace strace-f ltrace-f
lsof fuser ss netstat-tcp iproute2 ip addr link neigh route-sys mtr
traceroute tracepath hping3 hping nping scapy python-scapy tcpdump
wireshark tshark dumpcap editcap mergecap capinfos tcpflow ngrep
ettercap bettercap dsniff arpspoof macchanger aircrack-ng airodump-ng
aireplay-ng kismet kismetdb wash reaver pixiewps bully cowpatty
asleap genkeys hashid hash-identifier name-that-hash nth datalinks
john2hashcat convert hashcat-utils cap2hccapx hcxpcapngtool hcxdumptool
hcxpsktool hashdeep md5sum sha1sum sha256sum sha512sum certutil-hash
openssl gpg gnupg age rage minisign signify ssh-keygen openssh
dropbear-ssh tinyssh mosh et mosh-client tmate screen-attach tmux-attach
abduco dtach reptyr expect pexpect socat2 pwncat pwncat-cs conpty
winpty colortail less more head tail cut sort uniq comm join paste tr
fold fmt expand unexpand od xxd hexdump bvi vim vi nano emacs ed ex sed-edit
awk-edit perl-edit ruby-edit php-edit node-edit jq yq-go yq-python jqp fx
xsv csvkit miller q qsv dasel gron underscore-cli jsonnet jp jello jid
jid2 yqr jsonata jsm json-parse sed-json python-json php-json ruby-json
shellcheck shfmt bat cat zcat bzcat xzcat zstd zstdcat lz4 lzop p7zip
7z 7za unar unrar rar arj lha cab wim swm esd msu msi msix appx appxbundle
oneget winget choco scoop brew apt dpkg rpm yum dnf zypper pacman apk
portage emerge nix guix flatpak snap appimage conda pip pipx pipenv poetry
uv rye pdm hatch npm pnpm yarn bun deno cargo rustup goenv nvm fnm volta
asdf mise sdkman jabba pyenv virtualenv venv pipx-run pip-run uvx
git-lfs git-annex git-crypt git-secret sops age-encrypt ansible-vault
terraform-state opentofu pulumi cdk cdk8s serverless sam cli awscli
aws-vault gcloud gsutil azure-cli az kubectl kubeadm kops eksctl helmfile
kustomize skaffold tilt devspace okteto garden werf k3d kind-cluster
minikube-cluster microk8s k0s rke k3sup talos kairos immutos edge
nixos guix-system gentoo arch archlinux debian ubuntu centos rhel rocky
alma fedora suse opensuse kali kali-linux parrot backbox blackarch
photon alpine wolfi distroless scratch busybox-musl musl-cross glibc-cross
uclibc bionic musl-dynamic static-pie elf-no-pie pie-exec no-pie
fortify relro now bind-now execstack noexec nx-bit smep smap umip
kpti pti retbleed spectre-v2 spectre-v4 l1tf mds-cve taa tsx tsx-async
srbds mmio stale-data ret2dir kaslr fgkaslr kfence kmalloc kvmalloc
slub slab slob vmalloc vmemmap page-tables paging tlb shootdown
hugepages thp transparent-hugepages numa numa-balancing cpuset
sched-scheduler cfs rt-sched deadline-sched fifo rr niceness renice
chrt taskset numactl cpuset-cgroup io-nice ionice blkio cgroup-v1
cgroup-v2 systemd-cgroup cgroupns cgroup-driver runc-rootless
crun kata-runtime gvisor-runtime firecracker-runtime cloud-hypervisor
stratovirt nvidia-driver intel-gpu amd-gpu virtio vfio sriov dpdk
ovs-dpdk xdp af-xdp tcx netkit bpf bpf-map bpf-prog xdp-hook tc-hook
clsact qdisc htb tbf fq-codel cake pie red wred sfq hfsc cbq prio
netem ifb veth-bridge macvtap ipvtap tun-tap wireguard-udp
gre-tunnel ipip-tunnel sit-tunnel vxlan-tunnel geneve-tunnel
ipsec-esp ipsec-ah isakmp-ike ikev1 ikev2 nat44 nat66 nptv6
port-forwarding reverse-proxy forward-proxy transparent-proxy
intercepting-proxy upstream downstream backend frontend origin
edge-node cdn-waf anycast unicast multicast broadcast geocast
unicast-flood unknown-unicast storm-control port-security dhcp-snooping
arp-inspection ip-source-guard dae dot1x eapol eap-tls eap-ttls eap-peap
eap-mschapv2 radius-diameter tacacs tacacs-plus ldap-tls starttls
implicit-tls ssl-vpn ipsec-vpn l2tp-ipsec pptp-sstp openvpn-tls
wireguard-nat mosh-udp quic http3-alt-svc h2-prior-knowledge
alpn npn sni esni ech ecdhe dhe rsa-ecdhe psk srp opaque-pake
spake2 oprf voprf threshold-signing shamir secret-sharing
sss-sssd winbind nslcd nscd nsswitch pam-modules samba smbd winbindd
nmblookup smbget smbpasswd pdbedit net-ads net-rpc wbinfo getent
idmap idmapd rpc-idmapd gssd svcgssd ktutil kinit klist kdestroy
kpasswd kvno ktutil-list msktutil adjoin realm-join sssd-join
oddjob oddjobd realm-kinit adcli netdom dsquery dsadd dsmod dsrm
csvde ldifde repadmin dcdiag netdiag dnsdiag nltest gpupdate gpresult
gpedit secedit auditpol wevtutil logman typeperf relog lodctr unlodctr
wpr xperf wpa perfmon resmon msinfo32 dxdiag systeminfo driverquery
sc-query sc-config sc-start sc-stop net-start net-stop net-use net-view
net-session net-file net-share net-user net-group net-localgroup
dsacls icacls-grant xcacls subinacl setacl setaclex chml chown-chmod
umask-chattr lsattr getfacl setfacl getcap setcap chacl getrichacl
nfs4-acl posix-acl acl-mask default-acl access-acl audit-acl
samba-acl smb-cacls ntfs-perms share-perms ntfs-ads alternate-data-stream
ads-zone identifier-zone mof-compiler wmi-provider wmic-script
powershell-remoting winrm-https wsman winrs psexec-sysinternals
procmon procexp autoruns tcpview handle streamsmagic sigcheck
sdelete junction mklink fsutil dskperf winsat bcdedit bootcfg
msconfig regedit reg regsvr32-silent regsvc scm service-control-manager
schtasks-create task-scheduler at-create wmi-event-subscription
com-hijacking com-object com-clsid progid inprocserver localserver
com-surrogate dcomcnfg oleview process-explorer process-hacker
system-informer pe-bear pestudio die detect-it-easy exeinfo peid
upx mpress aspack themida vmprotect enigma obsidium pelock
netguard theenigma eziriz confuser de4dot dnspy ilspy dotpeek
justdecompile monodis ildasm ilasm csc msbuild-inline csi fsi
roslyn dotnet-script dotnet-run dotnet-build nuget paket fake
cargo-rustup rustc cargo-edit cargo-audit cargo-deny cargo-tarpaulin
cargo-fuzz honggfuzz afl aflplusplus libfuzzer syzkaller go-fuzz
jazzer atheris fuzztest deepstate hypothesis property-based-testing
quickcheck proptest rapidcheck gopter scalacheck minitest rspec
pytest unittest nose2 nose behave lettuce radish cucumber specflow
gauge robotframework cypress-playwright vitest jest mocha jasmine
karma ava tape tap node-tap nyc istanbul c8 coverage-lcov gcov
gcovr lcov genhtml coveralls codecov sonarqube sonar-scanner
fortify-scanner checkmarx snyk trivy grype syft osv-scanner
dependency-check retire-js auditjs npm-audit yarn-audit pnpm-audit
cargo-deny-audit bundler-audit pip-audit safety pipenv-check
poetry-check govulncheck osv vuln-list cve-list nvd cisa kev
epss cvss cwe capec mitre-attck attck tactics techniques
sub-techniques kill-chain diamond-model attack-flow d3fend
mitre-d3fend mitre-engage deception honeypot canary-token
honeycred honeyhash honeytoken tripwire aide samhain ossec wazuh
elastic-security suricata snort zeek bro securityonion moloch
arkime velociraptor grr osquery fleet kolide laika cytomic
carbon-black falcon sysmon sysmon-config sigma yara yara-rules
clara volk oletools oledump oleid mraptor officeparser
rtfdump pcode peepdf pdfid pdf-parser qpdf mutool pdftk
ghostscript gs pocorgtfo didier-stevens xorsearch exiftool-carving
foremost-scalpel binwalk-carving volatility volatility3 rekall
lime avml winpmem dumpit f-response magnet-forensics encase ftk
x-ways autopsy sleuthkit tsk fls icat istat mmls fsstat blkls
sigfind hfind mac-robber macapt plist parser regripper registry-explorer
hivex hivexregedit libregf reglookup regripper-plugin
ericzimmerman tools jumplist shellbags amcache shimcache prefetch
recentdocs lnk-files jumplist-files usnjrnl ntfs-logfile mft-master-file-table
evtx evtx-parser chainsaw hayabusa sigma-events sysmon-events
powershell-log scriptblock logging amsi-log etw-provider wpp
trace-logging manifest-based-etw dtrace-bpf uprobes kprobes tracepoints
impacket-mssqlclient impacket-changepasswd impacket-secretsdump struts-pwn
accesschk ntpdate ldd nxc iwr pre2k
srw-rw---- template-sync change-me myminio sdestruct rinit
socket sys role debug image pwd privileged email password url payment secrets
transaction users internal-creds admin administrator root system manager
changeme cisco apc elastic pma raspberry requirepass s3cret sa123 synology
internal private public wiki open description eval exec destination hook
resource tofile playbook ipa mirth self sysadmin plugin secure chmod name
super localhost listener rinfo env symlink agent generic line tcpwrapped
unknown attestation direct enterprise none package query race sink classic
devmode strict auxiliary naming return point action detail list renum rname
rnames rns r-desc r-find r-show r-status rgroup-find r-enum rcontent radd
rname-generation rname-anarchy rs-kerberos-only rsfile point-toolchain
point-action k-v4-pro i686-w64-mingw32-gcc sslfactory mappings
d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240
'''.split())

# 卡名集合：以 frontmatter name 为准（skill 注册表按 name 加载）。
NAME_PAT = re.compile(r'^[a-z0-9][a-z0-9-]{2,}$')


def parse_frontmatter(raw):
    if not raw.startswith('---'):
        return None, raw
    lines = raw.split('\n')
    fields = []
    closing = None
    for i in range(1, len(lines)):
        line = lines[i].rstrip('\r')
        if line.strip() == '---':
            closing = i
            break
        m = FIELD_RE.match(line)
        if m:
            val = m.group(2).strip()
            if val.endswith('---'):
                fields.append((m.group(1), val[:-3].rstrip()))
                closing = i
                break
            fields.append((m.group(1), val))
        elif fields:
            k, v = fields[-1]
            fields[-1] = (k, v + '\n' + line)
    if closing is None:
        return None, raw
    return fields, '\n'.join(lines[closing + 1:])


def unquote(v):
    v = v.strip()
    if len(v) >= 2 and v[0] in '\'"' and v[-1] == v[0]:
        return v[1:-1]
    return v


def norm(text):
    return text.strip().lower()


def card_text(fdict, body):
    """All prose where a cross-card reference may appear."""
    parts = [fdict.get('name', ''), fdict.get('description', ''),
             fdict.get('whenToUse', ''), body]
    return '\n'.join(parts)


def main():
    errors = []
    warnings = []
    infos = []

    dirs = sorted(os.listdir(SKILLS))
    cards = {}          # dir -> (fdict, body)
    by_name = {}        # name(lower) -> dir
    ref_tokens = []     # (dir, token, kind) extracted candidates
    seen_bad = set()

    # --- A/B: load every card, validate frontmatter ---
    for entry in dirs:
        p = os.path.join(SKILLS, entry, 'SKILL.md')
        if not os.path.isfile(p):
            errors.append('NO-SKILLMD: %s' % entry)
            continue
        raw = open(p, encoding='utf-8').read()
        fields, body = parse_frontmatter(raw)
        if fields is None:
            errors.append('NO-FRONTMATTER: %s' % entry)
            continue
        fdict = {}
        for k, v in fields:
            fdict[k] = v
        name = unquote(fdict.get('name', ''))
        desc = unquote(fdict.get('description', ''))
        if not name:
            errors.append('NO-NAME: %s' % entry)
            continue
        if not desc:
            errors.append('NO-DESCRIPTION: %s (%s)' % (entry, name))
        # 引号翻倍回归守卫：正确的 YAML 转义最多出现连续 2 个单引号（''），
        # 出现 3 个以上说明历史转义 bug 复发（scripts/fix_yaml.py 已幂等化）。
        for field in ('name', 'description', 'whenToUse'):
            raw_val = fdict.get(field, '')
            if raw_val and "'''" in raw_val:
                errors.append('QUOTE-RUN-CORRUPTION: %s field=%s (run scripts/recover_quotes.py to fix)' % (entry, field))
        if not NAME_PAT.match(name):
            errors.append('BAD-NAME-FORMAT: %s (%r)' % (entry, name))
        nkey = norm(name)
        if nkey in by_name:
            errors.append('DUPLICATE-NAME: %s (%s) collides with %s' % (entry, name, by_name[nkey]))
        by_name[nkey] = entry
        if entry != name:
            warnings.append('DIR-NAME-MISMATCH: dir=%s name=%s' % (entry, name))
        cards[entry] = (fdict, body)

    names = set(by_name.keys())
    names_original = {norm(unquote(fdict.get('name', ''))): unquote(fdict.get('name', '')) for fdict, _ in cards.values()}

    # --- D: MAPPING <-> disk bidirectional coverage ---
    on_disk = set(cards.keys())
    mapped = set(MAPPING.keys())
    for d in sorted(on_disk - mapped):
        errors.append('UNMAPPED-DIR: %s (add to MAPPING in scripts/triage_skills.py)' % d)
    for m in sorted(mapped - on_disk):
        errors.append('DEAD-MAPPING: %s (in MAPPING but no skills/%s/ dir -> index would route to nothing)' % (m, m))
    for m in sorted(REMOVE & on_disk):
        errors.append('RESURRECTED: %s is in REMOVE but still on disk' % m)
    for m, (dom, tier) in sorted(MAPPING.items()):
        if dom not in DOMAIN_LABEL:
            errors.append('BAD-DOMAIN: %s -> %s' % (m, dom))
        if tier not in ('T1', 'T2', 'T3'):
            errors.append('BAD-TIER: %s -> %s' % (m, tier))

    # --- E: tier metadata & disable-model-invocation consistency ---
    for entry, (fdict, body) in sorted(cards.items()):
        name = norm(unquote(fdict.get('name', '')))
        meta = fdict.get('metadata', '')
        m = re.search(r'tier:\s*(T[123])', meta)
        meta_tier = m.group(1) if m else None
        mapped_tier = MAPPING.get(entry, (None, None))[1] if entry in MAPPING else None
        if entry in MAPPING:
            if meta_tier != mapped_tier:
                errors.append('TIER-MISMATCH: %s metadata.tier=%s MAPPING=%s' % (entry, meta_tier, mapped_tier))
        elif entry == INDEX_NAME:
            pass  # generator owns the index card
        elif meta_tier:
            warnings.append('METADATA-WITHOUT-MAPPING: %s tier=%s but not in MAPPING' % (entry, meta_tier))
        dis = fdict.get('disable-model-invocation', '')
        dis_true = norm(dis) == 'true'
        expect_dis = mapped_tier is not None and mapped_tier != 'T1'
        if mapped_tier is not None and entry != INDEX_NAME:
            if dis_true != expect_dis:
                errors.append('INVOCATION-FLAG-MISMATCH: %s tier=%s disable-model-invocation=%r (expected %r)' % (entry, mapped_tier, dis_true, expect_dis))

    # --- F: index freshness (compare against generated text) ---
    if INDEX_NAME in cards:
        idx_path = os.path.join(SKILLS, INDEX_NAME, 'SKILL.md')
        current = open(idx_path, encoding='utf-8').read()
        expected = None
        if triage is not None:
            expected = triage.generate_index_text(MAPPING)
        if expected is not None and current != expected:
            errors.append('STALE-INDEX: %s differs from MAPPING-generated content (rerun scripts/triage_skills.py)' % INDEX_NAME)

    # --- G: cross-reference resolution ---
    for entry, (fdict, body) in sorted(cards.items()):
        text = card_text(fdict, body)
        for m in WIKILINK_RE.finditer(text):
            tok = m.group(1).strip()
            if not tok or not all(ord(c) < 128 for c in tok):
                continue
            ref_tokens.append((entry, tok, 'wikilink'))
        for m in BACKTICK_RE.finditer(text):
            tok = m.group(1).strip()
            if ' ' in tok or '\n' in tok:
                continue
            if not all(ord(c) < 128 for c in tok):
                continue
            ref_tokens.append((entry, tok, 'backtick'))
        for m in CJK_KW_RE.finditer(text):
            ref_tokens.append((entry, m.group(1), 'route-kw'))
        for m in LATIN_KW_RE.finditer(text):
            ref_tokens.append((entry, m.group(1), 'route-kw'))

    dangling = {}
    for entry, tok, kind in ref_tokens:
        if tok != tok.lower() or not NAME_TOKEN_RE.match(tok):
            continue  # 大小写混杂/非法字符：不可能是全小写卡名
        if tok[0].isdigit():
            continue  # 数字开头的值/哈希/IP，不是卡名
        if tok in names:
            continue
        if len(tok) < 3:
            continue
        if tok in WHITELIST:
            continue
        dangling.setdefault(entry, set()).add((tok, kind))

    for entry in sorted(dangling):
        for tok, kind in sorted(dangling[entry]):
            errors.append('DANGLING-REF: %s -> %r (%s)' % (entry, tok, kind))

    # --- H: reachability (info): names never mentioned by any other card ---
    all_text = '\n'.join(card_text(fdict, body) for fdict, body in cards.values())
    unreferenced = []
    for n in sorted(names):
        if n == INDEX_NAME:
            continue
        if not re.search(r'(?<![a-z0-9-])%s(?![a-z0-9-])' % re.escape(n), all_text.replace(card_text(cards[by_name[n]][0], cards[by_name[n]][1]), '')):
            unreferenced.append(n)
    if unreferenced:
        infos.append('UNREFERENCED (reachable only via index; fine for T3): %s' % ', '.join(unreferenced))

    # --- T1 catalog quality: whenToUse present? (warning) ---
    no_when = []
    for entry, (fdict, _) in sorted(cards.items()):
        if entry not in MAPPING or entry == INDEX_NAME:
            continue
        if MAPPING[entry][1] == 'T1' and not fdict.get('whenToUse', '').strip():
            no_when.append(entry)
    if no_when:
        warnings.append('T1-WITHOUT-WHENTOUSE: %s' % ', '.join(no_when))

    print('cards on disk: %d   MAPPING: %d   extracted refs: %d' % (len(cards), len(MAPPING), len(ref_tokens)))
    for w in warnings:
        print('WARN:', w)
    for i in infos:
        print('INFO:', i)
    for e in errors:
        print('ERROR:', e)
    print('SUMMARY: %d errors, %d warnings, %d infos' % (len(errors), len(warnings), len(infos)))
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
