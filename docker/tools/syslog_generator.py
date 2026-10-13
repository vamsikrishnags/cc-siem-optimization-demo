"""Synthetic RFC3164 syslog generator (firewall, sshd, sudo, IAM, account service, system noise).

~97% of what it emits is routine noise an analyst never needs in the SIEM; the rest are
scripted attack scenarios that Flink should keep, enrich and mask:

  * SSH brute force from a threat-intel IP, sometimes followed by a successful login,
    sudo and a backdoor account (kill-chain story)
  * C2 beaconing from a finance laptop to a threat-intel IP (firewall ACCEPT!)
  * Port scans: mostly harmless DROPs, a few against sensitive ports
  * Password resets / MFA changes that carry e-mail addresses (PII masking)

All "external" attacker addresses come from the RFC 5737 documentation ranges.
"""

import os
import random
import socket
import threading
import time
from datetime import datetime

TARGET_HOST = os.getenv("SYSLOG_HOST", "fluent-bit")
TARGET_PORT = int(os.getenv("SYSLOG_PORT", "5140"))
EPS = float(os.getenv("SYSLOG_EVENTS_PER_SEC", "40"))

# facility * 8 + severity
KERN_INFO, KERN_WARN = 6, 4
AUTHPRIV_INFO, AUTHPRIV_NOTICE, AUTHPRIV_WARN = 86, 85, 84
CRON_INFO, DAEMON_INFO, LOCAL0_INFO, LOCAL0_NOTICE = 78, 30, 134, 133

USERS = ["alice.wong", "bob.smith", "carol.diaz", "dave.patel", "erin.chen", "frank.okafor"]
SERVICE_USERS = ["svc_backup", "svc_deploy"]
EMAIL_DOMAIN = "acme-corp.example"

LAPTOPS = ["10.10.20.15", "10.10.20.31", "10.10.20.45", "10.10.20.52", "10.10.20.67", "10.10.20.88"]
SERVERS = {"bastion01": "10.10.10.5", "web01": "10.10.10.20", "web02": "10.10.10.21",
           "app01": "10.10.30.15", "db01": "10.10.30.10"}
SSH_HOSTS = ["bastion01", "web01", "web02", "app01", "db01"]
SUDO_HOSTS = ["web01", "web02", "app01", "db01"]

POPULAR_DESTS = ["142.250.80.46", "13.107.21.200", "151.101.1.44", "104.16.132.229",
                 "52.32.63.138", "20.190.160.1", "17.253.144.10", "35.186.224.25"]
INTERNET_NOISE = ["45.33.32.156", "185.220.101.4", "89.248.165.10", "162.142.125.12",
                  "71.6.199.23", "193.163.125.70"]

BRUTEFORCE_IP = "203.0.113.66"     # in threat_intel (bruteforce, high)
BRUTEFORCE_IP_2 = "203.0.113.45"   # in threat_intel (bruteforce, medium)
C2_IP = "198.51.100.23"            # in threat_intel (c2, critical)
SCANNER_IP = "198.51.100.200"      # NOT in threat_intel - only the sensitive-port hits survive

SENSITIVE_PORTS = [22, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200]


class Syslog:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addr = None
        self.pid = {h: random.randint(800, 30000) for h in list(SERVERS) + ["fw01"]}

    def resolve(self):
        while self.addr is None:
            try:
                self.addr = (socket.gethostbyname(TARGET_HOST), TARGET_PORT)
            except socket.gaierror:
                print(f"waiting for {TARGET_HOST} ...", flush=True)
                time.sleep(2)

    def send(self, pri, host, app, msg, pid=True):
        now = datetime.now()
        stamp = f"{now:%b} {now.day:>2} {now:%H:%M:%S}"
        tag = f"{app}[{self.pid.get(host, 1000) + random.randint(0, 50)}]" if pid else app
        line = f"<{pri}>{stamp} {host} {tag}: {msg}"
        self.sock.sendto(line.encode(), self.addr)


def fw(action, src, dst, proto, dpt, spt=None, iface_in="eth1", iface_out="eth0"):
    spt = spt or random.randint(1024, 65535)
    return (f"FW ACTION={action} IN={iface_in} OUT={iface_out} SRC={src} DST={dst} "
            f"PROTO={proto} SPT={spt} DPT={dpt} LEN={random.randint(40, 1500)}")


# ----------------------------- noise -----------------------------

def noise_fw_outbound(s):
    port, proto = random.choice([(443, "TCP")] * 6 + [(80, "TCP"), (53, "UDP"), (123, "UDP")])
    s.send(KERN_INFO, "fw01", "kernel", fw("ACCEPT", random.choice(LAPTOPS), random.choice(POPULAR_DESTS), proto, port))


def noise_fw_internal(s):
    port = random.choice([443, 5432, 8080, 389, 53])
    s.send(KERN_INFO, "fw01", "kernel",
           fw("ACCEPT", random.choice(LAPTOPS), random.choice(list(SERVERS.values())), "TCP", port, iface_out="eth2"))


def noise_fw_internet_drop(s):
    port = random.choice([random.randint(1024, 65535), 8081, 8888, 37215, 52869, 60001])
    s.send(KERN_WARN, "fw01", "kernel",
           fw("DROP", random.choice(INTERNET_NOISE), "10.10.10.20", "TCP", port, iface_in="eth0", iface_out="eth1"))


def noise_cron(s):
    host = random.choice(SSH_HOSTS)
    cmd = random.choice(["/usr/lib/sysstat/sa1 1 1", "test -x /usr/sbin/anacron || run-parts /etc/cron.daily",
                         "/usr/local/bin/backup-rotate.sh", "[ -x /usr/lib/php/sessionclean ] && /usr/lib/php/sessionclean"])
    s.send(CRON_INFO, host, "CRON", f"(root) CMD ({cmd})")


def noise_systemd(s):
    host = random.choice(SSH_HOSTS)
    msg = random.choice([f"Started Session {random.randint(1000, 9999)} of User {random.choice(USERS)}.",
                         "Started Daily apt download activities.", "Starting Cleanup of Temporary Directories...",
                         "Finished Cleanup of Temporary Directories.", "Started Refresh fwupd metadata and update motd."])
    s.send(DAEMON_INFO, host, "systemd", msg, pid=False)


def noise_ntp(s):
    s.send(DAEMON_INFO, random.choice(SSH_HOSTS), "chronyd", f"Selected source 10.10.0.{random.choice([1, 2])} (ntp.acme-corp.example)")


def noise_nginx_health(s):
    s.send(LOCAL0_INFO, random.choice(["web01", "web02"]), "nginx",
           f'10.10.10.2 - - "GET /healthz HTTP/1.1" 200 2 "-" "kube-probe/1.30"')


def noise_ssh_internal(s):
    host, user = random.choice(SSH_HOSTS), random.choice(USERS + SERVICE_USERS)
    src = random.choice(LAPTOPS) if user in USERS else "10.10.30.15"
    if random.random() < 0.4:
        s.send(AUTHPRIV_INFO, host, "sshd",
               f"Accepted publickey for {user} from {src} port {random.randint(40000, 65000)} ssh2: "
               f"ED25519 SHA256:{random.getrandbits(128):032x}")
    else:
        verb = random.choice(["opened", "closed"])
        tail = " by (uid=0)" if verb == "opened" else ""
        s.send(AUTHPRIV_INFO, host, "sshd", f"pam_unix(sshd:session): session {verb} for user {user}(uid={1000 + USERS.index(user) if user in USERS else 998}){tail}")


def noise_sudo_routine(s):
    user = random.choice(USERS)
    cmd = random.choice(["/usr/bin/systemctl restart nginx", "/usr/bin/journalctl -u app --since today",
                         "/usr/bin/apt-get update", "/usr/bin/docker ps"])
    s.send(AUTHPRIV_NOTICE, random.choice(SUDO_HOSTS), "sudo",
           f"{user} : TTY=pts/{random.randint(0, 4)} ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}", pid=False)


NOISE = [
    (noise_fw_outbound, 52), (noise_fw_internal, 12), (noise_fw_internet_drop, 9),
    (noise_cron, 6), (noise_systemd, 8), (noise_ntp, 3), (noise_nginx_health, 4),
    (noise_ssh_internal, 5), (noise_sudo_routine, 1),
]
NOISE_FUNCS, NOISE_WEIGHTS = zip(*NOISE)


# ----------------------------- attack scenarios -----------------------------

def scenario_bruteforce(s, burst_no):
    attacker = BRUTEFORCE_IP if burst_no % 2 == 0 else BRUTEFORCE_IP_2
    target = "bastion01"
    for _ in range(random.randint(15, 30)):
        user = random.choice(["root", "admin", "oracle", "ubuntu", "test", "svc_backup", "postgres"])
        invalid = "invalid user " if user in ("admin", "oracle", "test", "postgres") else ""
        s.send(AUTHPRIV_WARN, target, "sshd",
               f"Failed password for {invalid}{user} from {attacker} port {random.randint(30000, 65000)} ssh2")
        time.sleep(random.uniform(0.2, 0.8))
    if burst_no % 3 == 2:  # every third burst the attacker gets in ...
        s.send(AUTHPRIV_INFO, target, "sshd",
               f"Accepted password for svc_backup from {attacker} port {random.randint(30000, 65000)} ssh2")
        time.sleep(2)
        s.send(AUTHPRIV_NOTICE, target, "sudo",
               "svc_backup : TTY=pts/3 ; PWD=/home/svc_backup ; USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash sysupdate",
               pid=False)
        s.send(AUTHPRIV_INFO, target, "useradd",
               "new user: name=sysupdate, UID=1050, GID=1050, home=/home/sysupdate, shell=/bin/bash, from=/dev/pts/3")
        s.send(AUTHPRIV_INFO, target, "usermod", "add 'sysupdate' to group 'sudo'")


def scenario_c2_beacon(s):
    for _ in range(random.randint(2, 4)):
        s.send(KERN_INFO, "fw01", "kernel", fw("ACCEPT", "10.10.20.45", C2_IP, "TCP", 8443))
        time.sleep(random.uniform(0.5, 1.5))


def scenario_port_scan(s):
    ports = random.sample(range(1, 10000), 60) + random.sample(SENSITIVE_PORTS, 4)
    random.shuffle(ports)
    for port in ports:
        s.send(KERN_WARN, "fw01", "kernel",
               fw("DROP", SCANNER_IP, "10.10.10.20", "TCP", port, iface_in="eth0", iface_out="eth1"))
        time.sleep(0.05)


def scenario_account(s):
    user = random.choice(USERS)
    src = random.choice(LAPTOPS)
    msg = random.choice([f"password reset requested for {user}@{EMAIL_DOMAIN} from {src}",
                         f"MFA device enrolled for {user}@{EMAIL_DOMAIN} from {src}",
                         f"MFA device removed for {user}@{EMAIL_DOMAIN} from {src}"])
    s.send(LOCAL0_NOTICE, "app01", "account-service", msg)


SCENARIOS = [  # (function, mean seconds between occurrences)
    ("bruteforce", 90), ("c2", 120), ("scan", 150), ("account", 20),
]


def main():
    s = Syslog()
    s.resolve()
    print(f"sending ~{EPS:.0f} events/s to {s.addr[0]}:{s.addr[1]}", flush=True)
    next_at = {name: time.time() + random.uniform(10, mean) for name, mean in SCENARIOS}
    bursts, sent, last_report = 0, 0, time.time()
    interval = 1.0 / EPS

    while True:
        start = time.time()
        random.choices(NOISE_FUNCS, NOISE_WEIGHTS)[0](s)
        sent += 1

        for name, mean in SCENARIOS:
            if start >= next_at[name]:
                # scenarios sleep between steps, so run them beside the noise stream
                if name == "bruteforce":
                    args = (scenario_bruteforce, (s, bursts))
                    bursts += 1
                elif name == "c2":
                    args = (scenario_c2_beacon, (s,))
                elif name == "scan":
                    args = (scenario_port_scan, (s,))
                else:
                    args = (scenario_account, (s,))
                threading.Thread(target=args[0], args=args[1], daemon=True).start()
                next_at[name] = time.time() + random.expovariate(1.0 / mean)

        if start - last_report >= 60:
            print(f"{sent} noise events in the last minute", flush=True)
            sent, last_report = 0, start

        time.sleep(max(0.0, interval - (time.time() - start)))


if __name__ == "__main__":
    main()
