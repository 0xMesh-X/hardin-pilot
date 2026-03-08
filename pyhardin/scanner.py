from pathlib import Path

from pydantic import BaseModel, Field

KNOWN_SERVICE_PATHS: dict[str, list[str]] = {
    "ssh": ["/etc/ssh/sshd_config", "/etc/ssh/ssh_config"],
    "nginx": ["/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/", "/etc/nginx/conf.d/"],
    "apache2": [
        "/etc/apache2/apache2.conf",
        "/etc/apache2/sites-enabled/",
        "/etc/apache2/conf-enabled/",
    ],
    "mysql": ["/etc/mysql/my.cnf", "/etc/mysql/mysql.conf.d/", "/etc/mysql/conf.d/"],
    "mariadb": ["/etc/mysql/mariadb.conf.d/"],
    "postgresql": ["/etc/postgresql/"],
    "redis": ["/etc/redis/redis.conf"],
    "samba": ["/etc/samba/smb.conf"],
    "vsftpd": ["/etc/vsftpd.conf", "/etc/vsftpd/"],
    "proftpd": ["/etc/proftpd/proftpd.conf"],
    "postfix": ["/etc/postfix/main.cf", "/etc/postfix/master.cf"],
    "dovecot": ["/etc/dovecot/dovecot.conf", "/etc/dovecot/conf.d/"],
    "bind": ["/etc/bind/named.conf", "/etc/bind/named.conf.options"],
    "dhcp": ["/etc/dhcp/dhcpd.conf"],
    "ntp": ["/etc/ntp.conf", "/etc/chrony/chrony.conf"],
    "rsyslog": ["/etc/rsyslog.conf", "/etc/rsyslog.d/"],
    "logrotate": ["/etc/logrotate.conf", "/etc/logrotate.d/"],
    "sudo": ["/etc/sudoers", "/etc/sudoers.d/"],
    "cron": ["/etc/crontab", "/etc/cron.d/"],
    "pam": ["/etc/pam.d/"],
    "ufw": ["/etc/ufw/", "/etc/default/ufw"],
    "iptables": ["/etc/iptables/"],
    "fail2ban": ["/etc/fail2ban/jail.conf", "/etc/fail2ban/jail.local"],
    "sysctl": ["/etc/sysctl.conf", "/etc/sysctl.d/"],
    "grub": ["/etc/default/grub"],
    "fstab": ["/etc/fstab"],
    "hosts": ["/etc/hosts", "/etc/hosts.allow", "/etc/hosts.deny"],
    "resolv": ["/etc/resolv.conf"],
    "nsswitch": ["/etc/nsswitch.conf"],
    "login_defs": ["/etc/login.defs"],
    "passwd_shadow": ["/etc/passwd", "/etc/shadow", "/etc/group"],
    "docker": ["/etc/docker/daemon.json"],
    "kubernetes": ["/etc/kubernetes/"],
    "snmp": ["/etc/snmp/snmpd.conf"],
    "nfs": ["/etc/exports"],
    "xinetd": ["/etc/xinetd.conf", "/etc/xinetd.d/"],
    "systemd": ["/etc/systemd/system.conf", "/etc/systemd/journald.conf"],
    "auditd": ["/etc/audit/auditd.conf", "/etc/audit/rules.d/"],
    "apparmor": ["/etc/apparmor.d/"],
    "selinux": ["/etc/selinux/config"],
    "modprobe": ["/etc/modprobe.d/"],
    "network": ["/etc/network/interfaces", "/etc/netplan/"],
    "squid": ["/etc/squid/squid.conf"],
    "haproxy": ["/etc/haproxy/haproxy.cfg"],
    "openvpn": ["/etc/openvpn/"],
    "wireguard": ["/etc/wireguard/"],
    "php": ["/etc/php/"],
    "mongodb": ["/etc/mongod.conf"],
    "elasticsearch": ["/etc/elasticsearch/elasticsearch.yml"],
    "memcached": ["/etc/memcached.conf"],
    "tomcat": ["/etc/tomcat9/", "/etc/tomcat8/"],
}

CONFIG_EXTENSIONS = {
    ".conf", ".cfg", ".cnf", ".ini", ".yaml", ".yml",
    ".json", ".toml", ".properties", ".xml",
}


class ServiceConfig(BaseModel):
    service_name: str
    files: list[str] = Field(default_factory=list)
    contents: dict[str, str] = Field(default_factory=dict)
    os_context: dict[str, str] = Field(default_factory=dict)


def detect_linux_distro() -> dict[str, str]:
    """Parse /etc/os-release to identify the Linux distribution."""
    os_info = {}
    try:
        p = Path("/etc/os-release")
        if p.exists() and p.is_file():
            content = p.read_text(errors="replace")
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    val = val.strip('"').strip("'")
                    os_info[key] = val
    except (PermissionError, OSError):
        pass

    # Fallback for older systems like CentOS 6 or very obscure distros
    if not os_info:
        try:
            if Path("/etc/redhat-release").exists():
                os_info["ID"] = "rhel"
                os_info["PRETTY_NAME"] = Path("/etc/redhat-release").read_text().strip()
            elif Path("/etc/debian_version").exists():
                os_info["ID"] = "debian"
                deb_ver = Path('/etc/debian_version').read_text().strip()
                os_info["PRETTY_NAME"] = f"Debian GNU/Linux {deb_ver}"
        except (PermissionError, OSError):
            pass

    return os_info


def _read_file_safe(path: str) -> str | None:
    try:
        p = Path(path)
        if p.is_file() and p.stat().st_size < 1_000_000:
            return p.read_text(errors="replace")
    except (PermissionError, OSError):
        pass
    return None


def _scan_directory(dir_path: str) -> list[str]:
    found: list[str] = []
    try:
        p = Path(dir_path)
        if not p.is_dir():
            return found
        for item in p.rglob("*"):
            if item.is_file() and (item.suffix in CONFIG_EXTENSIONS or item.name.startswith(".")):
                found.append(str(item))
    except (PermissionError, OSError):
        pass
    return found


def scan_known_services() -> list[ServiceConfig]:
    results = []
    os_context = detect_linux_distro()
    for service_name, paths in KNOWN_SERVICE_PATHS.items():
        svc = ServiceConfig(service_name=service_name, os_context=os_context)
        for path in paths:
            p = Path(path)
            if p.is_dir():
                files = _scan_directory(path)
                svc.files.extend(files)
            elif p.is_file():
                svc.files.append(path)
        svc.files = sorted(set(svc.files))
        if svc.files:
            for fp in svc.files:
                content = _read_file_safe(fp)
                if content:
                    svc.contents[fp] = content
        if svc.contents:
            results.append(svc)
    return results


def scan_additional_configs(extra_paths: list[str] | None = None) -> list[ServiceConfig]:
    results = []
    search_dirs = ["/etc"]
    if extra_paths:
        search_dirs.extend(extra_paths)

    known_files: set[str] = set()
    for paths in KNOWN_SERVICE_PATHS.values():
        for p in paths:
            if Path(p).is_file():
                known_files.add(p)

    os_context = detect_linux_distro()
    misc = ServiceConfig(service_name="miscellaneous", os_context=os_context)
    for search_dir in search_dirs:
        for fpath in _scan_directory(search_dir):
            if fpath not in known_files:
                content = _read_file_safe(fpath)
                if content:
                    misc.files.append(fpath)
                    misc.contents[fpath] = content

    if misc.contents:
        misc.files = sorted(set(misc.files))
        results.append(misc)
    return results


def list_all_services() -> list[str]:
    available = []
    for service_name, paths in sorted(KNOWN_SERVICE_PATHS.items()):
        for path in paths:
            p = Path(path)
            if p.exists():
                available.append(service_name)
                break
    return available


def run_full_scan(extra_paths: list[str] | None = None) -> list[ServiceConfig]:
    known = scan_known_services()
    additional = scan_additional_configs(extra_paths)
    return known + additional
