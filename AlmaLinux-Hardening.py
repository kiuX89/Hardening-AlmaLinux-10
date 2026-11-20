#!/usr/bin/env python3
# AlmaLinux hardening - exécution unique, sans --resume ni service de reprise.
# Le journal script.log est créé dans le même dossier que ce script.

import grp
import json
import logging
import os
import pwd
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
LOG_FILE = SCRIPT_DIR / "script.log"
STATE_DIR = Path("/var/lib/alma-hardening")
SSH_PORT = 49222
SSH_DROPIN = Path("/etc/ssh/sshd_config.d/99-hardening.conf")
F2B_JAIL = Path("/etc/fail2ban/jail.local")
F2B_LOCAL = Path("/etc/fail2ban/fail2ban.local")
SYSCTL_FILE = Path("/etc/sysctl.d/99-hardening.conf")
FSTAB = Path("/etc/fstab")

logger = logging.getLogger("alma-hardening")
logger.setLevel(logging.INFO)
logger.handlers.clear()

logger.propagate = False  # Empêche l'affichage des INFO dans le terminal

formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)


def log(message, level="info"):
    getattr(logger, level)(message)


def run(command, *, check=True, timeout=300, input_text=None):
    """Exécute une commande sans afficher sa sortie à l'écran; tout va dans script.log."""
    if isinstance(command, str):
        args = shlex.split(command)
        display = command
    else:
        args = [str(x) for x in command]
        display = shlex.join(args)
    log(f"$ {display}")
    try:
        result = subprocess.run(
            args, text=True, input=input_text, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=timeout, check=False
        )
        output = (result.stdout or "").rstrip()
        if output:
            log("SORTIE COMMANDE:\n" + output)
        log(f"CODE RETOUR: {result.returncode}")
        if check and result.returncode != 0:
            raise RuntimeError(f"Commande en échec (code {result.returncode}): {display}")
        return result
    except subprocess.TimeoutExpired as exc:
        log(f"TIMEOUT après {timeout}s: {display}", "error")
        if exc.stdout:
            log(str(exc.stdout), "error")
        raise RuntimeError(f"Délai dépassé: {display}") from exc


def write_file(path, content, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            if not content.endswith("\n"):
                f.write("\n")
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
        log(f"Fichier écrit: {path} (mode {oct(mode)})")
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def task(label, function, *, required=True):
    try:
        function()
        print(f"✅ {label}")
        log(f"OK: {label}")
        return True
    except Exception as exc:
        print(f"❌ {label}")
        log(f"ÉCHEC: {label}: {exc}", "error")
        if required:
            log("Arrêt du script après une étape obligatoire en échec.", "error")
            raise
        return False


def require_root():
    if os.geteuid() != 0:
        print("❌ Ce script doit être exécuté en root (sudo ou connexion root).")
        sys.exit(1)


def select_wheel_user():
    wheel_gid = grp.getgrnam("wheel").gr_gid
    candidates = []
    for entry in pwd.getpwall():
        if entry.pw_uid < 1000 or entry.pw_uid == 65534:
            continue
        groups = {g.gr_gid for g in grp.getgrall() if entry.pw_name in g.gr_mem}
        try:
            primary_name = grp.getgrgid(entry.pw_gid).gr_name
        except KeyError:
            primary_name = ""
        if entry.pw_gid == wheel_gid or wheel_gid in groups or primary_name == "wheel":
            candidates.append(entry)
    candidates.sort(key=lambda p: p.pw_name)
    if not candidates:
        raise RuntimeError("Aucun utilisateur humain appartenant à wheel n'a été trouvé.")
    print("Choisissez un administrateur qui aura uniquement le droit de se connecter en SSH :")
    for i, entry in enumerate(candidates, 1):
        print(f"[{i}] {entry.pw_name}")
    while True:
        choice = input("Choix de l'utilisateur SSH : ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(candidates):
            user = candidates[int(choice) - 1]
            break
        print("Choix invalide.")
    print("Collez la clé PUBLIQUE SSH (une seule ligne), puis Entrée :")
    key = input().strip()
    if not re.match(r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com)\s+\S+", key):
        raise RuntimeError("Format de clé publique SSH non reconnu.")
    if "\n" in key or "\r" in key:
        raise RuntimeError("La clé doit tenir sur une seule ligne.")
    log(f"Utilisateur SSH sélectionné: {user.pw_name}")
    log(f"Type de clé SSH fourni: {key.split()[0]}")
    return user, key


def install_authorized_key(user, key):
    ssh_dir = Path(user.pw_dir) / ".ssh"
    ssh_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(ssh_dir, user.pw_uid, user.pw_gid)
    os.chmod(ssh_dir, 0o700)
    auth = ssh_dir / "authorized_keys"
    existing = auth.read_text(encoding="utf-8") if auth.exists() else ""
    if key not in existing.splitlines():
        with auth.open("a", encoding="utf-8") as f:
            if existing and not existing.endswith("\n"):
                f.write("\n")
            f.write(key + "\n")
    os.chown(auth, user.pw_uid, user.pw_gid)
    os.chmod(auth, 0o600)
    run(["restorecon", "-RF", str(ssh_dir)], check=False)
    log(f"Clé publique installée dans {auth}")


def system_update():
    run(["dnf", "makecache"], timeout=900)
    run(["dnf", "update", "-y"], timeout=3600)
    run(["dnf", "autoremove", "-y"], timeout=1800)


def packages_and_base():
    run(["dnf", "install", "-y", "epel-release", "dnf-utils"], timeout=1800)
    packages = [
        "vim", "git", "wget", "curl", "tar",
        "policycoreutils-python-utils", "setroubleshoot-server",
        "chrony", "firewalld", "openssh-server"
    ]
    run(["dnf", "install", "-y"] + packages, timeout=1800)
    run(["dnf", "remove", "-y", "cockpit", "cockpit-ws", "cockpit-bridge",
         "cockpit-system", "cockpit-packagekit", "cockpit-storaged",
         "cockpit-podman"], check=False, timeout=1200)
    run(["timedatectl", "set-timezone", "Europe/Paris"])
    run(["systemctl", "enable", "--now", "chronyd"])
    # autoremove peut avoir retiré le paquet SELinux utilitaire : on le réinstalle explicitement.
    run(["dnf", "install", "-y", "policycoreutils-python-utils"], timeout=900)
    if shutil.which("semanage") is None:
        raise RuntimeError("La commande semanage est introuvable après installation du paquet.")


def configure_firewall():
    run(["systemctl", "enable", "--now", "firewalld"])
    # Le port est ouvert AVANT le changement de port SSH pour éviter de couper l'accès.
    run(["firewall-cmd", "--permanent", f"--add-port={SSH_PORT}/tcp"])
    for service in ("ssh", "cockpit", "dhcpv6-client"):
        run(["firewall-cmd", "--permanent", f"--remove-service={service}"], check=False)
    run(["firewall-cmd", "--permanent", "--set-target=DROP"])
    # firewalld ne possède pas d'option générique --remove-forward.
    # Les redirections existantes sont laissées intactes plutôt que de supprimer une règle inconnue.
    log("INFO: aucune option générique --remove-forward n'existe dans firewall-cmd; règles de redirection existantes conservées.")
    run(["firewall-cmd", "--reload"])
    run(["firewall-cmd", "--query-port", f"{SSH_PORT}/tcp"])


def set_selinux_ssh_port():
    """Ajoute directement le port SSH 49222 à la politique SELinux."""
    if shutil.which("semanage") is None:
        run(["dnf", "install", "-y", "policycoreutils-python-utils"], timeout=900)
    run(["semanage", "port", "-a", "-t", "ssh_port_t", "-p", "tcp", str(SSH_PORT)])


def enforce_ssh_key_only(user_name):
    final_config = f"""# Géré par alma-hardening.py
Port {SSH_PORT}
AddressFamily inet
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
PermitEmptyPasswords no
IgnoreRhosts yes
StrictModes yes
UsePAM yes
AllowUsers {user_name}
MaxAuthTries 3
MaxSessions 2
LoginGraceTime 30
MaxStartups 10:30:60
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
PermitUserRC no
PermitUserEnvironment no
LogLevel VERBOSE
"""
    backup = SSH_DROPIN.with_suffix(".conf.pre-hardening")
    if SSH_DROPIN.exists():
        shutil.copy2(SSH_DROPIN, backup)
    write_file(SSH_DROPIN, final_config, 0o600)
    try:
        run(["sshd", "-t"])
        run(["systemctl", "enable", "sshd"])
        run(["systemctl", "restart", "sshd"])
    except Exception:
        if backup.exists():
            shutil.copy2(backup, SSH_DROPIN)
            run(["sshd", "-t"], check=False)
            run(["systemctl", "restart", "sshd"], check=False)
        raise




def configure_fail2ban():
    run(
        ["dnf", "install", "-y", "fail2ban", "fail2ban-firewalld"],
        timeout=900
    )

    jail = """[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 3
backend = systemd
bantime.increment = true
bantime.factor = 1
bantime.maxtime = 2w
bantime.overalljails = true
bantime.rndtime = 10m
banaction = firewallcmd-rich-rules

[sshd]
enabled = true
port = 49222
backend = systemd
maxretry = 3
findtime = 10m
bantime = 1h

[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
backend = auto
maxretry = 3
findtime = 24h
bantime = 1w
banaction = firewallcmd-rich-rules
"""

    local = """[Definition]
dbpurgeage = 30d
logtarget = /var/log/fail2ban.log
"""

    # Écrire les fichiers de configuration.
    write_file(F2B_JAIL, jail, 0o644)
    write_file(F2B_LOCAL, local, 0o644)

    # Préparer le fichier de journalisation.
    log_file = Path("/var/log/fail2ban.log")
    log_file.parent.mkdir(parents=True, exist_ok=True)
    log_file.touch(exist_ok=True)
    os.chmod(log_file, 0o600)
    os.chown(log_file, 0, 0)

    # Vérifier la syntaxe de la configuration.
    run(["fail2ban-client", "-t"], timeout=60)

    # Activer et redémarrer Fail2ban.
    run(["systemctl", "enable", "fail2ban"], timeout=30)
    run(["systemctl", "restart", "fail2ban"], timeout=60)

    # Vérifier que systemd considère le service actif.
    status = run(
        ["systemctl", "is-active", "fail2ban"],
        check=False,
        timeout=30
    )

    if status.stdout.strip() != "active":
        run(
            ["journalctl", "-u", "fail2ban", "-n", "100", "--no-pager"],
            check=False,
            timeout=30
        )
        raise RuntimeError(
            "Le service Fail2ban n'est pas actif."
        )

    # Attendre que le socket soit disponible et que le serveur réponde.
    import time

    server_ready = False

    for attempt in range(10):
        ping = run(
            ["fail2ban-client", "ping"],
            check=False,
            timeout=10
        )

        if ping.returncode == 0:
            server_ready = True
            break

        time.sleep(1)

    if not server_ready:
        run(
            ["journalctl", "-u", "fail2ban", "-n", "100", "--no-pager"],
            check=False,
            timeout=30
        )

        run(
            ["tail", "-n", "100", "/var/log/fail2ban.log"],
            check=False,
            timeout=30
        )

        raise RuntimeError(
            "Fail2ban ne répond pas après son démarrage."
        )

    # Vérifier les prisons configurées.
    run(
        ["fail2ban-client", "status"],
        timeout=30
    )

    run(
        ["fail2ban-client", "status", "sshd"],
        timeout=30
    )

    run(
        ["fail2ban-client", "status", "recidive"],
        timeout=30
    )

    log("Configuration Fail2ban terminée avec succès.")


def configure_dnf_automatic():
    run(["dnf", "install", "-y", "dnf-automatic"], timeout=900)
    conf = Path("/etc/dnf/automatic.conf")
    content = conf.read_text(encoding="utf-8") if conf.exists() else ""
    if "[commands]" not in content:
        content += "\n[commands]\n"
    section = re.search(r"(?ms)^\[commands\]\s*(.*?)(?=^\[|\Z)", content)
    block = section.group(1) if section else ""
    values = {
        "upgrade_type": "security",
        "download_updates": "yes",
        "apply_updates": "yes",
        "reboot": "when-needed",
    }
    for key, value in values.items():
        pattern = rf"(?m)^{re.escape(key)}\s*=.*$"
        if re.search(pattern, block):
            block = re.sub(pattern, f"{key} = {value}", block)
        else:
            block += f"\n{key} = {value}"
    if section:
        content = content[:section.start(1)] + block.rstrip() + "\n" + content[section.end(1):]
    else:
        content += block
    write_file(conf, content, 0o644)
    timer = Path("/etc/systemd/system/dnf-automatic.timer.d/override.conf")
    timer_content = """[Timer]
OnCalendar=*-*-* 03:30:00
RandomizedDelaySec=0
Persistent=true

"""
    write_file(timer, timer_content, 0o644)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now", "dnf-automatic.timer"])



def configure_authselect():
    # Installer authselect.
    run(["dnf", "install", "-y", "authselect"], timeout=900)

    # Vérifier le profil actuel et le journaliser.
    run(["authselect", "current"], timeout=30)

    # Activer la protection contre les tentatives échouées.
    run(
        ["authselect", "enable-feature", "with-faillock"],
        timeout=60
    )

    # Appliquer les modifications PAM.
    run(
        ["authselect", "apply-changes"],
        timeout=60
    )

    # Configurer faillock.
    faillock = """# Nombre maximum de tentatives échouées avant blocage
deny = 5

# Durée du blocage : 900 secondes (15 minutes)
unlock_time = 900

# Appliquer également le blocage au compte root
even_deny_root
"""

    write_file(
        "/etc/security/faillock.conf",
        faillock,
        0o644
    )

    # Vérifier la configuration finale.
    run(["authselect", "current"], timeout=30)

    log("Protection authselect / faillock configurée avec succès.")



def configure_sysctl():
    content = """# Paramètres de durcissement réseau et noyau
# IPv4
# ============================================================
# ALMALINUX - HARDENING SYSTEME VIA SYSCTL
# Fichier : /etc/sysctl.d/99-hardening.conf
# Objectif : Renforcement du noyau, du réseau et de la mémoire
# ============================================================


# ============================================================
# 1. CONFIGURATION DU ROUTAGE
# ============================================================

# Désactive le transfert des paquets IPv4.
# Le serveur ne doit pas agir comme un routeur.
net.ipv4.ip_forward = 0

# Désactive le transfert des paquets IPv6.
# Empêche le noyau de router le trafic IPv6.
net.ipv6.conf.all.forwarding = 0


# ============================================================
# 2. PROTECTION RESEAU IPV4
# ============================================================

# Active le filtrage anti-spoofing strict.
# Vérifie que l'interface de réception correspond au chemin
# de retour vers l'adresse IP source.
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Refuse les routes sources IP.
# Empêche un paquet de dicter son propre chemin réseau.
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Refuse les redirections ICMP entrantes.
# Empêche une machine distante de modifier les routes du serveur.
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# Désactive les redirections ICMP considérées comme sécurisées.
# Complète la protection contre les modifications de routage.
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Empêche le serveur d'envoyer des redirections ICMP.
# Un serveur classique n'a pas besoin de conseiller des routes.
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Journalise les paquets ayant des adresses incohérentes.
# Utile pour détecter certaines anomalies et tentatives de spoofing.
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore les requêtes ICMP Echo envoyées en broadcast.
# Réduit les risques d'attaques de type Smurf.
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore certaines erreurs ICMP incorrectes.
# Évite de traiter des messages ICMP manifestement anormaux.
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Active les SYN Cookies.
# Protection contre certaines attaques TCP SYN Flood.
net.ipv4.tcp_syncookies = 1

# Active la protection TCP contre le TIME-WAIT assassination.
# Améliore le respect des règles TCP RFC 1337.
net.ipv4.tcp_rfc1337 = 1

# Empêche le routage des adresses loopback depuis les interfaces.
# Évite notamment certains détournements utilisant 127.0.0.0/8.
net.ipv4.conf.all.route_localnet = 0
net.ipv4.conf.default.route_localnet = 0

# Refuse les paquets utilisant une adresse source locale
# reçus depuis une interface réseau.
net.ipv4.conf.all.accept_local = 0
net.ipv4.conf.default.accept_local = 0

# Désactive le Proxy ARP.
# Empêche le serveur de répondre aux requêtes ARP
# pour le compte d'autres machines.
net.ipv4.conf.all.proxy_arp = 0
net.ipv4.conf.default.proxy_arp = 0


# ============================================================
# 3. PROTECTION RESEAU IPV6
# ============================================================

# Refuse les redirections ICMPv6 entrantes.
# Empêche la modification des routes IPv6 par des tiers.
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Refuse les routes sources IPv6.
# Empêche les paquets de spécifier leur propre chemin.
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0


# ============================================================
# 4. PROTECTION DES INFORMATIONS DU NOYAU
# ============================================================

# Restreint l'accès aux messages du noyau via dmesg.
# Empêche les utilisateurs non privilégiés de consulter
# certaines informations sensibles du système.
kernel.dmesg_restrict = 1

# Masque les adresses des pointeurs du noyau.
# Réduit les possibilités de fuite d'informations mémoire.
kernel.kptr_restrict = 2

# Restreint ptrace.
# Un processus ne peut normalement pas inspecter arbitrairement
# les autres processus appartenant à d'autres utilisateurs.
kernel.yama.ptrace_scope = 1

# Désactive BPF pour les utilisateurs non privilégiés.
# Réduit la surface d'attaque liée aux programmes eBPF.
kernel.unprivileged_bpf_disabled = 1

# Désactive les commandes Magic SysRq.
# Empêche leur utilisation via le clavier ou certaines interfaces.
kernel.sysrq = 0


# ============================================================
# 5. PROTECTION DE LA MEMOIRE
# ============================================================

# Active l'ASLR complet.
# Randomise les adresses mémoire des composants du système.
kernel.randomize_va_space = 2

# Désactive les core dumps pour les exécutables SUID/SGID.
# Évite l'exposition de données sensibles dans les dumps mémoire.
fs.suid_dumpable = 0

# Ajoute le PID au nom des fichiers core dump.
# Permet de distinguer les éventuels fichiers de crash.
kernel.core_uses_pid = 1


# ============================================================
# 6. PROTECTION DES FICHIERS ET DU SYSTEME
# ============================================================

# Protège contre certaines attaques utilisant des liens symboliques.
fs.protected_symlinks = 1

# Empêche certains abus de liens physiques.
fs.protected_hardlinks = 1

# Protège les FIFO dans les répertoires accessibles en écriture
# par plusieurs utilisateurs.
fs.protected_fifos = 2

# Protège les fichiers ordinaires dans les répertoires
# accessibles en écriture par plusieurs utilisateurs.
fs.protected_regular = 2


# ============================================================
# FIN DU HARDENING SYSCTL
# ============================================================
"""
    write_file(SYSCTL_FILE, content, 0o644)
    run(["sysctl", "--system"], timeout=300)


def disable_services():
    services = [
        "bluetooth.service", "libstoragemgmt.service", "udisks2.service",
        "plocate-updatedb.timer", "raid-check.timer", "mdmonitor.service",
        "atd.service", "cups.service", "avahi-daemon.service"
    ]
    for service in services:
        run(["systemctl", "disable", "--now", service], check=False)
        run(["systemctl", "mask", service], check=False)
    run(["dnf", "remove", "-y", "cups", "avahi", "bluez"], check=False, timeout=1200)
    run(["dnf", "autoremove", "-y"], timeout=1800)


def harden_tmpfs():
    line = "tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0"
    lines = FSTAB.read_text(encoding="utf-8").splitlines() if FSTAB.exists() else []
    if not any(re.match(r"^\s*tmpfs\s+/dev/shm\s+", item) for item in lines):
        with FSTAB.open("a", encoding="utf-8") as f:
            f.write("\n" + line + "\n")
    else:
        updated = []
        for item in lines:
            if re.match(r"^\s*tmpfs\s+/dev/shm\s+", item):
                updated.append(line)
            else:
                updated.append(item)
        write_file(FSTAB, "\n".join(updated) + "\n", 0o644)
    run(["systemctl", "daemon-reload"])
    run(["mount", "-o", "remount,nosuid,nodev,noexec", "/dev/shm"])


def configure_dnf_conf():
    path = Path("/etc/dnf/dnf.conf")
    content = path.read_text(encoding="utf-8") if path.exists() else ""
    if re.search(r"(?m)^installonly_limit\s*=", content):
        content = re.sub(r"(?m)^installonly_limit\s*=.*$", "installonly_limit=2", content)
    else:
        content += "\ninstallonly_limit=2\n"
    write_file(path, content, 0o644)

def run_command(command, timeout=900, show_passphrase_prompt=False):
    """Exécute silencieusement les commandes LUKS, sauf l'invite de passphrase."""

    display = shlex.join(map(str, command))
    log(f"[LUKS] $ {display}")

    if show_passphrase_prompt:
        result = subprocess.run(
            command,
            text=True,
            stdin=None,
            stdout=subprocess.DEVNULL,
            stderr=None,
            timeout=timeout
        )
        output = ""
    else:
        result = subprocess.run(
            command,
            text=True,
            stdin=None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout
        )
        output = (result.stdout or "").strip()

        if output:
            log("[LUKS] SORTIE COMMANDE:\n" + output)

    log(f"[LUKS] CODE RETOUR: {result.returncode}")

    if result.returncode != 0:
        raise RuntimeError(
            "Échec commande LUKS. Consultez script.log pour les détails."
        )

    return output

def find_partition_pair():

    boot_source = run_command([
        "findmnt", "-n", "-o", "SOURCE", "--target", "/boot"
    ])

    boot_source = os.path.realpath(boot_source)

    if not boot_source.startswith("/dev/"):
        raise RuntimeError(
            f"Source de /boot non reconnue : {boot_source}"
        )

    boot_uuid = run_command([
        "blkid", "-s", "UUID", "-o", "value", boot_source
    ]).strip()

    if not boot_uuid:
        raise RuntimeError("UUID de /boot introuvable.")

    rows = run_command([
        "lsblk", "-nrpo", "NAME,TYPE,PKNAME,PARTN,FSTYPE"
    ])

    boot_number = None
    parent_disk = None

    for line in rows.splitlines():

        fields = line.split()

        if len(fields) < 5:
            continue

        name, part_type, parent, part_number, fs_type = fields[:5]

        if os.path.realpath(name) == boot_source:

            if part_type != "part":
                raise RuntimeError(
                    "/boot n'est pas une partition classique."
                )

            parent_disk = parent
            boot_number = part_number
            break

    if not parent_disk or not boot_number:
        raise RuntimeError(
            "Impossible d'identifier le disque parent de /boot."
        )

    target_number = str(int(boot_number) + 1)
    target_partition = None

    for line in rows.splitlines():

        fields = line.split()

        if len(fields) < 5:
            continue

        name, part_type, parent, part_number, fs_type = fields[:5]

        if (
            part_type == "part"
            and os.path.realpath(parent) == os.path.realpath(parent_disk)
            and part_number == target_number
        ):
            target_partition = name
            break

    if not target_partition:
        raise RuntimeError(
            f"Partition {target_number} introuvable."
        )

    filesystem_type = run_command([
        "blkid", "-s", "TYPE", "-o", "value", target_partition
    ]).strip()

    if filesystem_type != "crypto_LUKS":
        raise RuntimeError(
            f"{target_partition} n'est pas un volume crypto_LUKS."
        )

    run_command([
        "cryptsetup", "isLuks", target_partition
    ], timeout=30)

    luks_uuid = run_command([
        "cryptsetup", "luksUUID", target_partition
    ], timeout=30).strip()

    if not luks_uuid:
        raise RuntimeError("UUID LUKS introuvable.")

    return boot_source, boot_uuid, target_partition, luks_uuid


# ============================================================
# MISE À JOUR DE /ETC/CRYPTTAB
# ============================================================

def update_crypttab(luks_uuid, boot_uuid):

    crypttab = Path("/etc/crypttab")
    backup = Path("/etc/crypttab.backup")

    if not crypttab.exists():
        raise RuntimeError("/etc/crypttab introuvable.")

    current = crypttab.read_text(encoding="utf-8")
    lines = current.splitlines()

    volume_name = f"luks-{luks_uuid}"

    # Format exact de la documentation.
    key_spec = f"/luks-keyfile.bin:UUID={boot_uuid}"

    updated_lines = []
    matches = 0

    for line in lines:

        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            updated_lines.append(line)
            continue

        fields = stripped.split()

        if len(fields) < 2:
            updated_lines.append(line)
            continue

        if (
            fields[0] == volume_name
            or fields[1] == f"UUID={luks_uuid}"
        ):

            matches += 1

            # Nom du volume.
            fields[0] = volume_name

            # Périphérique source.
            fields[1] = f"UUID={luks_uuid}"

            # Chemin du keyfile sur /boot.
            if len(fields) >= 3:
                fields[2] = key_spec
            else:
                fields.append(key_spec)

            # Options.
            if len(fields) >= 4:
                fields[3] = "discard,x-initrd.attach"
            else:
                fields.append("discard,x-initrd.attach")

            updated_lines.append("\t".join(fields))

        else:
            updated_lines.append(line)

    if matches > 1:
        raise RuntimeError(
            "Plusieurs entrées crypttab correspondent au volume."
        )

    # Si aucune entrée n'existe, on la crée.
    if matches == 0:

        updated_lines.append(
            f"{volume_name} "
            f"UUID={luks_uuid} "
            f"{key_spec} "
            "discard,x-initrd.attach"
        )

    # Sauvegarde de l'ancien fichier.
    if not backup.exists():

        shutil.copy2(crypttab, backup)
        os.chmod(backup, 0o600)

    # Écriture temporaire et remplacement.
    temporary = Path("/etc/crypttab.tmp")

    try:

        with temporary.open("w", encoding="utf-8") as file:

            file.write("\n".join(updated_lines) + "\n")
            file.flush()
            os.fsync(file.fileno())

        os.chown(temporary, 0, 0)
        os.chmod(temporary, 0o644)

        temporary.replace(crypttab)

    finally:
        temporary.unlink(missing_ok=True)

    run_command([
        "restorecon", str(crypttab)
    ])

    logging.info(
        "Entrée crypttab mise à jour pour %s",
        volume_name
    )


# ============================================================
# CONFIGURATION DE LA CLÉ LUKS
# ============================================================

def configure_luks_keyfile():

    logging.info("Début de la configuration LUKS.")

    packages = [
        "cryptsetup",
        "dracut",
        "lvm2",
        "policycoreutils-python-utils",
        "checkpolicy",
        "setools-console",
        "make",
        "selinux-policy-devel"
    ]

    run_command(
        ["dnf", "install", "-y"] + packages,
        timeout=1800
    )

    boot_partition, boot_uuid, luks_partition, luks_uuid = (
        find_partition_pair()
    )

    logging.info("Partition /boot : %s", boot_partition)
    logging.info("UUID /boot : %s", boot_uuid)
    logging.info("Partition LUKS : %s", luks_partition)
    logging.info("UUID LUKS : %s", luks_uuid)

    # --------------------------------------------------------
    # SAUVEGARDE DE L'EN-TÊTE LUKS
    # --------------------------------------------------------

    backup = Path("/root/luks-header-backup.img")

    if not backup.exists():

        run_command([
            "cryptsetup",
            "luksHeaderBackup",
            luks_partition,
            "--header-backup-file",
            str(backup)
        ], timeout=300)

        os.chmod(backup, 0o600)
        os.chown(backup, 0, 0)

    else:
        logging.info(
            "Sauvegarde d'en-tête déjà présente : %s",
            backup
        )

    # --------------------------------------------------------
    # CRÉATION OU VÉRIFICATION DU KEYFILE LUKS
    # --------------------------------------------------------

    keyfile = Path("/boot/luks-keyfile.bin")

    if not keyfile.exists():

        run_command([
            "dd",
            "if=/dev/urandom",
            f"of={keyfile}",
            "bs=64",
            "count=1",
            "status=none"
        ], timeout=60)

        os.chown(keyfile, 0, 0)
        os.chmod(keyfile, 0o600)

        run_command(["restorecon", str(keyfile)])

        # Ajout de la clé au volume LUKS.
        # La passphrase actuelle sera demandée.
        run_command([
            "cryptsetup",
            "luksAddKey",
            luks_partition,
            str(keyfile)
        ], timeout=None, show_passphrase_prompt=True)

        logging.info("Keyfile créé et ajouté au volume LUKS.")

    else:

        if keyfile.is_symlink() or not keyfile.is_file():
            raise RuntimeError("Keyfile invalide.")

        os.chown(keyfile, 0, 0)
        os.chmod(keyfile, 0o600)

        run_command(["restorecon", str(keyfile)])

        logging.info("Keyfile existant détecté.")

    # --------------------------------------------------------
    # TEST DU KEYFILE
    # --------------------------------------------------------

    run_command([
        "cryptsetup",
        "open",
        "--test-passphrase",
        "--key-file",
        str(keyfile),
        luks_partition
    ], timeout=60)

    logging.info("Test du keyfile réussi.")


    # --------------------------------------------------------
    # CONFIGURATION CRYPTTAB
    # --------------------------------------------------------

    update_crypttab(luks_uuid, boot_uuid)

    # --------------------------------------------------------
    # POLITIQUE SELINUX LOCALE
    # --------------------------------------------------------

    te_file = Path(
        "/root/local-cryptsetup-generator-extra.te"
    )

    te_content = """module local-cryptsetup-generator-extra 1.1;

require {
    type systemd_cryptsetup_generator_t;
    type init_var_run_t;
    class dir { write add_name create };
}

allow systemd_cryptsetup_generator_t init_var_run_t:dir { write add_name create };
"""

    te_file.write_text(te_content, encoding="utf-8")
    os.chmod(te_file, 0o600)

    run_command([
        "make",
        "-C",
        "/root",
        "-f",
        "/usr/share/selinux/devel/Makefile",
        "local-cryptsetup-generator-extra.pp"
    ], timeout=300)

    run_command([
        "semodule",
        "-i",
        "/root/local-cryptsetup-generator-extra.pp"
    ], timeout=300)

    # --------------------------------------------------------
    # RÉGÉNÉRATION INITRAMFS
    # --------------------------------------------------------

    kernel = run_command([
        "uname", "-r"
    ], timeout=30)

    initramfs = f"/boot/initramfs-{kernel}.img"

    run_command([
        "dracut",
        "--regenerate-all",
        "--force"
    ], timeout=1800)

    if not Path(initramfs).is_file():
        raise RuntimeError(
            "L'initramfs n'a pas été créé."
        )

    if Path(initramfs).stat().st_size == 0:
        raise RuntimeError(
            "L'initramfs généré est vide."
        )

    logging.info("Initramfs régénéré : %s", initramfs)
    logging.info("Configuration LUKS terminée.")


# ============================================================
# ÉTAPE LUKS
# ============================================================

def luks_step():

    try:

        configure_luks_keyfile()

        log("Configuration LUKS terminée avec succès.")

        return True

    except Exception:

        logging.exception(
            "Échec de la configuration LUKS."
        )

        log("Échec de la configuration LUKS. Consulter script.log.", "error")

        return False



def main():
    require_root()
    print(f"Journal détaillé : {LOG_FILE}")
    log("=" * 70)
    log("Démarrage du hardening AlmaLinux.")
    log(f"Version Python: {sys.version}")
    log(f"Architecture système: {os.uname().machine}")

    if not Path("/etc/almalinux-release").exists():
        raise RuntimeError(
            "Ce script est prévu pour AlmaLinux; "
            "/etc/almalinux-release absent."
        )

    user, key = select_wheel_user()

    task(
        "Installation de la clé SSH de l'utilisateur sélectionné",
        lambda: install_authorized_key(user, key)
    )

    task("Mise à jour du système et nettoyage DNF", system_update)

    task(
        "Dépôts, utilitaires, Cockpit, fuseau horaire et chronyd",
        packages_and_base
    )

    # Pare-feu et port SELinux avant de modifier/relancer sshd.
    task(
        "Configuration du pare-feu pour le port SSH 49222",
        configure_firewall
    )

    task(
        "Déclaration du port SSH dans SELinux",
        set_selinux_ssh_port
    )

    task(
        "Configuration SSH : port 49222 et authentification par clé uniquement",
        lambda: enforce_ssh_key_only(user.pw_name)
    )

    task("Configuration de Fail2ban", configure_fail2ban)

    task(
        "Mises à jour de sécurité automatiques",
        configure_dnf_automatic
    )

    task(
        "Protection contre les tentatives de connexion (faillock)",
        configure_authselect
    )

    task("Paramètres sysctl de sécurité", configure_sysctl)

    task(
        "Désactivation des services et paquets inutiles",
        disable_services
    )

    task(
        "Sécurisation de /dev/shm dans fstab",
        harden_tmpfs
    )

    task(
        "Limitation des anciens noyaux conservés par DNF",
        configure_dnf_conf
    )

    # LUKS : si cette étape échoue, le hardening échoue également.
    if not luks_step():
        raise RuntimeError(
            "Hardening interrompu : échec de la configuration LUKS."
        )

    print()
    print("✅ Le hardening est terminé. Vous pouvez redémarrer la machine. 🎉")
    print(f"Journal détaillé : {LOG_FILE}")
    log("Le hardening est terminé. Vous pouvez redémarrer la machine.")



if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n❌ Interruption demandée.")
        log("Interruption utilisateur.", "error")
        sys.exit(130)
    except Exception as exc:
        print(f"\n❌ Arrêt : {exc}")
        print(f"Consulte le journal : {LOG_FILE}")
        log(f"ARRÊT GLOBAL: {exc}", "error")
        sys.exit(1)
