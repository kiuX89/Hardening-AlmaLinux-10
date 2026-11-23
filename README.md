# AlmaLinux-Hardening

[Français](#français) | [English](#english)

---

# Français

## Présentation

**AlmaLinux-Hardening** est un outil de durcissement destiné exclusivement aux systèmes **AlmaLinux**. Il automatise plusieurs opérations de configuration système, réseau et sécurité afin de renforcer la configuration d'un serveur.

Le programme vérifie la présence de `/etc/almalinux-release` et s'arrête si le système n'est pas identifié comme AlmaLinux.

> **Attention :** ce programme modifie des paramètres sensibles du système, du pare-feu, de SSH, de PAM, de SELinux et du chiffrement LUKS. Il est destiné à des administrateurs qui comprennent les conséquences de ces changements. Ne l'exécutez pas sur un serveur de production sans sauvegarde, accès console ou procédure de récupération et test préalable.

## Fonctionnalités

### Système et paquets
- Actualisation des métadonnées DNF, mise à jour du système et nettoyage des paquets inutiles.
- Installation d'outils et de services de base : EPEL, `vim`, `git`, `wget`, `curl`, `tar`, outils SELinux, `chrony`, `firewalld` et serveur OpenSSH.
- Suppression de composants Cockpit.
- Configuration du fuseau horaire sur `Europe/Paris` et activation de `chronyd`.
- Limitation du nombre de noyaux conservés par DNF à deux.

### SSH et pare-feu
- Sélection interactive d'un utilisateur humain membre du groupe `wheel`.
- Demande et installation d'une clé publique SSH pour cet utilisateur.
- Configuration de SSH sur le port **49222/TCP**.
- Désactivation de la connexion SSH root et de l'authentification par mot de passe ; authentification par clé publique uniquement.
- Autorisation SSH limitée à l'utilisateur sélectionné.
- Activation de `firewalld`, ouverture du port TCP 49222 et définition de la cible du pare-feu à `DROP`.
- Déclaration du port 49222 dans la politique SELinux.

### Protection contre les tentatives d'accès
- Installation et configuration de Fail2ban, avec les prisons `sshd` et `recidive`.
- Activation de `faillock` via `authselect` : seuil de cinq échecs et verrouillage de 900 secondes, y compris pour root.

### Noyau et services
- Déploiement de paramètres `sysctl` pour renforcer les protections réseau, mémoire et noyau.
- Désactivation et masquage de plusieurs services considérés comme non nécessaires par le script.
- Configuration de `/dev/shm` avec les options `nosuid`, `nodev` et `noexec`.

### Mises à jour automatiques
- Installation de `dnf-automatic`.
- Configuration des mises à jour de sécurité et de leur application automatique.
- Configuration d'un redémarrage lorsque nécessaire et d'une exécution quotidienne à **03:30**.

### Chiffrement LUKS
Le script comprend une étape de configuration LUKS qui :
- détecte la partition `/boot` et la partition LUKS située immédiatement après celle-ci sur le même disque ;
- sauvegarde l'en-tête LUKS dans `/root/luks-header-backup.img` si cette sauvegarde n'existe pas déjà ;
- crée `/boot/luks-keyfile.bin` si le fichier n'existe pas, puis demande la phrase secrète actuelle pour ajouter ce fichier comme clé LUKS ;
- teste le fichier de clé, met à jour `/etc/crypttab`, installe une règle SELinux locale et régénère les images initramfs.

**Point de sécurité majeur :** le fichier de clé LUKS est placé dans `/boot`. Cette partition n'est généralement pas chiffrée lorsque le système utilise un chiffrement LUKS classique. Cela peut réduire fortement la protection apportée par le chiffrement du volume. Évaluez ce choix selon votre modèle de menace avant d'utiliser cette fonction. Conservez également une sauvegarde indépendante et sécurisée de l'en-tête LUKS et assurez-vous de disposer d'une méthode de récupération.

## Prérequis

- Un système AlmaLinux.
- Un accès administrateur `root` (ou la possibilité d'utiliser `sudo`).
- Un accès réseau aux dépôts configurés pour installer et mettre à jour les paquets.
- Un compte utilisateur administrateur membre de `wheel`.
- Une clé publique SSH valide.
- Pour l'étape LUKS : une installation avec une partition `/boot` classique et une partition LUKS répondant à la disposition attendue par le script.

Le script utilise notamment `dnf`, `systemctl`, `firewalld`, `SELinux`, `OpenSSH`, `Fail2ban`, `authselect`, `cryptsetup` et `dracut`.

## Téléchargement et installation

Téléchargez l'archive correspondant à votre architecture depuis la page **Releases** du dépôt GitHub.

Exemple avec l'archive Linux :

```bash
tar -xzf AlmaLinux-Hardening-vX.Y.Z-linux.tar.gz
cd AlmaLinux-Hardening-vX.Y.Z
```

Choisissez le binaire correspondant à l'architecture de la machine :

```bash
uname -m
```

- `x86_64` : `AlmaLinux-Hardening-linux-x86_64`
- `aarch64` : `AlmaLinux-Hardening-linux-arm64`

Rendez le fichier exécutable si nécessaire :

```bash
chmod +x AlmaLinux-Hardening-linux-x86_64
# ou :
chmod +x AlmaLinux-Hardening-linux-arm64
```

## Exécution

L'exécution nécessite les privilèges root :

```bash
sudo ./AlmaLinux-Hardening-linux-x86_64
```

Sur une machine ARM64 :

```bash
sudo ./AlmaLinux-Hardening-linux-arm64
```

Le programme demande de sélectionner l'utilisateur SSH parmi les comptes humains membres de `wheel`, puis de coller sa **clé publique SSH** sur une seule ligne.

Avant de lancer le programme, vérifiez que :
1. la clé publique correspond bien à la clé privée dont vous disposez ;
2. le port TCP **49222** est autorisé dans les règles réseau amont (cloud, hyperviseur, routeur ou pare-feu externe) ;
3. vous avez un accès console ou une autre méthode de récupération ;
4. vous avez sauvegardé les données et les configurations importantes.

Après le changement de port SSH, reconnectez-vous en utilisant le port 49222 et la clé configurée, par exemple :

```bash
ssh -p 49222 utilisateur@adresse_du_serveur
```

Ne fermez pas votre session SSH actuelle avant d'avoir vérifié qu'une nouvelle connexion fonctionne.

## Journalisation et comportement

- Le journal détaillé est écrit dans `script.log`, dans le même répertoire que le programme.
- Les commandes exécutées et leurs sorties sont consignées dans ce journal.
- Les étapes principales affichent un indicateur de réussite ou d'échec dans le terminal.
- Le programme s'exécute une seule fois : il ne propose pas de mode `--resume` ni de service de reprise.
- Une erreur dans une étape obligatoire interrompt l'exécution. L'étape LUKS est également bloquante pour la réussite globale.

## Compatibilité et limites

Le programme est conçu pour AlmaLinux et utilise des outils propres à l'écosystème RHEL. Les binaires publiés séparément pour `x86_64` et `aarch64` doivent être utilisés sur l'architecture correspondante.

La compatibilité exacte avec chaque version d'AlmaLinux doit être validée par des tests sur des machines de test. La disposition des partitions, les versions des paquets, les politiques SELinux et la configuration initiale peuvent influencer le résultat, en particulier pour l'étape LUKS.

## Avertissements importants

- **Risque de perte d'accès SSH :** le port SSH est remplacé, l'accès root et les mots de passe sont désactivés, et seul l'utilisateur choisi est autorisé.
- **Risque de blocage réseau :** la cible du pare-feu est réglée sur `DROP`. Vérifiez les règles nécessaires à vos services avant l'exécution.
- **Risque lié à PAM :** `faillock` peut verrouiller des comptes après plusieurs échecs d'authentification.
- **Redémarrages automatiques :** `dnf-automatic` est configuré pour redémarrer lorsque cela est nécessaire.
- **Risque lié au chiffrement :** la configuration LUKS modifie `/etc/crypttab`, ajoute un fichier de clé et régénère initramfs. Une erreur de configuration peut empêcher le démarrage ou le déverrouillage du volume.
- **Pas de garantie de conformité :** cet outil ne garantit pas à lui seul la conformité à un référentiel ou une norme de sécurité.

Utilisez-le d'abord sur une machine de test et adaptez les paramètres à votre environnement.

---

# English

## Overview

**AlmaLinux-Hardening** is a system-hardening tool designed exclusively for **AlmaLinux**. It automates several system, network and security configuration tasks to strengthen a server's configuration.

The program checks for `/etc/almalinux-release` and exits if the system is not identified as AlmaLinux.

> **Warning:** this program changes sensitive system, firewall, SSH, PAM, SELinux and LUKS settings. It is intended for administrators who understand the consequences of these changes. Do not run it on a production server without backups, console access or a recovery procedure, and prior testing.

## Features

### System and packages
- Refreshes DNF metadata, updates the system and removes unnecessary packages.
- Installs EPEL and base tools/services, including `vim`, `git`, `wget`, `curl`, `tar`, SELinux utilities, `chrony`, `firewalld` and OpenSSH server.
- Removes Cockpit components.
- Sets the timezone to `Europe/Paris` and enables `chronyd`.
- Limits the number of kernels retained by DNF to two.

### SSH and firewall
- Interactively selects a human user who belongs to the `wheel` group.
- Requests and installs that user's SSH public key.
- Configures SSH to listen on **TCP port 49222**.
- Disables root SSH login and password authentication; public-key authentication only.
- Restricts SSH access to the selected user.
- Enables `firewalld`, opens TCP port 49222 and sets the firewall default target to `DROP`.
- Adds port 49222 to the SELinux SSH port policy.

### Login protection
- Installs and configures Fail2ban with the `sshd` and `recidive` jails.
- Enables `faillock` through `authselect`: five failed attempts and a 900-second lockout, including for root.

### Kernel and services
- Applies `sysctl` settings to strengthen network, memory and kernel protections.
- Disables and masks several services the script considers unnecessary.
- Configures `/dev/shm` with the `nosuid`, `nodev` and `noexec` mount options.

### Automatic updates
- Installs `dnf-automatic`.
- Configures automatic security updates and their application.
- Allows a reboot when required and schedules the timer to run daily at **03:30**.

### LUKS encryption
The script includes a LUKS configuration step that:
- detects the `/boot` partition and the LUKS partition immediately following it on the same disk;
- backs up the LUKS header to `/root/luks-header-backup.img` if that backup does not already exist;
- creates `/boot/luks-keyfile.bin` if it does not exist, then prompts for the current passphrase to add the file as a LUKS key;
- tests the keyfile, updates `/etc/crypttab`, installs a local SELinux rule and regenerates initramfs images.

**Major security consideration:** the LUKS keyfile is stored in `/boot`. This partition is usually unencrypted when a system uses conventional LUKS volume encryption. This can substantially weaken the protection provided by encrypting the volume. Assess this design against your threat model before using this feature. Keep an independent, secure backup of the LUKS header and ensure that you have a recovery method.

## Requirements

- An AlmaLinux system.
- Root access (or the ability to use `sudo`).
- Network access to the configured repositories to install and update packages.
- An administrator account that belongs to `wheel`.
- A valid SSH public key.
- For the LUKS step: a system with a conventional `/boot` partition and a LUKS partition laid out as expected by the script.

The script uses tools including `dnf`, `systemctl`, `firewalld`, `SELinux`, `OpenSSH`, `Fail2ban`, `authselect`, `cryptsetup` and `dracut`.

## Download and installation

Download the archive matching your architecture from the repository's GitHub **Releases** page.

Example using the Linux archive:

```bash
tar -xzf AlmaLinux-Hardening-vX.Y.Z-linux.tar.gz
cd AlmaLinux-Hardening-vX.Y.Z
```

Check the machine architecture:

```bash
uname -m
```

- `x86_64`: `AlmaLinux-Hardening-linux-x86_64`
- `aarch64`: `AlmaLinux-Hardening-linux-arm64`

Make the selected binary executable if needed:

```bash
chmod +x AlmaLinux-Hardening-linux-x86_64
# or:
chmod +x AlmaLinux-Hardening-linux-arm64
```

## Running

Root privileges are required:

```bash
sudo ./AlmaLinux-Hardening-linux-x86_64
```

On an ARM64 machine:

```bash
sudo ./AlmaLinux-Hardening-linux-arm64
```

The program asks you to select the SSH user from the human accounts in `wheel`, then paste that user's **SSH public key** on a single line.

Before running the program, make sure that:
1. the public key matches a private key you control;
2. TCP port **49222** is allowed by upstream network rules (cloud security group, hypervisor, router or external firewall);
3. you have console access or another recovery method;
4. important data and configuration files are backed up.

After the SSH port changes, reconnect using port 49222 and the configured key, for example:

```bash
ssh -p 49222 username@server_address
```

Do not close your current SSH session until you have confirmed that a new connection works.

## Logging and execution behavior

- Detailed logs are written to `script.log` in the same directory as the program.
- Executed commands and their output are recorded in this log.
- Main steps display a success or failure indicator in the terminal.
- The program runs once; it does not provide a `--resume` mode or a recovery service.
- A failure in a required step stops execution. The LUKS step is also required for overall success.

## Compatibility and limitations

The program is designed for AlmaLinux and uses tools from the RHEL ecosystem. Separate binaries for `x86_64` and `aarch64` must be run on the matching CPU architecture.

Exact compatibility with each AlmaLinux release must be validated through testing on test machines. Partition layout, package versions, SELinux policies and the initial system configuration may affect the result, particularly for the LUKS step.

## Important warnings

- **SSH lockout risk:** the SSH port is changed, root login and password authentication are disabled, and only the selected user is allowed.
- **Network lockout risk:** the firewall target is set to `DROP`. Check the rules required by your services before running the tool.
- **PAM lockout risk:** `faillock` can lock accounts after repeated authentication failures.
- **Automatic reboots:** `dnf-automatic` is configured to reboot when required.
- **Encryption risk:** the LUKS configuration changes `/etc/crypttab`, adds a keyfile and regenerates initramfs. A configuration error may prevent the system from booting or unlocking the volume.
- **No compliance guarantee:** this tool alone does not guarantee compliance with any security benchmark or standard.

Test it on a non-production machine first and adapt the settings to your environment.
