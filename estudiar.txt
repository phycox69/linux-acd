investigar 


/usr/lib/python3/dist-packages/yubico/yubikey_config.py:478: SyntaxWarning: "is" with 
'int' literal. Did you mean "=="?
  if slot is 1:
/usr/lib/python3/dist-packages/yubico/yubikey_config.py:483: SyntaxWarning: "is" with 
'int' literal. Did you mean "=="?
  elif slot is 2:
/usr/lib/python3/dist-packages/yubico/yubikey_usb_hid.py:288: SyntaxWarning: "is" with
 'str' literal. Did you mean "=="?
  if mode is 'nand':
/usr/lib/python3/dist-packages/yubico/yubikey_usb_hid.py:294: SyntaxWarning: "is" with
 'str' literal. Did you mean "=="?
  elif mode is 'and':
/usr/lib/python3/dist-packages/yubico/yubikey_usb_hid.py:306: SyntaxWarning: "is" with
 'str' literal. Did you mean "=="?
  if mode is 'nand':
Configurando libpath-utils1t64:amd64 (0.6.2-2.1build1) ...
Configurando python3-decorator (5.1.1-5) ...
Configurando python3-gssapi (1.8.2-1ubuntu1) ...
Configurando libaugeas0:amd64 (1.14.1-1build2) ...
Configurando wamerican (2020.12.07-2) ...
Configurando libimagequant0:amd64 (2.18.0-1build1) ...
Configurando libcares2:amd64 (1.27.0-1.0ubuntu1) ...
Configurando libdhash1t64:amd64 (0.6.2-2.1build1) ...
Configurando python3-typing-extensions (4.10.0-1) ...
Configurando python3-html5lib (1.1-6) ...
Configurando libcrack2:amd64 (2.9.6-5.1build2) ...
Configurando keyutils (1.6.3-3build1) ...
Configurando certmonger (0.79.19-1build4) ...
Created symlink /etc/systemd/system/multi-user.target.wants/certmonger.service → /usr/
lib/systemd/system/certmonger.service.
Configurando python3-lxml:amd64 (5.2.1-1) ...
Configurando python3-augeas (0.5.0-1.1) ...
Configurando liblua5.3-0:amd64 (5.3.6-2build2) ...
Configurando libopenjp2-7:amd64 (2.5.0-2ubuntu0.4) ...
Configurando python3-libipa-hbac (2.9.4-1.1ubuntu6.3) ...
Configurando libharfbuzz0b:amd64 (8.3.0-2build2) ...
Configurando libnss-sudo (1.9.15p5-3ubuntu5.24.04.1) ...
Configurando freeipa-common (4.11.1-2) ...
Configurando python3-cssselect (1.2.0-2) ...
Configurando libwebpmux3:amd64 (1.3.2-0.4build3) ...
Configurando libsss-nss-idmap0 (2.9.4-1.1ubuntu6.3) ...
Configurando libini-config5t64:amd64 (0.6.2-2.1build1) ...
Configurando libsasl2-modules-gssapi-mit:amd64 (2.1.28+dfsg1-5ubuntu3.1) ...
Configurando python3-soupsieve (2.5-1) ...
Configurando libnss3-tools (2:3.98-1build1) ...
Configurando libnss-sss:amd64 (2.9.4-1.1ubuntu6.3) ...
Configurando libsss-sudo (2.9.4-1.1ubuntu6.3) ...
Configurando chrony (4.5-1ubuntu4.2) ...

Creating config file /etc/chrony/chrony.conf with new version

Creating config file /etc/chrony/chrony.keys with new version
dpkg-statoverride: atención: se ha utilizado --update pero no existe /var/log/chrony
Created symlink /etc/systemd/system/chronyd.service → /usr/lib/systemd/system/chrony.s
ervice.
Created symlink /etc/systemd/system/multi-user.target.wants/chrony.service → /usr/lib/
systemd/system/chrony.service.
Configurando python3-cffi (1.16.0-2build1) ...
Configurando python3-bs4 (4.12.3-1) ...
Configurando cracklib-runtime (2.9.6-5.1build2) ...
Configurando libpwquality1:amd64 (1.4.5-3build1) ...
Configurando libraqm0:amd64 (0.10.1-1build1) ...
Configurando librpmio9t64 (4.18.2+dfsg-2.1build2) ...
Configurando librpm9t64 (4.18.2+dfsg-2.1build2) ...
Configurando libpam-pwquality:amd64 (1.4.5-3build1) ...
Configurando rpm-common (4.18.2+dfsg-2.1build2) ...
Configurando python3-pil:amd64 (10.2.0-1ubuntu1) ...
Configurando librpmsign9t64 (4.18.2+dfsg-2.1build2) ...
Configurando python3-qrcode (7.4.2-4) ...
update-alternatives: utilizando /usr/bin/python3-qr para proveer /usr/bin/qr (qr) en m
odo automático
Configurando libpam-sss:amd64 (2.9.4-1.1ubuntu6.3) ...
Configurando python3-ipalib (4.11.1-2) ...
Configurando sssd-common (2.9.4-1.1ubuntu6.3) ...
Creating SSSD system user & group...
warn: The home directory `/var/lib/sss' already exists.  Not touching this directory.
warn: Warning: The home directory `/var/lib/sss' does not belong to the user you are c
urrently creating.
Warning: found usr.sbin.sssd in /etc/apparmor.d/force-complain, forcing complain mode
Warning from /etc/apparmor.d/usr.sbin.sssd (/etc/apparmor.d/usr.sbin.sssd line 69): Ca
ching disabled for: 'usr.sbin.sssd' due to force complain
Created symlink /etc/systemd/system/sssd.service.wants/sssd-autofs.socket → /usr/lib/s
ystemd/system/sssd-autofs.socket.
Created symlink /etc/systemd/system/sssd.service.wants/sssd-nss.socket → /usr/lib/syst
emd/system/sssd-nss.socket.
Created symlink /etc/systemd/system/sssd.service.wants/sssd-pam-priv.socket → /usr/lib
/systemd/system/sssd-pam-priv.socket.
Created symlink /etc/systemd/system/sssd.service.wants/sssd-pam.socket → /usr/lib/syst
emd/system/sssd-pam.socket.
Created symlink /etc/systemd/system/sssd.service.wants/sssd-ssh.socket → /usr/lib/syst
emd/system/sssd-ssh.socket.
Created symlink /etc/systemd/system/sssd.service.wants/sssd-sudo.socket → /usr/lib/sys
temd/system/sssd-sudo.socket.
Created symlink /etc/systemd/system/multi-user.target.wants/sssd.service → /usr/lib/sy
stemd/system/sssd.service.
sssd-autofs.service is a disabled or a static unit, not starting it.
sssd-nss.service is a disabled or a static unit, not starting it.
sssd-pam.service is a disabled or a static unit, not starting it.
sssd-ssh.service is a disabled or a static unit, not starting it.
sssd-sudo.service is a disabled or a static unit, not starting it.
Could not execute systemctl:  at /usr/bin/deb-systemd-invoke line 148.
Configurando sssd-proxy (2.9.4-1.1ubuntu6.3) ...
Configurando sssd-ad-common (2.9.4-1.1ubuntu6.3) ...
Created symlink /etc/systemd/system/sssd.service.wants/sssd-pac.socket → /usr/lib/syst
emd/system/sssd-pac.socket.
sssd-pac.service is a disabled or a static unit, not starting it.
Could not execute systemctl:  at /usr/bin/deb-systemd-invoke line 148.
Configurando sssd-krb5-common (2.9.4-1.1ubuntu6.3) ...
Configurando python3-ipaclient (4.11.1-2) ...
Configurando sssd-krb5 (2.9.4-1.1ubuntu6.3) ...
Configurando sssd-ldap (2.9.4-1.1ubuntu6.3) ...
Configurando sssd-ad (2.9.4-1.1ubuntu6.3) ...
Configurando sssd-ipa (2.9.4-1.1ubuntu6.3) ...
Configurando sssd (2.9.4-1.1ubuntu6.3) ...
Configurando freeipa-client (4.11.1-2) ...
Configurando libverto1t64:amd64 (0.3.1-1.2ubuntu3) ...
Configurando libkrad0:amd64 (1.20.1-6ubuntu2.6) ...
Configurando libverto-libevent1t64:amd64 (0.3.1-1.2ubuntu3) ...
Configurando sssd-passkey (2.9.4-1.1ubuntu6.3) ...
Procesando disparadores para dbus (1.14.10-4ubuntu4.1) ...
Procesando disparadores para libc-bin (2.39-0ubuntu8.6) ...
Procesando disparadores para man-db (2.12.0-4build2) ...
Procesando disparadores para oddjob (0.34.7-2) ...
Scanning processes...                                                                 
Scanning linux images...                                                              

Running kernel seems to be up-to-date.

No services need to be restarted.

No containers need to be restarted.

No user sessions are running outdated binaries.

No VM guests are running outdated hypervisor (qemu) binaries on this host.
E: Fallo al obtener http://es.archive.ubuntu.com/ubuntu/pool/main/o/openldap/libldap2_2.6.7%2bdfsg-1%7eexp1ubuntu8.2_amd64.deb  404  Not Found [IP: 91.189.92.24 80]
E: Fallo al obtener http://es.archive.ubuntu.com/ubuntu/pool/main/o/openldap/ldap-utils_2.6.7%2bdfsg-1%7eexp1ubuntu8.2_amd64.deb  404  Not Found [IP: 91.189.92.24 80]
E: Fallo al obtener http://es.archive.ubuntu.com/ubuntu/pool/main/o/openldap/libldap-common_2.6.7%2bdfsg-1%7eexp1ubuntu8.2_all.deb  404  Not Found [IP: 91.189.92.24 80]
pau@ls01:~$ sudo apt install freeipa-client
Leyendo lista de paquetes... Hecho
Creando árbol de dependencias... Hecho
Leyendo la información de estado... Hecho
freeipa-client ya está en su versión más reciente (4.11.1-2).
0 actualizados, 0 nuevos se instalarán, 0 para eliminar y 134 no actualizados.
pau@ls01:~$ sudo nano /etc/resolv.conf 
pau@ls01:~$ ipa trust-add --type=ad lab02.lan --admin Administrator --password
IPA client is not configured on this system
pau@ls01:~$ sudo samba-tool domain trust create lab02.lan \
  --type=forest \
  --direction=both \
  -U administrator@lab02.lan
WARNING: Using passwords on command line is insecure. Installing the setproctitle python module will hide these from shortly after program start.
LocalDomain Netbios[LAB01] DNS[lab01.local] SID[S-1-5-21-2095897496-1640123670-162631286]
ERROR: Failed to find a writeable DC for domain 'lab02.lan': The object name is not found.
pau@ls01:~$ sudo systemctl reload samba-ad-dc
pau@ls01:~$ host -t A ls02.lab02.lan
host -t SRV _ldap._tcp.lab06.lan
Host ls02.lab02.lan not found: 3(NXDOMAIN)
_ldap._tcp.lab06.lan has no SRV record
pau@ls01:~$ host -t A ls02.lab02.lan
Host ls02.lab02.lan not found: 3(NXDOMAIN)
pau@ls01:~$ ipa dnsforwardzone-add lab02.lan --forwarder=172.30.20.26 --forward-policy=only
IPA client is not configured on this system
pau@ls01:~$ srv-host=_kerberos._tcp.lab02.lan,ls02.lab02.lan,88
srv-host=_kerberos._tcp.lab02.lan,ls02.lab02.lan,88: command not found
pau@ls01:~$ host -t SRV _ldap._tcp.lab06.lan
_ldap._tcp.lab06.lan has no SRV record
pau@ls01:~$ host -t SRV _ldap._tcp.lab02.lan
Host _ldap._tcp.lab02.lan not found: 3(NXDOMAIN)
pau@ls01:~$ host -t A ls02.lab02.lan
Host ls02.lab02.lan not found: 3(NXDOMAIN)
pau@ls01:~$ sudo nano /etc/krb5.conf
pau@ls01:~$ getent hosts ls02.lab02.lan
172.30.20.26    lab02.lan ls02.lab02.lan
pau@ls01:~$ service samba-ad-dc restart
==== AUTHENTICATING FOR org.freedesktop.systemd1.manage-units ====
Authentication is required to restart 'samba-ad-dc.service'.
Authenticating as: pau
Password: 
polkit-agent-helper-1: pam_authenticate failed: Authentication failure
==== AUTHENTICATION FAILED ====
Failed to restart samba-ad-dc.service: Access denied
See system logs and 'systemctl status samba-ad-dc.service' for details.
pau@ls01:~$ service samba-ad-dc statu
swUsage: /etc/init.d/samba-ad-dc {start|stop|restart|force-reload|status}
pau@ls01:~$ service samba-ad-dc status
● samba-ad-dc.service - Samba AD Daemon
     Loaded: loaded (/usr/lib/systemd/system/samba-ad-dc.service; enabled; preset: en>
     Active: active (running) since Fri 2026-02-20 09:47:46 UTC; 1h 41min ago
       Docs: man:samba(8)
             man:samba(7)
             man:smb.conf(5)
    Process: 5014 ExecReload=/bin/kill -HUP $MAINPID (code=exited, status=0/SUCCESS)
   Main PID: 2200 (samba)
     Status: "samba: ready to serve connections..."
      Tasks: 59 (limit: 4605)
     Memory: 187.7M (peak: 284.1M)
        CPU: 34.365s
     CGroup: /system.slice/samba-ad-dc.service
             ├─2200 "samba: root process"
             ├─2201 "samba: tfork waiter process(2202)"
             ├─2202 "samba: task[s3fs] pre-fork master"
             ├─2203 "samba: tfork waiter process(2205)"
             ├─2204 "samba: tfork waiter process(2206)"
             ├─2205 "samba: task[rpc] pre-fork master"
             ├─2206 /usr/sbin/smbd -D "--option=server role check:inhibit=yes" --fore>
             ├─2207 "samba: tfork waiter process(2208)"
             ├─2208 "samba: task[nbt] pre-fork master"
             ├─2209 "samba: tfork waiter process(2211)"
             ├─2210 "samba: tfork waiter process(2212)"
             ├─2211 "samba: task[rpc] pre-forked worker(0)"
             ├─2212 "samba: task[wrepl] pre-fork master"
             ├─2213 "samba: tfork waiter process(2214)"
             ├─2214 "samba: task[rpc] pre-forked worker(1)"
             ├─2215 "samba: tfork waiter process(2216)"
             ├─2216 "samba: task[ldap] pre-fork master"
             ├─2217 "samba: tfork waiter process(2219)"
             ├─2218 "samba: tfork waiter process(2221)"
             ├─2219 "samba: task[rpc] pre-forked worker(2)"
             ├─2220 "samba: tfork waiter process(2222)"
             ├─2221 "samba: task[cldap] pre-fork master"
             ├─2222 "samba: task[rpc] pre-forked worker(3)"
             ├─2223 "samba: tfork waiter process(2224)"
             ├─2224 "samba: task[kdc] pre-fork master"
             ├─2225 "samba: tfork waiter process(2227)"
             ├─2226 "samba: tfork waiter process(2228)"
             ├─2227 "samba: task[drepl] pre-fork master"
             ├─2228 "samba: task[kdc] pre-forked worker(0)"
             ├─2229 "samba: tfork waiter process(2232)"
             ├─2230 "samba: tfork waiter process(2231)"
             ├─2231 "samba: task[kdc] pre-forked worker(1)"
             ├─2232 "samba: task[winbindd] pre-fork master"
             ├─2233 "samba: tfork waiter process(2239)"
             ├─2234 "samba: tfork waiter process(2236)"
             ├─2235 "samba: tfork waiter process(2237)"
             ├─2236 "samba: task[kdc] pre-forked worker(2)"
             ├─2237 /usr/sbin/winbindd -D "--option=server role check:inhibit=yes" -->
             ├─2238 "samba: tfork waiter process(2241)"
             ├─2239 "samba: task[ntp_signd] pre-fork master"
             ├─2241 "samba: task[kdc] pre-forked worker(3)"
             ├─2242 "samba: tfork waiter process(2243)"
             ├─2243 "samba: task[kcc] pre-fork master"
             ├─2244 "samba: tfork waiter process(2245)"
             ├─2245 "samba: task[dnsupdate] pre-fork master"
             ├─2246 "samba: tfork waiter process(2248)"
             ├─2248 "samba: task[dns] pre-fork master"
             ├─2253 "smbd: notifyd" .
             ├─2254 "smbd: cleanupd "
             ├─2255 "winbindd: domain child [LAB01]"
             ├─2256 "samba: tfork waiter process(2257)"
             ├─2257 "samba: task[ldap] pre-forked worker(0)"
             ├─2258 "samba: tfork waiter process(2259)"
             ├─2259 "samba: task[ldap] pre-forked worker(1)"
             ├─2260 "samba: tfork waiter process(2261)"
             ├─2261 "samba: task[ldap] pre-forked worker(2)"
             ├─2262 "samba: tfork waiter process(2263)"
             ├─2263 "samba: task[ldap] pre-forked worker(3)"
             └─4106 "winbindd: idmap child"
pau@ls01:~$ sudo samba-tool domain trust create lab02.lan --type external --direction=both -U administrator@lab02.lan
[sudo] password for pau: 
Sorry, try again.
[sudo] password for pau: 
WARNING: Using passwords on command line is insecure. Installing the setproctitle python module will hide these from shortly after program start.
LocalDomain Netbios[LAB01] DNS[lab01.local] SID[S-1-5-21-2095897496-1640123670-162631286]
ERROR: Failed to find a writeable DC for domain 'lab02.lan': The object name is not found.
pau@ls01:~$ sudo samba-tool domain trust create lab02.lan --type external --direction=both -U administrator@lab02.lan
WARNING: Using passwords on command line is insecure. Installing the setproctitle python module will hide these from shortly after program start.
LocalDomain Netbios[LAB01] DNS[lab01.local] SID[S-1-5-21-2095897496-1640123670-162631286]
ERROR: Failed to find a writeable DC for domain 'lab02.lan': The object name is not found.
pau@ls01:~$ samba-tool domain level show
ltdb: tdb(/var/lib/samba/private/sam.ldb): tdb_open_ex: could not open file /var/lib/samba/private/sam.ldb: Permission denied

Unable to open tdb '/var/lib/samba/private/sam.ldb': Permission denied
Failed to connect to 'tdb:///var/lib/samba/private/sam.ldb' with backend 'tdb': Unable to open tdb '/var/lib/samba/private/sam.ldb': Permission denied
ERROR(ldb): uncaught exception - Unable to open tdb '/var/lib/samba/private/sam.ldb': Permission denied
pau@ls01:~$ sudo samba-tool domain level show
Domain and forest function level for domain 'DC=lab01,DC=local'

Forest function level: (Windows) 2008 R2
Domain function level: (Windows) 2008 R2
Lowest function level of a DC: (Windows) 2008 R2
pau@ls01:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:b3:ce:9b brd ff:ff:ff:ff:ff:ff
    inet 172.30.20.94/25 metric 100 brd 172.30.20.127 scope global dynamic enp0s3
       valid_lft 4983sec preferred_lft 4983sec
    inet6 fe80::a00:27ff:feb3:ce9b/64 scope link 
       valid_lft forever preferred_lft forever
3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:7e:e2:dc brd ff:ff:ff:ff:ff:ff
    inet 192.168.10.10/24 brd 192.168.10.255 scope global enp0s8
       valid_lft forever preferred_lft forever
    inet6 fe80::a00:27ff:fe7e:e2dc/64 scope link 
       valid_lft forever preferred_lft forever
pau@ls01:~$ realm discover lab02.lan
lab02.lan
  type: kerberos
  realm-name: LAB02.LAN
  domain-name: lab02.lan
  configured: no
  server-software: active-directory
  client-software: sssd
  required-package: sssd-tools
  required-package: sssd
  required-package: libnss-sss
  required-package: libpam-sss
  required-package: adcli
  required-package: samba-common-bin
pau@ls01:~$ sudo samba-tool domain trust create lab02.lan --type external --direction=both -U administrator@lab02.lan
WARNING: Using passwords on command line is insecure. Installing the setproctitle python module will hide these from shortly after program start.
LocalDomain Netbios[LAB01] DNS[lab01.local] SID[S-1-5-21-2095897496-1640123670-162631286]
ERROR: Failed to find a writeable DC for domain 'lab02.lan': The object name is not found.
pau@ls01:~$ sudo samba-tool domain trust create lab02.lan --type external --direction=both -U Administrator
WARNING: Using passwords on command line is insecure. Installing the setproctitle python module will hide these from shortly after program start.
LocalDomain Netbios[LAB01] DNS[lab01.local] SID[S-1-5-21-2095897496-1640123670-162631286]
ERROR: Failed to find a writeable DC for domain 'lab02.lan': The object name is not found.
pau@ls01:~$ sudo samba-tool domain trust create lab02.lan --type external --direction=both -U Administrator --password=admin_21
WARNING: Using passwords on command line is insecure. Installing the setproctitle python module will hide these from shortly after program start.
LocalDomain Netbios[LAB01] DNS[lab01.local] SID[S-1-5-21-2095897496-1640123670-162631286]
ERROR: Failed to find a writeable DC for domain 'lab02.lan': The object name is not found.
pau@ls01:~$ sudo samba-tool domain trust create LAB02.LAN --type external --direction=both -U Administrator --password=admin_21
WARNING: Using passwords on command line is insecure. Installing the setproctitle python module will hide these from shortly after program start.
LocalDomain Netbios[LAB01] DNS[lab01.local] SID[S-1-5-21-2095897496-1640123670-162631286]
ERROR: Failed to find a writeable DC for domain 'LAB02.LAN': The object name is not found.
pau@ls01:~$ service samba-ad-dc 
Usage: /etc/init.d/samba-ad-dc {start|stop|restart|force-reload|status}
pau@ls01:~$ service samba-ad-dc restart
==== AUTHENTICATING FOR org.freedesktop.systemd1.manage-units ====
Authentication is required to restart 'samba-ad-dc.service'.
Authenticating as: pau
Password: 
==== AUTHENTICATION COMPLETE ====
pau@ls01:~$ sudo samba-tool domain trust create lab02.lan --type external --direction=both -U Administrator --password=admin_21
WARNING: Using passwords on command line is insecure. Installing the setproctitle python module will hide these from shortly after program start.
LocalDomain Netbios[LAB01] DNS[lab01.local] SID[S-1-5-21-2095897496-1640123670-162631286]
RemoteDC Netbios[LS02] DNS[ls02.lab02.lan] ServerType[PDC,GC,LDAP,DS,KDC,TIMESERV,CLOSEST,WRITABLE,GOOD_TIMESERV,FULL_SECRET_DOMAIN_6]
ERROR: REMOTE_DC[ls02.lab02.lan]: failed to connect lsa server - ERROR(0xC000006D) - The attempted logon is invalid. This is either due to a bad username or authentication information.
pau@ls01:~$ sudo samba-tool domain trust create lab02.lan --type external --direction=both -U Administrator@lab02.lan --password=admin_21
WARNING: Using passwords on command line is insecure. Installing the setproctitle python module will hide these from shortly after program start.
LocalDomain Netbios[LAB01] DNS[lab01.local] SID[S-1-5-21-2095897496-1640123670-162631286]
RemoteDC Netbios[LS02] DNS[ls02.lab02.lan] ServerType[PDC,GC,LDAP,DS,KDC,TIMESERV,CLOSEST,WRITABLE,GOOD_TIMESERV,FULL_SECRET_DOMAIN_6]
RemoteDomain Netbios[LAB02] DNS[lab02.lan] SID[S-1-5-21-1847597971-1021502290-426557704]
Creating remote TDO.
Remote TDO created.
Setting supported encryption types on remote TDO.
Creating local TDO.
Local TDO created
Setting supported encryption types on local TDO.
Validating outgoing trust...
OK: LocalValidation: DC[\\ls02.lab02.lan] CONNECTION[WERR_OK] TRUST[WERR_OK] VERIFY_STATUS_RETURNED
Validating incoming trust...
OK: RemoteValidation: DC[\\ls01.lab01.local] CONNECTION[WERR_OK] TRUST[WERR_OK] VERIFY_STATUS_RETURNED
Success.
pau@ls01:~$ sudo samba-tool domain trust list
Type[External] Transitive[No]  Direction[BOTH]     Name[lab02.lan]
pau@ls01:~$ cat /etc/resolv.conf 
nameserver 127.0.0.1
nameserver 172.30.20.94
search lab01.local lab02.lan
pau@ls01:~$ cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 ls01.lab01.local ls01
192.168.10.10 ls01.lab01.local ls01
172.30.20.26  lab02.lan ls02.lab02.lan
pau@ls01:~$ sudo samba-tool domain trust create lab02.lan --type external --direction=both -U administrator@lab02.lan
WARNING: Using passwords on command line is insecure. Installing the setproctitle python module will hide these from shortly after program start.
LocalDomain Netbios[LAB01] DNS[lab01.local] SID[S-1-5-21-2095897496-1640123670-162631286]
^C
pau@ls01:~$ cat /etc/resolv.conf 
nameserver 127.0.0.1
nameserver 172.30.20.94
search lab01.local lab02.lan
pau@ls01:~$ 
pau@ls01:~$ cat /etc/samba/
gdbcommands   smb.conf      smb.conf.bak  tls/          
pau@ls01:~$ cat /etc/samba/smb.conf
# Global parameters
[global]
	interfaces = lo enp0s3
    	bind interfaces only = yes
    	dns forwarder = 172.30.20.26
	netbios name = LS01
	realm = LAB01.LOCAL
	server role = active directory domain controller
	workgroup = LAB01
	idmap_ldb:use rfc2307 = yes

[sysvol]
	path = /var/lib/samba/sysvol
	read only = No

[netlogon]
	path = /var/lib/samba/sysvol/lab01.local/scripts
	read only = No

[FinanceDocs]
    path = /srv/samba/FinanceDocs
    read only = no
    guest ok = no

[HRDocs]
    path = /srv/samba/HRDocs
    read only = no
    guest ok = no

[Public]
    path = /srv/samba/Public
    read only = yes
    guest ok = yes
pau@ls01:~$ cat /etc/resolv.conf 
nameserver 127.0.0.1
nameserver 172.30.20.94
search lab01.local lab02.lan
pau@ls01:~$ nano /etc/k
kernel/        keyutils/      krb5.conf      krb5.conf.bak  krb5.conf.d/
pau@ls01:~$ nano /etc/krb5.conf
pau@ls01:~$ nano /etc/resolv.conf 
pau@ls01:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:b3:ce:9b brd ff:ff:ff:ff:ff:ff
    inet 172.30.20.94/25 metric 100 brd 172.30.20.127 scope global dynamic enp0s3
       valid_lft 7082sec preferred_lft 7082sec
    inet6 fe80::a00:27ff:feb3:ce9b/64 scope link 
       valid_lft forever preferred_lft forever
3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:7e:e2:dc brd ff:ff:ff:ff:ff:ff
    inet 192.168.10.10/24 brd 192.168.10.255 scope global enp0s8
       valid_lft forever preferred_lft forever
    inet6 fe80::a00:27ff:fe7e:e2dc/64 scope link 
       valid_lft forever preferred_lft forever
pau@ls01:~$ 
