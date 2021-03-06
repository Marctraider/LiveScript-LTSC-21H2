# Windows 10 LTSC 21H2 Custom Post-install configuration script.

## Disclaimer: 

Needs third party tools for correct function: PsExec.exe, PsExec64.exe, SetACL.exe, SetTimerResolutionService.exe, psshutdown.exe

Goal of script: Clean and usable (Compromise) Windows 10 LTSC installation while easily deployed on multiple target platforms without going through the hassle of configuring entire systems by hand, without making system unusable.
Only use if you have actual experience with windows and know how to minimize risks in an online environment. Just some highlights:

###### Performance:

- Disable DEP for 32-bit processes. (64-bit processes are forced)
- Tweaked SysMain (SuperFetch) and memory management
- Disable Windows Defender
- Disable multitude of (unneeded) services and components.
- Disable load of task scheduler tasks (Except critical)
- Disable mitigations and new exploit protections (Optionally enable per executable if application needs network connectivity)
- Apply tweaked power plan (.pow) files for either maximum performance and lowest latency, or a balance of power efficiency for laptop. (Advice to make your own and export with powercfg)
- Configure network (adapters) automatically
- Configure hibernation and pagefile size and allocation

###### Security:

- Purged all default firewall rules, block all inbound and outbound by default, and setup custom core networking rules. (DHCP, IGMP, Ping, SMB, RDP, NTP, etc)
- Enable event viewer (security) insight on what application is being blocked, so you can easily set up rules through executable context menu.
- Block a multitude of telemetry through registry keys, although basically the firewall configuration blocks everything. (At least further reduces resources and keeps security logs clean.
- PowerShell background script to monitor unsolicited firewall rules being created by programs and installers, and subsequently remove them when detected.

###### Context Menu:

- Set mitigation policy per executable, either default (OS default), Performance or security. (Prerequisite for allowing firewall rule to apply)
	Additionally, with default or security, DSCP value 4 is applied to outgoing data of these executables. For performance, value 46 is applied.
- Set firewall rules per executable (Either predefined for ease, All Incoming, All Outgoing, All incoming local, All outgoing local, 80/443/TCP/UDP or custom rule)
- Take ownership on files/folders
- Classic customize (Windows 7)
- Bypass tunnel (Basically apply specific DSCP markings to executable packets going out, so you could have router support and route specific executables over a VPN or whatever, sets DSCP 40, and precedes every other applied QoS marking.
- Disable DPI Scaling
- GPU Adapter preference
- Add advanced system settings to right click on 'My PC'
- Block executable from running
- Open command prompt and powershell open here
- Full screen optimization
- Run as different user

###### Misc:
- Automatic installation of Visual Runtime C++ and Direct3D9 Runtime pack if not installed.
- Automatic installation of HEIFImageExtension, VCLibs, VP9VideoExtensions, WebMediaExtensions, etc.
- Installation / Removal of Windows features and capabilities.
- Restore Windows Photo Viewer
- Purge default annoying sound scheme
- Purge trash from context menu (Pin Quick Access, Pin to Start, Troubleshoot, Send To, Modern Sharing, Include in Library, Give Access To, Edit with Paint 3D / Rotate Image / 3D Print, Cast to Device, Windows Defender)
- Permanently disable Update Medic Service, Update Orchestrator Service, Delivery Optimization, BITS, while keeping Windows Update service functional. (Thus can manually apply cumulative updates still)
- PowerShell background script to monitor user startup (at login) entries being created by random programs and installers, and remove them automatically. (Only affect user specific startup programs created under HCKU)
- Disabled nagging about 'do you want to initialize disks' if they contain fully encrypted filesystems in diskmgmt.msc (And subsequently destroy the disk by accident on a misclick)
- Disable certain devmgmt.msc drivers
- Optional enable MSI on supported drivers/hardware and irq affinity.
- System-wide driver disable 'allowed to go to sleep'
- Cleanup control panel
- Desktop/Explorer/DWM custom personalization
- Monitor.ps1 can be used to act on a variety of triggers to futher automate the system as desired (Do something when application runs, or when RDP session is detected)

## How to use?
- First configure script to personal preference, set up your own power plan profiles, add/remove target computers/names. 
- Install LTSC without network cable attached.
- Activate built-in Administrator account. (Optionally remove default account created on first setup)
- Activate Windows
- Install all desired drivers, etc.
- Backup system in case something fails. (Recommending AOMEI Backupper)
- Run.cmd will start the corresponding elevated and unelevated scripts. (Elevated has SYSTEM level privilege, unelevated runs under local user account. For HKLM/HKCU hives respectively) 
- Script can be ran after every driver, cumulative update or other significant OS change which is covered by the script. (Script generated and already created custom firewall rules through context menu will not be purged.)
- Recommended for first use to run script again after first reboot.

## Notes
- Unable to disable Tamper protection through script on some systems (i.e. vmware?), but does work manually through UI. (Requires more investigation on what's causing this)
- Use MarkC mouse acceleration curve generator for perfect 1:1 pixel movement on screen DPI other than 100% (Otherwise, disabling enhance mouse pointer is sufficient)
- Enable 'wuauserv' (Windows Update) service in order to apply cumulative updates. (Will be disabled again after re-running script after applying an update)

## DSCP Markings
DSCP values can be useful for allowing only data through the router on home network for extra security layer, or to put router in performance mode (Gaming) by detecting markings and act upon it, or to route data through some specified network interface.<br>
If you have such a networking system in place, you can also install Windows 10 without being afraid of having to pull your network cable each time because nothing will get through.<br>
<br>
Example:<br/>

Allow clients to bypass tunnel with dscp 40:<br/>
<br/>
-A POSTROUTING -s 192.168.1.0/24 -o eth1 -p tcp -m dscp --dscp 40 -j MASQUERADE<br/>
-A POSTROUTING -s 192.168.1.0/24 -o eth1 -p udp -m dscp --dscp 40 -j MASQUERADE<br/>
<br/>
Allow LAN to Tunnel:<br/>
<br/>
-A POSTROUTING -s 192.168.1.0/24 -o wg0 -p tcp -m dscp --dscp 4 -j MASQUERADE<br/>
-A POSTROUTING -s 192.168.1.0/24 -o wg0 -p udp -m dscp --dscp 4 -j MASQUERADE<br/>
-A POSTROUTING -s 192.168.1.0/24 -o wg0 -p tcp -m dscp --dscp 40 -j MASQUERADE<br/>
-A POSTROUTING -s 192.168.1.0/24 -o wg0 -p udp -m dscp --dscp 40 -j MASQUERADE<br/>
-A POSTROUTING -s 192.168.1.0/24 -o wg0 -p tcp -m dscp --dscp 46 -j MASQUERADE<br/>
-A POSTROUTING -s 192.168.1.0/24 -o wg0 -p udp -m dscp --dscp 46 -j MASQUERADE<br/>
