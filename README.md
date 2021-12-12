# Windows 10 LTSC 21H2 Custom Post-install configuration script.

## Disclaimer: Needs third party tools for correct functioning.

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

- Set mitigation policy per executable, either default (performance) or security. (Prerequisite for allowing firewall rule to apply)
- Set firewall rules per executable (Either predefined for ease, All Incoming, All Outgoing, All incoming local, All outgoing local, 80/443/TCP/UDP or custom rule)
- Take ownership on files
- Classic customize (Windows 7)
- Bypass tunnel (Basically apply specific DSCP markings to executable packets going out, so you could have router support and route specific executables over a VPN or whatever)
- Disable DPI Scaling
- GPU Adapter preference

###### Misc:
- Automatic installation of Visual Runtime C++ and Direct3D9 Runtime pack if not installed.
- Automatic installation of HEIFImageExtension, VCLibs, VP9VideoExtensions, WebMediaExtensions, etc.
- Installation / Removal of Windows features and capabilities.
- Restore Windows Photo Viewer
- Purge default annoying sound scheme
- Purge trash from context menu (Pin Quick Access, Pin to Start, Troubleshoot, Send To, Modern Sharing, Include in Library, Give Access To, Edit with Paint 3D / Rotate Image / 3D Print, Cast to Device, Windows Defender)
- Permanently disable Update Medic Service, Update Orchestrator Service, Delivery Optimization, BITS, while keeping Windows Update service functional. (Thus can manually apply cumulative updates still)
- PowerShell background script to monitor user startup (at login) entries being created by random programs and installers, and remove them automatically.
- Disabled nagging about 'do you want to initialize disks' if they contain fully encrypted filesystems in diskmgmt.msc (And subsequently destroy the disk)
- Disable certain devmgmt.msc drivers
- Optional enable MSI on supported drivers/hardware and irq affinity.
- System-wide driver disable 'allowed to go to sleep'
- Cleanup control panel
- Desktop/Explorer/DWM custom personalization
- And much more! (Too much to list)

## How to use?
- First configure script to personal preference, set up your own power plan profiles, add/remove target computers/names. 
- Install LTSC without network cable attached.
- Activate built-in Administrator account.
- Activate Windows
- Install all desired drivers, etc.
- Backup system in case something fails. (Recommending AOMEI Backupper)
- Run.cmd will start the corresponding elevated and unelevated scripts.
- Script can be ran after every driver, cumulative update or other significant OS change which is covered by the script. Script generated and already created custom firewall rules through context menu will not be purged.

## Notes
- Somehow on some systems, tamper protection can't seem to get disabled, but through UI does work. Strangely on all my physical computers it works fine, but in a virtual machine the method through registry doesn't seem to work.