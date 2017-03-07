# win-inventory

This is a script used for creating an inventory of important characteristics of a Windows system. The results are written in JSON format to a local file.

The idea is to improve the security posture by monitoring these characteristics and detect various intrusions by observing any changes. Therefore any differences in the inventory since the last time the script was run will be written to a local file and posted to a central HTTP(S) endpoint where further analysis can be performed.

The check 'database' currently lists the following:
* **Certificates** - certificates installed in the Windows certificate store
* **ChangedDLLs** - recently changed DLL files in specified (currently hardcoded) system locations
* **Hosts** - entries from the Windows hosts file.
* **InstalledApplications** - applications installed on the system via Windows Installer or any derivatives (basically the applications that show up when using the "Add/Remove Programs" dialog)
* **InternetExplorerAddons** - plugins or addons used by Internet Explorer
* **ListeningPorts** - ports that the system is listening on (below 49152) as well which PID opened the port for listening
* **LocalAdmins** - users or groups in the local "Administrators" group
* **PrefetchFiles** - files present in the Windows Prefetch folder (showing which files have been executed and when)
* **RunningProcesses** - running processes along with information on if their signature (if any) is valid
* **ScheduledTasks** - scheduled tasks
* **Services** - services present on the system
* **StartupItems** - startup items
