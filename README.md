<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
[Scenario Creation](https://github.com/DennisMarple/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” and discovered that a user downloaded a Tor installer to the desktop and the creation of a file tor-shopping-list.txt at 2025-03-20T10:31:07.7429159Z. Events began at 2025-03-20T10:18:09.3055191Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "dennis"
| where FileName contains "tor"
|where Timestamp >= datetime(2025-03-20T10:18:09.3055191Z)
| order by Timestamp desc
|project Timestamp,DeviceName,ActionType,FileName,FolderPath,SHA256,Account=InitiatingProcessAccountName


```
![image](https://github.com/user-attachments/assets/f8d3edbc-0210-4a46-bcd0-d4f93ede6341)


---

### 2. Searched the `DeviceProcessEvents` Table

​Searched the DeviceProccessEvents table for any ProcessCommandLine for the string that contained "tor-browser-windows-x86_64-portable-14.0.7.exe" Based on the logs returned at,2025-03-20T10:18:36.1171907Z the user 'dennis' on the device 'dennis' executed the file 'tor-browser-windows-x86_64-portable-14.0.7.exe' from the 'Downloads' folder. The user also tried a silent installation command at 2025-03-20T10:21:41.6347515Z.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "dennis"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.7.exe"
|project Timestamp,DeviceName,AccountName,ActionType,FileName,FolderPath,SHA256,ProcessCommandLine

```
![image](https://github.com/user-attachments/assets/df3a8909-bc33-4eb2-a39b-d14b92155b02)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for an indication that the tor browser was opened by the user. It was opened at 2025-03-20T10:22:25.3065583Z
At 2025-03-20T10:22:25.3065583Z, the user 'dennis' launched 'firefox.exe' located in 'C:\U​sers\D​ennis\D​esktop\T​or Browser\B​rowser'​.


**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "dennis"
| where FileName has_any ("tor.exe","firefox.exe","tor-browser.exe")
|project Timestamp,DeviceName,AccountName,ActionType,FileName,FolderPath,SHA256,ProcessCommandLine
| order by Timestamp desc

```
![image](https://github.com/user-attachments/assets/cface4df-a875-4a5a-bc0d-2fdc83170c7a)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for an indication the Tor browser was used on any known tor ports.  ​At 2025-03-20T10:22:58.3123971Z, the user 'dennis' on the device 'dennis' initiated the 'firefox.exe' process located in 'C:\U​sers\D​ennis\D​esktop\T​or Browser\B​rowser'​. This process established a successful connection to the local IP address 127.0.0.1 on port 9150. There were also a few connections on port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "dennis"
|where InitiatingProcessFileName in ("tor.exe","firefox.exe")
|where RemotePort in ( "9001", "9030", "9040", "9050", "9051","9150","443","80")
|project Timestamp,DeviceName,ActionType,InitiatingProcessFileName,InitiatingProcessFolderPath,RemotePort,RemoteIP,RemoteUrl

```
![image](https://github.com/user-attachments/assets/4dc23c86-3fe0-4176-9eaf-32eeed7416c9)


---

# Chronological Event Timeline

## 1. File Download - TOR Installer
- **Timestamp:** 2025-03-20T10:18:09.3055191Z
- **Event:** The user "dennis" downloaded the Tor installer file **tor-browser-windows-x86_64-portable-14.0.7.exe** to the **Downloads** folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\dennis\Downloads\tor-browser-windows-x86_64-portable-14.0.7.exe`

## 2. Process Execution - TOR Installer Run
- **Timestamp:** 2025-03-20T10:18:36.1171907Z
- **Event:** The user "dennis" executed the Tor installer from the **Downloads** folder.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.7.exe`
- **File Path:** `C:\Users\dennis\Downloads\tor-browser-windows-x86_64-portable-14.0.7.exe`

## 3. Silent Installation Attempt
- **Timestamp:** 2025-03-20T10:21:41.6347515Z
- **Event:** The user attempted a **silent installation** of the Tor browser.
- **Action:** Process execution detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.7.exe /S`
- **File Path:** `C:\Users\dennis\Downloads\tor-browser-windows-x86_64-portable-14.0.7.exe`

## 4. TOR Browser Launch
- **Timestamp:** 2025-03-20T10:22:25.3065583Z
- **Event:** The user "dennis" opened the **Tor Browser**, launching **firefox.exe** from the installed directory.
- **Action:** Process execution detected.
- **File Path:** `C:\Users\dennis\Desktop\Tor Browser\Browser\firefox.exe`

## 5. TOR Network Connection Established
- **Timestamp:** 2025-03-20T10:22:58.3123971Z
- **Event:** The **firefox.exe** process established a network connection to **127.0.0.1** on **port 9150**, indicating Tor network usage.
- **Action:** Network connection detected.
- **Process:** `firefox.exe`
- **File Path:** `C:\Users\dennis\Desktop\Tor Browser\Browser\firefox.exe`

## 6. Additional Network Connections - TOR Browser Activity
- **Timestamps:**
  - **2025-03-20T10:23:05Z** - Connected to external IP on **port 443**.
  - **2025-03-20T10:23:12Z** - Connected to **127.0.0.1** on **port 9150**.
- **Event:** Additional **Tor network connections** were established, confirming continued browser activity.
- **Action:** Multiple successful connections detected.

## 7. File Creation - "tor-shopping-list.txt"
- **Timestamp:** 2025-03-20T10:31:07.7429159Z
- **Event:** The user "dennis" created a file **tor-shopping-list.txt** on the desktop, possibly related to Tor activity.
- **Action:** File creation detected.
- **File Path:** `C:\Users\dennis\Desktop\tor-shopping-list.txt`


---

## Summary

The user "dennis" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `dennis`. The device was isolated, and the user's direct manager was notified.

---
