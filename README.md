# Incident-Response

##### This project utilizes an Azure environment, where I created and actively responded to 3 alerts in Microsoft Sentinel. 

<img width="700" src="https://github.com/user-attachments/assets/86d9065f-ddbc-4a15-8d38-0eb475f553b0">

##### These 3 alerts included the following: 
- [Brute Force Attempts](#brute-force-attemps)
- [PowerShell Suspicious Web Requests](#powershell-suspicious-web-requests)
- [Potential Impossible Travel](#potential-impossible-travel)

---

### Brute Force Attempts
<img width="700" src="https://github.com/user-attachments/assets/cc5b5fca-2658-40b6-bc93-0da7d85a1d42">


#### Rule Query: 
```
DeviceLogonEvents
| where ActionType == "LogonFailed" and TimeGenerated > ago(5h)
| summarize EventCount = count() by RemoteIP, DeviceName
| where EventCount >= 10
| order by EventCount
```
##### Description: 

---
#### Detection: 

##### For this rule, I received a single alert that grouped 37 seperate events together in this shared environment: 

<img width="700" src="https://github.com/user-attachments/assets/80e07c7f-d2bc-4590-9085-e4cbfafa54cb">

##### All 37 events have been investigated, but I will be focusing on a single entity for this lab with the device name: "vm-final-lab-sc"

<img width="700" src="https://github.com/user-attachments/assets/65bb8cb9-12ca-4f1a-85a1-380feb0df2c0">

##### The Edwin-Brute Force Detection rule triggered the "vm-final-lab-sc" device a total of 297 times from 3 remote IP addresses.

---

#### Analysis: 

##### First, I looked into the two external IP addresses of "122.231.145.189" and "4.240.63.212". I increased the time range and searched for any successful login attemps. 

<img width="700" src="https://github.com/user-attachments/assets/2184eb8d-440e-4a6a-89ef-61857359a32f">

##### No successful logins were found, indicating there were no successful logins from these malicious brute force attempts. 

##### Next, I will investigate the local IP with 66 failed attempts. 

<img width="700" src="https://github.com/user-attachments/assets/d8d47dd2-8221-43c0-a652-128352798f85">

##### This query shows that there were almost 1500 successful sign in attempts within the last 7 days. The RemoteDeviceName of "local-scan-engi" may indicate a vulnerability scan from Tenable was conducted on this machine. 
##### I contacted the owner of "vm-final-lab-sc" and confirmed they entered incorrect credentials for their credentialed scans that resulted in those failed login attempts. 

#### Conclusion: 

##### After investigating the three suspicious remote ip addresses, there were no malicious successful login attempts on the "vm-final-lab-sc" device. 
##### Next steps would include running an antivirus scan as a precaution, escalating this ticket to have the remote IP addresses of "122.231.145.189" and "4.240.63.212" blocked, and to limit the number of failed login attempts. 


---


### PowerShell Suspicious Web Requests
<img width="700" src="https://github.com/user-attachments/assets/866059eb-138a-4f29-899e-3b7a89c6d8b6">

##### Rule Query: 
```
DeviceProcessEvents
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"
| order by TimeGenerated
```
##### Description:

---
#### Detection: 

##### For this rule, I received 1 alert containing 37 events: 

<img width="700" src="https://github.com/user-attachments/assets/55a02e0d-3f81-4cf8-bde2-665433953e86">

##### I will be investigating a single device with the name of "agvm"

---
#### Analysis: 

<img width="700" src="https://github.com/user-attachments/assets/3ec04363-c654-44a1-aa73-624abb6cdbe3">

##### 4 potentially malicous powershell scripts were invoked from a github page and downloaded to the machines C:\programdata folder.

<img width="700" src="https://github.com/user-attachments/assets/8f839734-d74c-41aa-b9b4-2c7ec022ba65">

##### Based on the names of the scripts, the attacker potentially is trying to scan the network for open ports (portscan.ps1), perform possible ransomware activities (pwncrypt.ps1), and to exfiltrate data from the machine (exfiltratedata.ps1). 

##### Next I queried to verify if these malicious powershell scripts were executed on the device based on the filename. 

<img width="700" src="https://github.com/user-attachments/assets/872139f5-b88b-46b7-a5c6-f0139fce1c94">
<img width="700" src="https://github.com/user-attachments/assets/858ac2d1-42f9-4757-8e41-b0335faea5d9">

##### These results indicate that all 4 malicous powershell scripts were executed on "agvm". 

---
#### Next Steps: 

##### I have isolated this machine and ran an antivirus scan.  
...

### Potential Impossible Travel

<img width="700" src="https://github.com/user-attachments/assets/130da8dd-618a-46ba-8367-8577e379df79">

#### Rule Query: 
```
let TimePeriodThreshold = timespan(2d);
let NumberOfDifferentLocationsAllowed = 2;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
```
#### Detection: 

##### For this query, I received a single alert and event within the last 3 days of launching this alert: 

<img width="700" src="https://github.com/user-attachments/assets/d6d8c2a3-c6e6-4cb4-aef2-4e5c45c801bd">

<img width="700" src="https://github.com/user-attachments/assets/1d4260a4-3fb4-462f-9db2-b2f6a004e835">

##### Using the UserPrincipalName of the single event, I first expanded the search to 7 days. Then I ran a query that projects the City, State, and Country for the UserPrincipalName. This query resulted in 3 distinct locations: [(San Jose, California), (Portland, Oregan), (Los Angeles, California)]. 

<img width="700" src="https://github.com/user-attachments/assets/4822b031-2a64-4c03-9ebc-aef27be0a0aa">

##### While these geographic locations are not impossible to travel over 7 days, they are far enough to warrant asking the user for confirmation of these logins.

---

#### Next Steps:

##### I questioned the user about these logins and was confirmed these were legitimate logins. Since these were legitimate logins, I simply resolved the alert. 


