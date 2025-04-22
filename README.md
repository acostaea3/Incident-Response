# Incident-Response

This project utilizes an Azure environment, where I created and actively responded to 3 alerts in Microsoft Sentinel. 

![image](https://github.com/user-attachments/assets/86d9065f-ddbc-4a15-8d38-0eb475f553b0)


These 3 alerts included the following: 
- [Brute Force Attempts](#brute-force-attemps)
- [PowerShell Suspicious Web Requests](#powershell-suspicious-web-requests)
- [Impossible Travel](#impossible-travel)

---

### Brute Force Attempts

Rule Query: 
```
DeviceLogonEvents
| where ActionType == "LogonFailed" and TimeGenerated > ago(5h)
| summarize EventCount = count() by RemoteIP, DeviceName
| where EventCount >= 10
| order by EventCount
```
Description: 

---
Detection: 

For this rule, we received a single alert that grouped 37 seperate events together in this shared environment: 

![image](https://github.com/user-attachments/assets/80e07c7f-d2bc-4590-9085-e4cbfafa54cb)





### PowerShell Suspicious Web Requests




---

### Impossible Travel
