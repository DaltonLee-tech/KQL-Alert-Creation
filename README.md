# KQL-Alert-Creation

In this lab we will explore KQL queries and how they relate to alerts in the SIEM tool Microsoft Sentinel. I will go in depth on how to structure queries to create alerts inside of Sentinel, and how to create incidents using these alerts. We will then trigger a few of the alerts and observe the incidents they create.

KQL queries

For this lab we will be focusing on querying Windows event logs, but KQL can be used to query Linux machines, Microsoft Entra ID, Network Security Groups, Azure Key vaults, and many other resources inside of Azure. You can query in many different places in Azure, but for the purposes of this lab we will be querying the Log Analytics Workspace since all of the logs in my environment are routed here. The first query we will dissect is relating to brute force attempts on a Windows Virtual Machine. We can define a brute force login attempt as 10 or more failed logins within 1 hour.

![image](https://github.com/user-attachments/assets/0e9042b4-a38d-40de-b1ad-281042773073)

The first line in the query specifies what table the query pulls logs from. SecurityEvent is a type of log in Windows that pertains to security related events. These include:

Successful and failed logon attempts (Event ID 4624 for successful logon, Event ID 4625 for failed logon).
Logoff events (Event ID 4634).

User account changes such as creation, deletion, and modification (Event IDs 4720, 4722, 4723, 4724, 4725, 4726).

Events related to the use of privileges (Event ID 4672).

Changes to audit policies, such as enabling or disabling auditing (Event ID 4719).

Events that affect the system's integrity, like startup and shutdown of the system (Event IDs 4608, 4609).

Changes to group membership, including additions and removals of users in groups (Event IDs 4731, 4732, 4733).

Access to objects like files, folders, and registry keys (Event IDs 4663, 4660).

Events related to clearing of the event logs (Event ID 1102).

![image](https://github.com/user-attachments/assets/75e901de-635b-4463-be09-c8cb63588d42)


The second line in the query specifies the event ID of the log. In this case we are looking for failed logins so the corresponding EventID is 4625.

![image](https://github.com/user-attachments/assets/26f20d2b-ee70-4615-93f8-9435b3616c1f)

The third line restricts our results to only the past hour.

![image](https://github.com/user-attachments/assets/b2b59a1e-5258-4c0c-99d3-154ad91c4860)


The 4th line summarizes the data by counting the number of failed logon attempts (FailureCount = count()) and groups the results by the source IP address (SourceIP = IpAddress), event ID (EventID), and activity (Activity).

![image](https://github.com/user-attachments/assets/6464e190-626e-4c14-aa04-0c4aff18257c)

Finally, the 5th line filters the summarized results to include only those groups where the FailureCount (number of failed logon attempts) is 10 or more.


Creating Alerts in Sentinel

To be alerted of a brute force attempt in Sentinel we first need to configure a new rule using the KQL query we just assembled. To start this navigate to the analytics tab under configuration and create a new scheduled query rule.

![image](https://github.com/user-attachments/assets/591b010f-e232-4157-9622-ad47e9597d8b)

![image](https://github.com/user-attachments/assets/c29221c1-f44b-46f6-9174-988c6cf37ed3)

Under the "General" tab is where you can name and write a description of the rule. This is also where you can set the severity, enable/disbale the rule, and map to a specific instance of the MITRE ATT&CK framework.

![image](https://github.com/user-attachments/assets/0bf25b78-99fa-487f-92f3-95c2e14ddeb7)

The "Set Rule Logic" tab is where we will insert our query. There are other options for our rule in this tab such as:
Entity mapping: This option
Query scheduling:
Alert Threshold:
Event grouping:

![image](https://github.com/user-attachments/assets/7201b436-a539-4811-85a3-570248f67d0c)

The "Incident Settings" tab is where we will have incidents spun up from this rule. We can also group related alerts triggered by this rule into incidents. Grouping alerts into incidents provides the context you need to respond and reduces the noise from single alerts.

![image](https://github.com/user-attachments/assets/64a7c805-beaf-40b8-8e68-aa40435de0d8)

The "Automated Response" tab is where we can have Sentinel automatically perform an action when an incident or alert is created. These include running a preset playbook, changing the incident status or severity, and assigning a new owner to the incident. Now we can finally save our rule.
