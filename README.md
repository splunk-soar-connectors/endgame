[comment]: # "Auto-generated SOAR connector documentation"
# Endgame

Publisher: Phantom  
Connector Version: 1\.0\.11  
Product Vendor: Endgame  
Product Name: Endgame  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 3\.0\.284  

This app integrates with Endgame to execute investigative and corrective actions

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Endgame asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** |  required  | string | URL
**verify\_server\_cert** |  optional  | boolean | Verify server certificate
**username** |  required  | string | Username
**password** |  required  | password | Password

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[list endpoints](#action-list-endpoints) - List all the endpoints/sensors configured on the device  
[list users](#action-list-users) - List all the users configured on the device  
[hunt user](#action-hunt-user) - Launch a search for a specific user session  
[hunt registry](#action-hunt-registry) - Launch a search for a specific registry  
[hunt ip](#action-hunt-ip) - Launch a search for a specific network connection  
[hunt process](#action-hunt-process) - Launch a search for a specific process  
[hunt file](#action-hunt-file) - Launch a search for a specific file  
[terminate process](#action-terminate-process) - Kill a Process  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'list endpoints'
List all the endpoints/sensors configured on the device

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**tags** |  optional  | Name of tag | string | 
**display\_operating\_system** |  optional  | Display operating system | string | 
**name** |  optional  | Name of endpoint | string |  `host name` 
**ip\_address** |  optional  | IPv4 address | string |  `ip` 
**core\_os** |  optional  | Core operating system | string | 
**limit** |  optional  | Maximum number of endpoints to retrieve \(Default\: 50\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.core\_os | string | 
action\_result\.parameter\.display\_operating\_system | string | 
action\_result\.parameter\.ip\_address | string |  `ip` 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.name | string |  `host name` 
action\_result\.parameter\.tags | string | 
action\_result\.data\.\*\.alert\_count | numeric | 
action\_result\.data\.\*\.core\_os | string | 
action\_result\.data\.\*\.created\_at | string | 
action\_result\.data\.\*\.display\_operating\_system | string | 
action\_result\.data\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.error | string | 
action\_result\.data\.\*\.hostname | string |  `host name` 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.investigation\_count | numeric | 
action\_result\.data\.\*\.ip\_address | string |  `ip` 
action\_result\.data\.\*\.mac\_address | string |  `mac address` 
action\_result\.data\.\*\.machine\_id | string | 
action\_result\.data\.\*\.name | string |  `host name` 
action\_result\.data\.\*\.operating\_system | string | 
action\_result\.data\.\*\.sensors\.\*\.id | string |  `endgame sensor id` 
action\_result\.data\.\*\.sensors\.\*\.sensor\_type | string | 
action\_result\.data\.\*\.sensors\.\*\.sensor\_version | string | 
action\_result\.data\.\*\.sensors\.\*\.status | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.status\_changed\_at | numeric | 
action\_result\.data\.\*\.tags\.\*\.id | string | 
action\_result\.data\.\*\.tags\.\*\.name | string | 
action\_result\.data\.\*\.updated\_at | string | 
action\_result\.summary\.num\_endpoints | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list users'
List all the users configured on the device

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.first\_name | string | 
action\_result\.data\.\*\.id | string |  `endgame user id` 
action\_result\.data\.\*\.is\_active | boolean | 
action\_result\.data\.\*\.is\_ldap | boolean | 
action\_result\.data\.\*\.is\_removable | boolean | 
action\_result\.data\.\*\.is\_superuser | boolean | 
action\_result\.data\.\*\.last\_name | string | 
action\_result\.data\.\*\.last\_viewed\_alert | string | 
action\_result\.data\.\*\.role\.id | string | 
action\_result\.data\.\*\.role\.permissions\.admin | boolean | 
action\_result\.data\.\*\.role\.permissions\.alerts\.admin\.forwardalerts | boolean | 
action\_result\.data\.\*\.role\.permissions\.alerts\.update | boolean | 
action\_result\.data\.\*\.role\.permissions\.alerts\.view | boolean | 
action\_result\.data\.\*\.role\.permissions\.endpoints\.changeconfiguration | boolean | 
action\_result\.data\.\*\.role\.permissions\.endpoints\.delete | boolean | 
action\_result\.data\.\*\.role\.permissions\.endpoints\.deploy | boolean | 
action\_result\.data\.\*\.role\.permissions\.endpoints\.respond | boolean | 
action\_result\.data\.\*\.role\.permissions\.endpoints\.scan | boolean | 
action\_result\.data\.\*\.role\.permissions\.endpoints\.tag | boolean | 
action\_result\.data\.\*\.role\.permissions\.endpoints\.uninstall | boolean | 
action\_result\.data\.\*\.role\.permissions\.endpoints\.view | boolean | 
action\_result\.data\.\*\.role\.permissions\.investigation\.create | boolean | 
action\_result\.data\.\*\.role\.permissions\.investigation\.update | boolean | 
action\_result\.data\.\*\.role\.permissions\.investigation\.view | boolean | 
action\_result\.data\.\*\.role\.permissions\.search\.delete | boolean | 
action\_result\.data\.\*\.role\.permissions\.search\.save | boolean | 
action\_result\.data\.\*\.role\.permissions\.search\.search | boolean | 
action\_result\.data\.\*\.role\.permissions\.sensor\.admin\.create | boolean | 
action\_result\.data\.\*\.role\.permissions\.sensor\.admin\.delete | boolean | 
action\_result\.data\.\*\.role\.permissions\.sensor\.admin\.download | boolean | 
action\_result\.data\.\*\.role\.permissions\.sensor\.admin\.update | boolean | 
action\_result\.data\.\*\.role\.permissions\.sensor\.admin\.view | boolean | 
action\_result\.data\.\*\.role\.permissions\.user\.create | boolean | 
action\_result\.data\.\*\.role\.permissions\.user\.delete | boolean | 
action\_result\.data\.\*\.role\.permissions\.user\.update | boolean | 
action\_result\.data\.\*\.role\.permissions\.user\.view | boolean | 
action\_result\.data\.\*\.role\.role | string | 
action\_result\.data\.\*\.username | string |  `user name` 
action\_result\.summary\.num\_users | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt user'
Launch a search for a specific user session

Type: **investigate**  
Read only: **True**

This action will launch a search for a specific user's sessions on the given endpoints\.<br><br>The <b>user</b> parameter can take a list of comma\-separated usernames\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user** |  required  | User to hunt | string | 
**domain** |  optional  | Domain | string |  `domain` 
**sensors** |  required  | Sensor IDs | string |  `endgame sensor id` 
**platform** |  required  | OS of sensors | string | 
**assignee** |  required  | Assignee | string |  `endgame user id` 
**name** |  required  | Name of the investigation | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.assignee | string |  `endgame user id` 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.parameter\.name | string | 
action\_result\.parameter\.platform | string | 
action\_result\.parameter\.sensors | string |  `endgame sensor id` 
action\_result\.parameter\.user | string | 
action\_result\.data\.\*\.collection\_id | string | 
action\_result\.data\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.ended | numeric | 
action\_result\.data\.\*\.logon\_type | string | 
action\_result\.data\.\*\.machine\_id | string | 
action\_result\.data\.\*\.password\_last\_set | numeric | 
action\_result\.data\.\*\.session\_count | numeric | 
action\_result\.data\.\*\.sid | string | 
action\_result\.data\.\*\.started | numeric | 
action\_result\.data\.\*\.username | string |  `user name` 
action\_result\.summary\.num\_results | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt registry'
Launch a search for a specific registry

Type: **investigate**  
Read only: **True**

This action will launch a search for a specific registry on the given endpoints\.<br><br>The <b>key</b> parameter can take a list of comma\-separated registry key names\.<br><br>This action only supports Windows endpoints\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**key** |  required  | IP to hunt | string | 
**hive** |  required  | Base hive to hunt in | string | 
**sensors** |  required  | Sensor IDs | string |  `endgame sensor id` 
**assignee** |  required  | Assignee | string |  `endgame user id` 
**name** |  required  | Name of the investigation | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.assignee | string |  `endgame user id` 
action\_result\.parameter\.hive | string | 
action\_result\.parameter\.key | string | 
action\_result\.parameter\.name | string | 
action\_result\.parameter\.sensors | string |  `endgame sensor id` 
action\_result\.data\.\*\.base\_hive | string | 
action\_result\.data\.\*\.collection\_id | string | 
action\_result\.data\.\*\.machine\_id | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.parent\_resource\_id | numeric | 
action\_result\.data\.\*\.path | string | 
action\_result\.data\.\*\.registry\_key\_last\_modified\_time | numeric | 
action\_result\.data\.\*\.registry\_value\_string | string | 
action\_result\.data\.\*\.registry\_value\_type | string | 
action\_result\.data\.\*\.resource\_id | numeric | 
action\_result\.summary\.num\_results | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt ip'
Launch a search for a specific network connection

Type: **investigate**  
Read only: **True**

This action will launch a search for connections to a remote IP on the given endpoints\.<br><br>The <b>ip</b> parameter can take a list of comma\-separated IPs\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to hunt | string |  `ip` 
**sensors** |  required  | Sensor IDs | string |  `endgame sensor id` 
**platform** |  required  | OS of sensors | string | 
**assignee** |  required  | Assignee | string |  `endgame user id` 
**name** |  required  | Name of the investigation | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.assignee | string |  `endgame user id` 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.name | string | 
action\_result\.parameter\.platform | string | 
action\_result\.parameter\.sensors | string |  `endgame sensor id` 
action\_result\.data\.\*\.connection\_status | string | 
action\_result\.data\.\*\.connection\_type | string | 
action\_result\.data\.\*\.exe | string |  `file path`  `file name` 
action\_result\.data\.\*\.family | string | 
action\_result\.data\.\*\.hashes\.md5 | string |  `md5` 
action\_result\.data\.\*\.hashes\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.hashes\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.local\_address | string |  `ip` 
action\_result\.data\.\*\.local\_port | numeric | 
action\_result\.data\.\*\.name | string |  `file name` 
action\_result\.data\.\*\.pid | numeric |  `pid` 
action\_result\.data\.\*\.protocol | string | 
action\_result\.data\.\*\.remote\_address | string |  `ip` 
action\_result\.data\.\*\.remote\_port | numeric | 
action\_result\.summary\.num\_results | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt process'
Launch a search for a specific process

Type: **investigate**  
Read only: **True**

This action will launch a search for a process on the given endpoints\.<br><br>The <b>process</b> parameter can take a process name or a list of comma\-separated hashes \(MD5, SHA1, or SHA256\)\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**process** |  required  | Process to hunt | string |  `md5`  `sha1`  `sha256`  `file name` 
**sensors** |  required  | Sensor IDs | string |  `endgame sensor id` 
**platform** |  required  | OS of sensors | string | 
**assignee** |  required  | Assignee | string |  `endgame user id` 
**name** |  required  | Name of the investigation | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.assignee | string |  `endgame user id` 
action\_result\.parameter\.name | string | 
action\_result\.parameter\.platform | string | 
action\_result\.parameter\.process | string |  `md5`  `sha1`  `sha256`  `file name` 
action\_result\.parameter\.sensors | string |  `endgame sensor id` 
action\_result\.data\.\*\.cmdline | string |  `file path` 
action\_result\.data\.\*\.create\_time | numeric | 
action\_result\.data\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.exe | string |  `file path`  `file name` 
action\_result\.data\.\*\.has\_unbacked\_execute\_memory | boolean | 
action\_result\.data\.\*\.is\_sensor | boolean | 
action\_result\.data\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.modules\.\*\.architecture | string | 
action\_result\.data\.\*\.modules\.\*\.authenticode\.cert\_signer\.issuer\_name | string | 
action\_result\.data\.\*\.modules\.\*\.authenticode\.cert\_signer\.serial\_number | string | 
action\_result\.data\.\*\.modules\.\*\.authenticode\.cert\_signer\.subject\_name | string | 
action\_result\.data\.\*\.modules\.\*\.authenticode\.cert\_timestamp\.issuer\_name | string | 
action\_result\.data\.\*\.modules\.\*\.authenticode\.cert\_timestamp\.serial\_number | string | 
action\_result\.data\.\*\.modules\.\*\.authenticode\.cert\_timestamp\.subject\_name | string | 
action\_result\.data\.\*\.modules\.\*\.authenticode\.cert\_timestamp\.timestamp\_string | string | 
action\_result\.data\.\*\.modules\.\*\.authenticode\.more\_info\_link | string | 
action\_result\.data\.\*\.modules\.\*\.authenticode\.program\_name | string | 
action\_result\.data\.\*\.modules\.\*\.authenticode\.publisher\_link | string | 
action\_result\.data\.\*\.modules\.\*\.compile\_time | numeric | 
action\_result\.data\.\*\.modules\.\*\.hashes\.imphash | string | 
action\_result\.data\.\*\.modules\.\*\.hashes\.md5 | string | 
action\_result\.data\.\*\.modules\.\*\.hashes\.sha1 | string | 
action\_result\.data\.\*\.modules\.\*\.hashes\.sha256 | string | 
action\_result\.data\.\*\.modules\.\*\.mapped\_address | numeric | 
action\_result\.data\.\*\.modules\.\*\.mapped\_size | numeric | 
action\_result\.data\.\*\.modules\.\*\.path | string | 
action\_result\.data\.\*\.modules\.\*\.pe\_imports\.\*\.dll\_name | string | 
action\_result\.data\.\*\.modules\.\*\.pe\_imports\.\*\.import\_names | string | 
action\_result\.data\.\*\.modules\.\*\.signature\_signer | string | 
action\_result\.data\.\*\.modules\.\*\.signature\_status | string | 
action\_result\.data\.\*\.name | string |  `file name` 
action\_result\.data\.\*\.parent\_exe | string |  `file path`  `file name` 
action\_result\.data\.\*\.parent\_name | string |  `file name` 
action\_result\.data\.\*\.pid | numeric |  `pid` 
action\_result\.data\.\*\.ppid | numeric |  `pid` 
action\_result\.data\.\*\.services\.\*\.name | string | 
action\_result\.data\.\*\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.sid | string | 
action\_result\.data\.\*\.signature\_signer | string | 
action\_result\.data\.\*\.signature\_status | string | 
action\_result\.data\.\*\.threads\.\*\.create\_time | numeric | 
action\_result\.data\.\*\.threads\.\*\.thread\_id | numeric | 
action\_result\.data\.\*\.threads\.\*\.up\_time | numeric | 
action\_result\.data\.\*\.unbacked\_execute\_byte\_count | numeric | 
action\_result\.data\.\*\.unbacked\_execute\_region\_count | numeric | 
action\_result\.data\.\*\.up\_time | numeric | 
action\_result\.data\.\*\.user | string | 
action\_result\.summary\.num\_results | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt file'
Launch a search for a specific file

Type: **investigate**  
Read only: **True**

This action will launch a search for a file on the given endpoints in the given directory\.<br><br>The <b>file</b> parameter can take a file name regex or a hash \(MD5, SHA1, or SHA256\)\. It can also take any combination of the aforementioned in a comma\-separated list \(e\.g\: 6383522c180badc4e1d5c30a5c4f4913,\*\.exe,62a30e96459b694f7b22d730c460a65cd2ebaaca\)

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file** |  required  | File to hunt | string |  `md5`  `sha1`  `sha256`  `file name` 
**directory** |  required  | Directory to hunt in | string |  `file path` 
**sensors** |  required  | Sensor IDs | string |  `endgame sensor id` 
**platform** |  required  | OS of sensors | string | 
**assignee** |  required  | Assignee | string |  `endgame user id` 
**name** |  required  | Name of the investigation | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.assignee | string |  `endgame user id` 
action\_result\.parameter\.directory | string |  `file path` 
action\_result\.parameter\.file | string |  `md5`  `sha1`  `sha256`  `file name` 
action\_result\.parameter\.name | string | 
action\_result\.parameter\.platform | string | 
action\_result\.parameter\.sensors | string |  `endgame sensor id` 
action\_result\.data\.\*\.file\_path | string |  `file path`  `file name` 
action\_result\.data\.\*\.meta\_data\.file\_attributes | numeric | 
action\_result\.data\.\*\.meta\_data\.file\_name\_timestamps\.accessed | numeric | 
action\_result\.data\.\*\.meta\_data\.file\_name\_timestamps\.created | numeric | 
action\_result\.data\.\*\.meta\_data\.file\_name\_timestamps\.entry\_modified | numeric | 
action\_result\.data\.\*\.meta\_data\.file\_name\_timestamps\.modified | numeric | 
action\_result\.data\.\*\.meta\_data\.file\_size | numeric | 
action\_result\.data\.\*\.meta\_data\.hashes\.md5 | string |  `md5` 
action\_result\.data\.\*\.meta\_data\.hashes\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.meta\_data\.hashes\.sha256 | string |  `sha256` 
action\_result\.summary\.num\_results | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'terminate process'
Kill a Process

Type: **contain**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**pid** |  required  | PID | numeric |  `pid` 
**sensors** |  required  | Sensor IDs | string |  `endgame sensor id` 
**platform** |  required  | OS of sensors | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.pid | string |  `pid` 
action\_result\.parameter\.platform | string | 
action\_result\.parameter\.sensors | string |  `endgame sensor id` 
action\_result\.data\.\*\.data\.created\_at | string | 
action\_result\.data\.\*\.data\.data\.results\.\*\.bulk\_task\_id | string | 
action\_result\.data\.\*\.data\.data\.results\.\*\.correlation\_id | string | 
action\_result\.data\.\*\.data\.data\.results\.\*\.endpoint\.display\_operating\_system | string | 
action\_result\.data\.\*\.data\.data\.results\.\*\.endpoint\.hostname | string |  `host name` 
action\_result\.data\.\*\.data\.data\.results\.\*\.endpoint\.id | string | 
action\_result\.data\.\*\.data\.data\.results\.\*\.endpoint\.ip\_address | string |  `ip` 
action\_result\.data\.\*\.data\.data\.results\.\*\.endpoint\.mac\_address | string | 
action\_result\.data\.\*\.data\.data\.results\.\*\.endpoint\.name | string | 
action\_result\.data\.\*\.data\.data\.results\.\*\.endpoint\.operating\_system | string | 
action\_result\.data\.\*\.data\.data\.results\.\*\.endpoint\.status | string | 
action\_result\.data\.\*\.data\.data\.results\.\*\.endpoint\.updated\_at | string | 
action\_result\.data\.\*\.data\.data\.results\.\*\.investigation\_id | string | 
action\_result\.data\.\*\.data\.data\.results\.\*\.origination\_task\_id | string | 
action\_result\.data\.\*\.data\.doc\_type | string | 
action\_result\.data\.\*\.data\.endpoint\.core\_os | string | 
action\_result\.data\.\*\.data\.endpoint\.created\_at | string | 
action\_result\.data\.\*\.data\.endpoint\.display\_operating\_system | string | 
action\_result\.data\.\*\.data\.endpoint\.domain | string |  `domain` 
action\_result\.data\.\*\.data\.endpoint\.error | string | 
action\_result\.data\.\*\.data\.endpoint\.hostname | string |  `host name` 
action\_result\.data\.\*\.data\.endpoint\.id | string | 
action\_result\.data\.\*\.data\.endpoint\.ip\_address | string |  `ip` 
action\_result\.data\.\*\.data\.endpoint\.mac\_address | string | 
action\_result\.data\.\*\.data\.endpoint\.machine\_id | string | 
action\_result\.data\.\*\.data\.endpoint\.name | string | 
action\_result\.data\.\*\.data\.endpoint\.operating\_system | string | 
action\_result\.data\.\*\.data\.endpoint\.sensors\.\*\.id | string | 
action\_result\.data\.\*\.data\.endpoint\.sensors\.\*\.sensor\_type | string | 
action\_result\.data\.\*\.data\.endpoint\.sensors\.\*\.sensor\_version | string | 
action\_result\.data\.\*\.data\.endpoint\.sensors\.\*\.status | string | 
action\_result\.data\.\*\.data\.endpoint\.status | string | 
action\_result\.data\.\*\.data\.endpoint\.status\_changed\_at | numeric | 
action\_result\.data\.\*\.data\.endpoint\.tags\.\*\.id | string | 
action\_result\.data\.\*\.data\.endpoint\.tags\.\*\.name | string | 
action\_result\.data\.\*\.data\.endpoint\.updated\_at | string | 
action\_result\.data\.\*\.data\.family | string | 
action\_result\.data\.\*\.data\.id | string | 
action\_result\.data\.\*\.data\.machine\_id | string | 
action\_result\.data\.\*\.data\.os\_type | string | 
action\_result\.data\.\*\.data\.status | string | 
action\_result\.data\.\*\.data\.task\_id | string | 
action\_result\.data\.\*\.data\.type | string | 
action\_result\.data\.\*\.metadata\.count | numeric | 
action\_result\.data\.\*\.metadata\.next | string | 
action\_result\.data\.\*\.metadata\.next\_url | string | 
action\_result\.data\.\*\.metadata\.per\_page | numeric | 
action\_result\.data\.\*\.metadata\.previous | string | 
action\_result\.data\.\*\.metadata\.previous\_url | string | 
action\_result\.data\.\*\.metadata\.timestamp | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 