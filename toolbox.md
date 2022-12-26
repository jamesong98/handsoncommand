# Linux
## General
### Docker
#### Docker Cli
- Image
    ```bash
    # List all Image
    docker images
    # List all Image ID only
    docker image -q
    #Filter Only the environment and show the tag together (this was checking what has been download only) --optional
    docker images --filter "reference=<registry url>/<folder>/*" --format "{{.Repository}}:{{.Tag}}"  
    #Delete Image
    docker rmi <Image ID/Image Name:Version>
    #Delete Unused Image
    docker rmi -f $(docker images -f "dangling=true" -q)
    #Build Image
    docker build -t <image tag name:version> <directory of Dockerfile>
    #Export Image
    docker save -o <path with .tar extension> <image name and tag>
    #Import Image
    docker load -i <path with .tar extension>

    ```
  
- Container
    ```bash
    #List Running Container 
    docker ps
    #List all Container
    docker ps -a
	#Run a container
	docker run 
	#Run a container with detach mode
	## restart can be always, unless-stopped
	docker run -d -p <host port>:<container port> --restart=always --name <container name> <image name>:<image version>
	#Run a container with interactive shell
	##shell can be /bin/bash, /bin/sh
	docker run -it <image name>:<image version> <type of shell>
	#Run a container and moutning host volume
	docker run -v <host volume path location>:<container path location> <image name>:<image version
	#Check each container statistic
	docker stats
	

    ```

#### Docker Compose
```bash
#Pull docker image based on compose file
docker-compose pull
#Build docker container based on compose file
docker-compose build
#Push docker container image
docker-compose push <service name>
#Run docker compose stack
docker-compose up
#Check custom  docker compose file container status
docker-compose -f <compose file> ps
#Run docker compose stack by specify environment variables file
docker-compose --env-file <environment variables file> up -d
#Bring down docker compose stack
docker-compose down
#Resolve the variable, combine multiple compose stack into one (tweak in .env file)
docker-compose config
```
### Containerd
#### Containerd Cli
- Image
    ```bash
    #List Image
    ctr image list
    #List Image that pull by Kubernetes (K8S)
    ctr --namespace k8s.io image list
    #Pull Image
    ctr image pull <image path or URL>
    #Pull Image with authentication
    ctr image pull --user <user:password> <image path or URL>
    #Delete image
    ctr image delete  <image path or URL>
    ```
- Container
    ```bash
    #List Containers
    ctr containers list
    #List Containers that launched by Kubernetes (K8S)
    ctr --namespace k8s.io containers list
    ```
### Kubernetes (K8S)
```bash
#Download KubeConfig (AWS)
aws eks update-kubeconfig --name <AWS EKS Name> --region <Region> --profile <AWS Profile Name>
#Download KubeConfig (AWS) with Assume Role
aws eks update-kubeconfig --name <AWS EKS Name> --role-arn <Role ARN to be assume> --region <Region> --profile <AWS Profile Name>
#List Context
kubectl config get-contexts
#Check current context
kubectl config current-context
#Use context
kubectl config use-context <context name>
#Apply resource manifest
kubectl apply -f <manifest file> --namespace <namespace>
#Delete resource with manifest
kubectl delete -f <manifest file> --namespace <namespace>
#Set Editor
export KUBE_EDITOR='code --wait'
#Edit resource
kubectl edit <resource type> <resource name> --namespace <namespace>
#Check Worker nodes
kubectl get nodes
kubectl get nodes --watch
#Check Namespace
kubectl get namespaces
#Check Pods
kubectl get pods
kubectl get pods -A
#Check resource
kubectl get <resource type> <resource name> --namespace <namespace>
```
### Helm
```bash
#Check Helm repository
helm repo list
#Add a Helm repository
helm repo add <repository name> <Repository URL>
#Remove a Helm repository
helm repo remove <repository name>
#Update Helm repository
helm repo update
#Search Helm repository
helm search <keyword>
helm search repo <keyword>
#Helm upgrade and install chart
helm upgrade  --install <release> --namespace <namespace>  <chart directory>
#Helm uninstall chart
helm uninstall <release> --namespace <namespace>
#Helm Roll back chart
helm rollback <release> <revision number>
#Helm download chart 
helm pull <repository name> <path of charts>
#Helm Download Release
helm get manifest <release name>
#Helm generate manifest
helm template <chart directory>
```
### LXC/LXD
- Image
```bash
#List image
lxc image list
#List image (specific server)
lxc image list <image server>
#Create image with fingerprint
lxc image alias create <image name> <image fingerprint>
#List image (remote)
lxc remote list
#Copy remote image to local
lxc image copy <remote server name>:<version>/<architecture> local: --alias <local image name>
#Import container
lxc image import <tar ball path> --alias <local image name>
#Publish image (Stop existing container before publish)
lxc publish --publish <existing container name> --alias=<local image name>
#Publish image (without stopping container and need take snapshot first then publish the snapshot)
lxc snapshot <container name> <snapshot name>
lxc publish <container name>/<snapshot name> --alias <image name>
#Export 
lxc image export <image name>
```
- Container
```bash
#Initialization
lxd init
#Attach console
lxc console <container name>
#List container
lxc list
#List container with specific column
<<'Explaination'
4 - IPv4 address

6 - IPv6 address

a - Architecture

c - Creation date

n - Name

p - PID of the container's init process

P - Profiles

s - State

S - Number of snapshots

t - Type (persistent or ephemeral)

Explaination

lxc list --column "nsapt"

#Enter shell of the container
lxc exec <container name> <command>
#Enter shell (specific shell) of the container
##shell can be sh, bash
lxc exec <container name> <shell>
#Enter shell with specific user
lxc exec <container name> -- sudo --user <user in container> --login
#Launch a new container
lxc launch <image server>:<distro>/<version>/<architecture> <container name>
#Launch a new container without running it
lxc init <image server>:<distro>/<version>/<architecture> <container name>
#Copy existing container name
lxc copy <exisiting container name> <new container name>
#Operation of container
lxc start <container name>
lxc stop <container name>
lxc restart <container name>
lxc pause <container name>
lxc delete <container name>/<snapshot name>
#Show info for the container name
lxc info <container name>
#Take a snapshot of the container
lxc snapshot <container name> <snapshot name>
#Restore snapshot for the container
lxc restore <container name> <snapshot name>
#Rename a snapshot of the container
lxc move <container name>/<snapshot name> <container name>/<new snapshot name>
#Copy file from container
lxc file pull <container name>:<file path in the container> <host file path>
#Copy file to container
lxc file push <host file path> <container name>:<file path in the container>
```
- operation
```bash
#List backgroud operation (sometimes lxc command not execute correctly and it might have schedule image update in the background)
lxc operation list
```

### Ansible
#### ansible command
   ```bash
   #Test host connectivity (SSH Connection from Ansible to host )
   ## Can use all to  check all host group
   ansible <host group name> -m ping
   #Execute shell command on remote host
   ansible <host group name> -m shell -a "<command to be execute>"
   ```
#### ansible-playbook
```bash
#Execute playboook with priviledge user password prompt
ansible-playbook -i <inventory file> --ask-become-pass
#Execute playbook  with priviledge user password prompt and decrypt ansible vault file
ansible-playbook -i <inventory file> --ask-become-pass --ask-vault-pass
```
#### ansible-vault
```bash
#Encrypt file
ansible-vault encrypt <file name>.yml
#View file
ansible-vault view <file name>.yml
#Edit file
ansible-vault edit <file name>.yml
#Decrypt File
ansible-vault decrypt <file name>.yml
```
### Text Editor
#### Vim
- Delete all lines
	Enter command mode
	Move cursor to end of target line
	input command `:.,$d` press `Enter`
- Find and Replace
	Enter Command Mode
	Input command `:%s/<target text>/<replace text>/g` to replace without confirmation
	OR
	Input command `:%s/<target text>/<replace text>/gc` to replace with confirmation 
- Multiple Line input at the same position
	Enter Command mode
	Press `v` to enter vertical select
	Move cursor how many line need to be input with the same position
	Press `Shift + i`
	Enter the text (it will only display at the first line)
	Press `Esc`
	the remaining line will start appearing with the text you have input at the first line
	
### View File
#### Pager
##### less
```bash
# Display Line Number
less -N <file name>
# Follow the file (live update and pause with Ctrl +C but still inside less pager)
less +F <file name>
```
- Go to line number, press ":" then enter line number you plan to navigate
- After navigate to the specific line, you may want to edit the file and now you may press "v" to editor default text editor to make the changes and you may save (based on your text editor) and it will return to less pager again
##### more
#### Stream Editor
##### sed
```bash
# without making changes, just preview
sed  "s/<text to replace>/<replace with>/g" <file name>
# making changes
sed -i "s/<text to replace>/<replace with>/g" <file name>
```
##### head
```bash
# Show first 10 line from the file
head <file name>
# Show first number of line from the file
head -n <line number> <file name>

```
##### tail
```bash
# Show last 10 line from the file
tail <file name>
# Show last number of line from the filoe
tail -n <line number> <file name>
# Show live update of at the end of a file
tail -f <file name>
```
##### grep
```bash
# search match string from the file
grep <simple word pattern> <file name>
# search match string from the directory
grep -r <simple word pattern> <directory name>
# search invert match string
grep -v <simple world pattern> <file name>
# search with and operator
grep -E "<condition 1>.*<condition 2>" <file name>
# search with or operator
grep -E "<condition 1>|<condition 2>" <file name>
egrep "<condition 1>|<condition 2>" <file name>
# search with line nearby with same number of before and after
grep -C <number line before and after> <simple world pattern> <filename>
# search PID with process name
pgrep <process name>
```
#### heredoc

### File
#### find
```bash
#Find with file type and name
find <directory> -type <f for file /d for directory> -name <file name pattern>
#Find with file type and name (no case sensitive)
find <directory> -type <f for file /d for directory> -iname <file name pattern>
#Find with user or group
find <directory> -user <user name>
find <directory -group <group name>
#Find file base on size
find <directory> -size <sizing>
find <directory -size +<greater than size> -<lesser than size>
#Find file that match condition and delete (if the list too long might fail to remove, try to output find command to a text file and use for loop to delete instead)
find <directory> -type f -name <file name pattern> -exec rm -f {} \;

```
#### locate

### Network
#### Netstat,ss
#### Iftop
#### nc
```bash
#test port without viewing the respond
nc -zv <ip address> <port>
#Listen for connection
nc -lvnp <port number>
```
#### Haproxy
```bash
#check if configuration is valid
haproxy -c -f <haproxy config file>
```
#### Nginx
```bash
#check if configuration is valid
nginx -t
```
#### iptables
```bash
iptables -L
iptables -t nat -L
iptables -L --line-numbers
iptables -A <chain> <rules>
iptables -D <chain> rules
iptables-save 
iptables-restore
```
#### NetPlan
```bash
netplan try
netplan apply
netplan apply --debug
```
#### OpenSSL
- Generate Random Byte
  ```bash
  openssl rand -hex <number of digits>
  openssl rand -base64 <number of digits>
  ```
- View OpenSSL related document
  ```bash
  openssl x509 -in <crt file> -noout -text | less
  openssl crl -in <crl file> -noout -text | less
  ```
- View SSH Key FingerPrint
```bash
#SHA1 (AWS display RSA Key Type that created by AWS), 
openssl pkcs8 -in <path to private key> -inform PEM -outform DER -topk8 -nocrypt | openssl sha1 -c
#MD5 (AWS Display RSA Key Type that import to AWS)
openssl rsa -in <path to private key> -pubout -outform DER | openssl md5 -c
ssh-keygen -l -E md5 -f <path to private key>
#SHA256 (AWS Display ED25519 Key Type)
ssh-keygen -l -f <path to private key>
```
- Check Connection certificate
```bash
openssl s_client -connect <URL without https>:<port number> -showcerts
```
#### Rsync
```bash
rsync -avhe ssh --progress <source path> <SSH Hostname/IP>:<destination path>
```
#### SSH
```bash
#ssh local port forward with 2 ports
ssh -L <localport1>:localhost:<remote machine service port1> -L <localport2>:localhost:<remote machine service port2>  <username>@<remote machine> -i <private key path>
#sshfs connection
sshfs -o allow_other -o ro,IdentityFile=<path to private key> <ssh username>@<ssh host>:<remote path> <localpath>
```
### Loop
#### For
#### While

### Mail
```bash
echo "<Body>" | mutt -s "<Subject>" <Recipient mail> -a <attachment>
mail -s <subject> <Recipient mail>
```
### Package Manger
- apt
- dpkg
- yum
- rpm

### Screen and Tmux
- Screen
 1. Ctrl + a + c -- Create new window
 2. Ctrl + a + " -- List all window 
 3. Ctrl + a + \<num\> -- Switch to window number
 4. Ctrl + a + n -- Next Window
 5. Ctrl + a + p -- Previous Window
 6. Ctrl + a + Shift + a -- Rename current window 
 7. Ctrl + a + Shift + S -- Split horizontal
 8. Ctrl + a + | -- Split vertical
 9. Ctrl + a + tab -- Switch the cursor to another region
 10. Ctrl + a + Shift + q -- Close all region but keep current
 11. Ctrl + a + Shift + x -- Close the current region
 12. Ctrl + a + d -- detach window
 13. Ctrl + a + Shift + h -- Activate logging and will save to home directory
 14. Ctrl + a + k -- Kill screen window
 15. Ctrl + a + \[ -- Enter Copy mode, move your cursor to start text -> press space -> highlight range -> press space again -> Esc
 16. Ctrl + a + \] -- Enter Paste
 17. Ctrl +a + Esc -- Enter Scrolling mode and use arrow key to start scrolling, can use less pager style also
	
```bash
#Start a Name Session
screen -S <session name>
#Reattach an existing screen session
screen -r
screen -r <session number from screen -ls>
#Reattach an existing attach screen
screen -dr
#Listing screen session
screen -ls
#Activate logging
screen -L
#Entering the existing session (Multi user in same screen)
screen -x <session name>
```
- Tmux
```bash
```
### Databases
#### MySQL
```bash
#Check Uptime
mysqladmin status
#Using MySQL Client to connect MySQL Server
mysql -u <username> -p  <database> -h <ip>
#Dumping Logical Backup
mysqldump --routines --triggers --single-transaction -u <user> -p  <database>
#Dumping Logical Backup with compress output and timestamp in file name
mysqldump --routines --triggers --single-transaction -u <user> -p  <database> | gzip -9 > <name>-$(date +%Y%m%d-%H%M%S).tar.gz

#Read the compress file with pager
zcat <name>-<timestamp>.tar.gz | less
#View Binary Log
mysqlbinlog <bin log file> --base64-output=DECODE-ROWS
```

# Windows
## PowerShell
### Download Files
```powershell
Invoke-WebRequest -UseBasicParsing "<URL>" -OutFile <filename>
Start-BitsTransfer -Source "<URL>" -Destination <filename>
```
### Check Public IP
```powershell
$(Invoke-WebRequest -UseBasicParsing "https://ifconfig.me").RawContent
```
### Here docs
```powershell
# Using double quote may not escape text that have dollar symbol
$CONTENT = @'
<Content of the file>
'@

Set-Content "<Path>" $CONTENT
```
### Port Test
```powershell
Test-NetConnection <url/ip> -p <port number>
```
### Start-Process
```powershell
# Start a process and wait it continue only proceed to next step
Start-Process -FilePath <path for binary> -Args "<Argument to pass>" -Wait
```
### Check Process Command Line
```powershell
Get-WmiObject Win32_Process -Filter "Name='<process name>.exe'" | select-object commandline
Get-WmiObject Win32_Process -Filter "name = '<process name>.exe'" | Format-Table -Property CommandLine -AutoSize | Out-String -Width 4096 | Select-String -Pattern '<key word>'
Get-WmiObject Win32_Process | Select-Object ProcessId, CommandLine | Where-Object -Property CommandLine -like "*<key word>*"
```
### Robocopy
```powershell
robocopy \\<source directory> <destination directory> /E /R:5 /W:5 /TBD /V /MT:64 /B
```
### Refresh Shell Environment
```powershell
$env:path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
```
### Filtering Command Output Text
```powershell
Get-Process | Select-String "<Pattern>"
Get-Service| Out-String -stream | Select-String -Pattern "<Pattern>"
```
### HyperV
```powershell
# Set VM to have nested CPU feature
Set-VMProcessor -VMName <Name of the VM>  -ExposeVirtualizationExtensions $true

```
### msbuild
```powershell
#Build with command
msbuild <path to csproj> /p:Configuration=Release /p:Platform=x64 /p:OutputPath=<artifact folder name>
```
### dotnet
```powershell
# Add NuGet Source
dotnet nuget add source  "<URL>" -n "<Name>"
# Restore NuGet Packages
dotnet nuget restore
# Build a csproj file
dotnet build "<path to csproj>" -c Release -o <artifacts folder name>

```
### nuget
```powershell
# Add NuGet Source
nuget sources add -Name "<Name>" -Source <URL>
# Restore NuGet packages
nuget restore
# Add repository api key
nuget setapikey "<api key value>" -Source <URL>
```
```
```
## Cmd
### net use
```bat
net use <drive letter>: \\<UNC Path/IP>\<ShareName> /user:<username>
net use <drive letter>: /delete
```
### netsh
```bat
::adjust mtu value
netsh interface ipv4 show subinterface
netsh interface ipv4 set subinterface “<Name of the interface>” mtu=<mtu value> store=persistent

::port forward (TCP only), connect address cannot  be loopback address
::show current port forward rules
netsh interface portproxy show all
::reset/ remove all port forward rules
netsh interface portproxy reset
::add port forward port 9000
netsh interface portproxy add v4tov4 listenaddress=127.0.0.1 listenport=9000 connectaddress=192.168.0.10 connectport=80
::delete port forward 3340
netsh interface portproxy delete v4tov4 listenport=3340 listenaddress=10.1.1.110

```



# FortiOS
- Sniffer
  ```sh
  diagnose sniffer packer <interface> "port <port number>"
  # available value --> port, host
  ```
- Ping
  ```sh
  #change ping source ip
  execute ping --option source <source ip>
  #then start ping command
  execute ping <ip address>
  ```
- HA
  ```sh
  #trigger ha synchronization
  execute ha synchorize start
  #check ha status
  get system ha status
  #diagnose ha synchronization isue
  diagnose sys ha
  #Manage another ha unit via Cli
  execute ha manage <id>
  ```
- PPPOE
  ```sh
  #manual trigger pppoe connection
  execute interface pppoe-reconnect <interface name>
  ```
- Top
  ```sh
  diagnose sys top 1 10
  ```
- SSL VPN
  ```sh
  #add user with email as 2FA
  config user local
  edit "<username>"
  set two-factor email
  set email-to <email address>
  end
  #ssl vpn monitor (check ssl vpn connection)
  get vpn ssl monitor

  ```
- Debug
  ```sh
  #clear debug settings
  diag debug reset
  #turn on debugging
  diagnose debug enable
  diagose debug console timestamp enable
  diagose debug application <application name> -1
  #available value pppoed hasync hatalk
  diagose debug disable
  ```
  - Interface MTU
  ```sh
  #Normally MTU was 1500, may try 1496 or 1472
  config system interface
	  edit <interface name>
		  set mtu-override enable
		  set mtu <mtu value>
  end
  ```
# MacOS
## Relaunch Finder if it hung
- Option Key -> Right Click Finder -> Relaunch Finder
- Click Apple Icon -> Hold Shift Key -> Force Quit Finder
- Open Terminal then type
```sh
killall Finder
```
  # AWS
  ## Cli
  ## RDS
  - Microsoft SQL Server
  ```sql
  #ONLINE a database
  EXEC rdsadmin.dbo.rds_set_database_online `<DB Name>`
  #Rename a database
  EXEC rdsadmin.dbo.rds_modify_db_name N'<DB Name>', N'<New Name>' 
  GO
  
  ```
  

