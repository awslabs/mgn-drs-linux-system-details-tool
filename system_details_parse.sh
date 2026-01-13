#!/bin/bash

# Script version: 1.6

banner_text=$(cat <<EOF

============================================
 System Details Gathering Script
============================================
This script gathers various system details and logs them to /var/log/system_details.log.

It checks the following:

1. General System Information:
   - OS release information
   - Kernel version
   - Hostname and system time
   - Network configuration and routing
   - Firewall rules
   - System services
   - System hardware details
   - Recent shutdown and reboot history
   - Proxy environment variables

2. Disks / Devices / LVM / Multipath / Mount / Memory / Drivers/Modules:
   - Boot device
   - Block Devices and Filesystems
   - Partition Tables
   - Logical Volume Manager (LVM) details
   - Disks with size less than 1G
   - Multipath and Device Mapper Information
   - Mounted filesystems
   - Disk usage
   - Memory usage
   - Loaded kernel modules

3. Directories:
   - Kernel source directories
   - Module directories
   - GRUB configuration directories
   - EFI system details

4. SELinux:
   - SELinux status and configuration

5. BIOS / UEFI / SecureBoot:
   - Boot mode (UEFI or Legacy BIOS)
   - EFI boot manager details
   - UEFI variables
   - Secure Boot status

6. GRUB Configuration Files:
   - GRUB configuration files and environment

7. Packages:
   - Required tools
   - Installed GRUB2 packages
   - Installed kernel packages
   - Installed mkinitrd and dracut packages
   - Installed and available Linux headers

8. Initramfs/initrd/Drivers:
   - Initramfs/initrd contents
   - Kernel module information

9. Replication Agent:
   - AWS replication agent details (if installed)
   - Running processes related to AWS replication Agent
   - Network connections related to AWS replication Agent
   - Replication server instances list

10. Permissions:
   - File attributes and permissions for critical files
   - Sudoers configuration
   - User and group information for 'aws-replication'
   - The presence and permissions of 'su' and 'sudo'

11. Endpoint Connectivity:
    - Checks connectivity to service-specific endpoints (MGN or DRS)
    - Tests all required S3 bucket endpoints
    - Tests connection using OpenSSL or curl
============================================

EOF
)

# Function to check if the system is using systemd or sysvinit
check_init_system() {
    if command -v systemctl &> /dev/null; then
        echo "systemd"
    elif command -v chkconfig &> /dev/null; then
        echo "sysvinit"
    else
        echo "unknown"
    fi
}

# Function to display the description and the command output
log_command() {
    local description=$1
    local command=$2

    {
        echo -e "===== ${description} : ===== \n" 
    } >> /var/log/system_details.log 2>&1
    eval "${command}" >> /var/log/system_details.log 2>&1
    echo -e "\n\n" >> /var/log/system_details.log 2>&1
}

# Function to display the description and the command output for initramfs/initrd
log_command_initramfs() {
    local initramfs_file=$1
    local description=$2
    local command=$3

    echo -e "===== ${description} : ===== \n" >> /var/log/system_details.log 2>&1
    if [ -e "${initramfs_file}" ]; then
        eval "${command}" >> /var/log/system_details.log 2>&1
    else
       echo -e "${initramfs_file}: No such file or directory" >> /var/log/system_details.log 2>&1
    fi
    echo -e "\n\n" >> /var/log/system_details.log 2>&1
}

# Function to check which OS firewall is installed and display its rules
check_os_firewall() {
    local found_firewall=false

    # Check for iptables
    if command -v iptables &> /dev/null; then
        log_command "iptables -L -v -n" "iptables -L -v -n" 
        found_firewall=true
    fi

    # Check for firewalld
    if command -v firewall-cmd &> /dev/null; then
        log_command "firewall-cmd --list-all" "firewall-cmd --list-all" 
        found_firewall=true
    fi

    # Check for ufw
    if command -v ufw &> /dev/null; then
        log_command "ufw status verbose" "ufw status verbose" 
        found_firewall=true
    fi

    # If no firewall is found
    if [ "$found_firewall" = false ]; then

        {
            echo -e "===== Verification if one of these firewalls is installed: 'iptables', 'firewalld', 'ufw' : ===== \n" 
        } >> /var/log/system_details.log 2>&1
        echo -e "None of these firewalls ('iptables', 'firewalld', 'ufw') are installed." >> /var/log/system_details.log 2>&1
        echo -e "\n\n" >> /var/log/system_details.log 2>&1
    fi
}

# Function to check if there is any disk with size less than 1GiB
check_disks_under_1GiB() {
    # Set the minimum disk size threshold (1 GiB in bytes)
    MIN_DISK_SIZE_GiB=1073741824
    MIN_DISK_SIZE_GB=1000000000

    # Get the list of disks excluding loop devices
    disks=$(lsblk -n -o NAME,SIZE,TYPE | grep -v 'loop' | awk '$3 == "disk" {print $1, $2}')

    # Loop through each disk and check size
    while IFS= read -r line; do
        # Extract disk name and size
        disk_name=$(echo "$line" | awk '{print $1}')
        disk_size=$(echo "$line" | awk '{print $2}')

        # Skip empty disk sizes
        if [ -z "$disk_size" ]; then
            continue
        fi

        # Convert disk size to bytes (assuming human-readable format, e.g., 477G, 20M, etc.)
        disk_size_bytes=$(echo "$disk_size" | awk 'BEGIN{IGNORECASE = 1} function printpower(n,b,p) {printf "%u\n", n*b^p; next} \
        /[0-9]$/{print $1;next}; \
        /K(iB)?$/{printpower($1, 2, 10)}; \
        /M(iB)?$/{printpower($1, 2, 20)}; \
        /G(iB)?$/{printpower($1, 2, 30)}; \
        /T(iB)?$/{printpower($1, 2, 40)}; \
        /KB$/{ printpower($1, 10, 3)}; \
        /MB$/{ printpower($1, 10, 6)}; \
        /GB$/{ printpower($1, 10, 9)}; \
        /TB$/{ printpower($1, 10, 12)}')

        # Check if disk size is less than minimum threshold
        if (( disk_size_bytes < MIN_DISK_SIZE_GiB || disk_size_bytes < MIN_DISK_SIZE_GB )); then
            {
                echo "WARNING: Disk '$disk_name' has size '$disk_size', which is less than minimum threshold of 1 GiB"
            } >> /var/log/system_details.log 2>&1
            echo -e "\n\n" >> /var/log/system_details.log 2>&1
        fi
    done <<< "$disks"
}

# Function to verify the boot device 
check_boot_device() {
    { 
        echo -e "===== Boot device is : ===== \n" 
    } >> /var/log/system_details.log 2>&1

    # First try: Find disk that hosts /boot mount point directly
    boot_partition=$(df /boot | tail -1 | awk '{print $1}')
    disk_name=""
    
    if [ -n "$boot_partition" ]; then
        # Get parent disk from partition
        disk_name=$(lsblk -no pkname "$boot_partition" 2>/dev/null)
        
        if [ -n "$disk_name" ]; then
            echo "Boot disk determined from /boot mount point: $disk_name" >> /var/log/system_details.log 2>&1
            lsblk -no NAME,MAJ:MIN,RM,SIZE,RO,TYPE | grep "^$disk_name" >> /var/log/system_details.log 2>&1
        fi
    fi

    # Second try: Fall back to root mount if /boot wasn't found or didn't yield a disk
    if [ -z "$disk_name" ]; then
        root_partition=$(df / | tail -1 | awk '{print $1}')
        
        if [ -n "$root_partition" ]; then
            disk_name=$(lsblk -no pkname "$root_partition" 2>/dev/null)
            
            if [ -n "$disk_name" ]; then
                echo "Boot disk determined from / mount point: $disk_name" >> /var/log/system_details.log 2>&1
                lsblk -no NAME,MAJ:MIN,RM,SIZE,RO,TYPE | grep "^$disk_name" >> /var/log/system_details.log 2>&1
            fi
        fi
    fi

    # Third try: Look for bootable flag in fdisk output
    if [ -z "$disk_name" ]; then
        # Try standard disks first
        fdisk_output=$(fdisk -l 2>/dev/null | grep -E '^/dev/[hsv]d[a-z][0-9]' | grep '*' | head -1)
        if [ -n "$fdisk_output" ]; then
            boot_part=$(echo "$fdisk_output" | awk '{print $1}')
            disk_name=$(echo "$boot_part" | sed -r 's|/dev/([hsv]d[a-z])[0-9]+|\1|')
            
            echo "Boot disk determined from bootable flag: $disk_name" >> /var/log/system_details.log 2>&1
            echo "$fdisk_output" >> /var/log/system_details.log 2>&1
        else
            # Try NVMe disks
            fdisk_nvme=$(fdisk -l 2>/dev/null | grep -E '^/dev/nvme[0-9]+n[0-9]+p[0-9]+' | grep '*' | head -1)
            if [ -n "$fdisk_nvme" ]; then
                boot_part=$(echo "$fdisk_nvme" | awk '{print $1}')
                # Handle NVMe disk naming carefully, extracting 'nvme0n1' from '/dev/nvme0n1p1'
                disk_name=$(echo "$boot_part" | sed -E 's|/dev/(nvme[0-9]+n[0-9]+)p[0-9]+|\1|')
                
                echo "Boot disk determined from NVMe bootable flag: $disk_name" >> /var/log/system_details.log 2>&1
                echo "$fdisk_nvme" >> /var/log/system_details.log 2>&1
            fi
        fi
    fi

    # If all methods failed
    if [ -z "$disk_name" ]; then
        echo "Script was not able to detect the boot device" >> /var/log/system_details.log 2>&1
    fi
    
    echo -e "\n\n" >> /var/log/system_details.log 2>&1
    
    # Call function to check Grub on boot disk if we found a disk
    if [ -n "$disk_name" ]; then
        check_grub_installation "$disk_name"
    fi
}

check_grub_installation() {
    local disk_name="$1"  # This should now be just the disk name (e.g., "sda" or "nvme0n1")
    local full_disk_path="/dev/${disk_name}"

    echo -e "===== GRUB on Boot disk : ===== \n" >>/var/log/system_details.log 2>&1
    echo "Disk name: $disk_name" >>/var/log/system_details.log 2>&1
    echo "Checking GRUB installation on $full_disk_path" >>/var/log/system_details.log 2>&1
    echo -e "\n" >> /var/log/system_details.log 2>&1
    
    if [ -e "$full_disk_path" ]; then
        { dd if="$full_disk_path" bs=512 count=1 2>/dev/null | hexdump -v -C ; } >>/var/log/system_details.log 2>&1
    else
        echo "Error: Device $full_disk_path does not exist" >>/var/log/system_details.log 2>&1
    fi
    
    echo -e "\n\n" >> /var/log/system_details.log 2>&1
}


# Function to check GRUB installation and version
check_grub_installation_version() {
    {
        echo -e "===== GRUB Installation and Version Check : ===== \n"
        
        if command -v grub-install &> /dev/null; then
            echo "GRUB is installed (grub-install found)\n"
            echo "--> GRUB Version:"
            grub-install --version
            echo -e "\n"
             
        elif command -v grub2-install &> /dev/null; then
            echo "GRUB2 is installed (grub2-install found)\n"
            echo "--> GRUB2 Version:"
            grub2-install --version
            echo -e "\n"
            
        else
            echo "Warning: Neither grub-install nor grub2-install was found on the system\n"
        fi
        
        # Check for GRUB modules directory
        #echo -e "** GRUB Modules Directory Check: **"
        for dir in "/usr/lib/grub" "/usr/lib/grub2" "/boot/grub" "/boot/grub2" "/usr/lib/grub/x86_64-efi/"; do
            echo -e "===== ls -lah $dir =====\n"
            ls -lah $dir
            echo -e "\n"
        done
        
        echo -e "\n"
    } >> /var/log/system_details.log 2>&1
}


# Check the list of Replication Server instances
replication_servers_list() {
    local logfile="/var/lib/aws-replication-agent/agent.log.0"
    local output_file="/var/log/system_details.log"

    {
        echo -e "===== Replication Server instances list : ===== \n"

        # Print header with formatting
        printf "%-30s %-20s\n" "TIMESTAMP" "REPLICATION SERVER"
        printf "%-30s %-20s\n" "$(printf '=%.0s' {1..30})" "$(printf '=%.0s' {1..20})"

        while IFS= read -r line; do
            # Extract timestamp
            timestamp=$(echo "$line" | grep -o '"@timestamp":"[^"]*"' | cut -d'"' -f4)
            # Extract instance ID
            instance_id=$(echo "$line" | grep -o '"args":\["[^"]*"' | grep -o 'i-[a-z0-9]*')
            if [ ! -z "$timestamp" ] && [ ! -z "$instance_id" ]; then
                printf "%-30s %-20s\n" "$timestamp" "$instance_id"
            fi
        done < <(grep "Connecting to replicator {0}" "$logfile")
        echo -e "\n"

    } >> "$output_file" 2>&1
}

# Endpoints connectivity check
REGION=""
SERVICE=""

usage() {
    echo "Usage: $0 --region <region> --service <service>"
    echo "  --region: AWS region (e.g., us-east-1)"
    echo "  --service: Service type (mgn or drs)"
    echo ""
    echo "Example:"
    echo "  $0 --region us-east-1 --service mgn"
    echo "  $0 --region eu-west-1 --service drs"
    exit 1
}

# Parameter parsing
while [[ $# -gt 0 ]]; do
    case $1 in
        --region)
            REGION="$2"
            shift 2
            ;;
        --service)
            SERVICE="$2"
            shift 2
            ;;
        *)
            echo "Unknown parameter: $1"
            usage
            ;;
    esac
done

# Validate parameters
if [[ -z "$REGION" ]] && [[ -z "$SERVICE" ]]; then
    echo "Error: Both --region and --service parameters are required"
    usage
elif [[ -z "$REGION" ]]; then
    echo "Error: --region parameter is required"
    usage
elif [[ -z "$SERVICE" ]]; then
    echo "Error: --service parameter is required"
    usage
fi

# Validate service parameter
if [[ "$SERVICE" != "mgn" ]] && [[ "$SERVICE" != "drs" ]]; then
    echo "Error: --service must be either 'mgn' or 'drs'"
    echo "You provided: $SERVICE"
    usage
fi

# Function for Endpoints connectivity check
check_endpoints_connectivity() {
    local service=$1
    local region=$2
    
    log_command "Checking connectivity to $service endpoints in region $region" "echo 'Starting endpoint connectivity check...'"
    
    declare -a endpoints

    if [ "$service" == "mgn" ]; then
        endpoints=(
            "mgn.$region.amazonaws.com"
            "aws-mgn-clients-$region.s3.$region.amazonaws.com"
            "aws-mgn-clients-hashes-$region.s3.$region.amazonaws.com"
            "aws-mgn-internal-$region.s3.$region.amazonaws.com"
            "aws-mgn-internal-hashes-$region.s3.$region.amazonaws.com"
            "aws-application-migration-service-$region.s3.$region.amazonaws.com"
            "aws-application-migration-service-hashes-$region.s3.$region.amazonaws.com"
            "amazon-ssm-$region.s3.$region.amazonaws.com"
        )
    elif [ "$service" == "drs" ]; then
        endpoints=(
            "drs.$region.amazonaws.com"
            "aws-drs-clients-$region.s3.$region.amazonaws.com"
            "aws-drs-clients-hashes-$region.s3.$region.amazonaws.com"
            "aws-drs-internal-$region.s3.$region.amazonaws.com"
            "aws-drs-internal-hashes-$region.s3.$region.amazonaws.com"
            "aws-elastic-disaster-recovery-$region.s3.$region.amazonaws.com"
            "aws-elastic-disaster-recovery-hashes-$region.s3.$region.amazonaws.com"
        )
    fi

    # Check if either openssl or curl is installed
    if ! command -v openssl >/dev/null 2>&1 && ! command -v curl >/dev/null 2>&1; then
        log_command "ERROR: Required tools check" "echo 'Neither OpenSSL nor curl is installed. Cannot check endpoint connectivity. Please install either openssl or curl to perform connectivity checks.'"
        return 1
    fi

    for endpoint in "${endpoints[@]}"; do
        if command -v openssl >/dev/null 2>&1; then
            log_command "Testing connectivity to '$endpoint' using OpenSSL" "echo -n | openssl s_client -connect $endpoint:443 2>&1"
        else
            log_command "Testing connectivity to '$endpoint' using curl" "curl -v -k https://$endpoint 2>&1"
        fi
    done
}


# Display the banner
echo "$banner_text"

LOG_FILE="/var/log/system_details.log"
REP_AGENT_HOME=/var/lib/aws-replication-agent 

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "Please execute this script using 'sudo' or with user 'root'"
    exit 1
fi

# Remove the old log file if it exists
rm -f "$LOG_FILE"

# Start gathering system details
echo -e "\n Gathering info ...\n"

echo -e "-------------------------------------\n"

{
    echo -e "\n===============================================================" 
    echo -e "Attempt: $(date +"%Y-%m-%d-%T")"
    echo -e "Script version: 1.6"
    echo -e "==============================================================="
} >> "$LOG_FILE" 2>&1
echo -e "\n" >> "$LOG_FILE" 2>&1


echo -e "\n <<<<<<<<<<<<<<<<<<<<<<<<<< General details >>>>>>>>>>>>>>>>>>>>>>>>>> \n\n" >> "$LOG_FILE" 2>&1

log_command "cat /etc/os-release" "cat /etc/os-release"
log_command "uname -r" "uname -r"
log_command "uname -a" "uname -a"
log_command "hostnamectl" "hostnamectl"
log_command "timedatectl" "timedatectl"
log_command "chronyc tracking" "chronyc tracking"
log_command "ip a" "ip a"
log_command "route -n || ip route" "route -n || ip route"
log_command "cat /etc/hosts" "cat /etc/hosts"
log_command "cat /etc/resolv.conf" "cat /etc/resolv.conf"
log_command "ls -l /etc/resolv.conf" "ls -l /etc/resolv.conf"
log_command "lsattr /etc/resolv.conf" "lsattr /etc/resolv.conf"
log_command "NetworkManager --print-config" "NetworkManager --print-config"
check_os_firewall

# Check init system and log appropriate command
init_system=$(check_init_system)

if [ "$init_system" == "systemd" ]; then
    log_command "systemctl" "systemctl"
    log_command "systemctl list-unit-files --type=service --state=enabled" "systemctl list-unit-files --type=service --state=enabled"
    log_command "systemctl --failed" "systemctl --failed"
elif [ "$init_system" == "sysvinit" ]; then
    log_command "chkconfig --list" "chkconfig --list"
else
    echo -e "Unknown init system. Skipping service list.\n" >> "$LOG_FILE" 2>&1
fi

log_command "dmidecode -t system" "dmidecode -t system"
log_command "arch" "arch"
log_command "lscpu | egrep -i Virtualization" "lscpu | egrep -i Virtualization"
log_command "last -Fxn10 shutdown reboot" "last -Fxn10 shutdown reboot"
log_command "env | grep -i proxy" "env | grep -i proxy"


echo -e "\n <<<<<<<<<<<<<<<<<<<<<<<<<< Disks / Devices / LVM / Multipath / Mount / Memory / Drivers/Modules >>>>>>>>>>>>>>>>>>>>>>>>>> \n\n" >> "$LOG_FILE" 2>&1

check_boot_device
log_command "lsblk -o +FSTYPE,UUID" "lsblk -o +FSTYPE,UUID"
check_disks_under_1GiB
log_command "blkid" "blkid"
log_command "fdisk -l" "fdisk -l"
log_command "parted -ls" "parted -ls"
log_command "fstab" "cat /etc/fstab"
log_command "pvs" "pvs"
log_command "vgs" "vgs"
log_command "lvs" "lvs"
log_command "pvdisplay -vv" "pvdisplay -vv"
log_command "vgdisplay -v" "vgdisplay -v"
log_command "lvdisplay -vm" "lvdisplay -vm"
log_command "ls -lartR /dev/mpath" "ls -lartR /dev/mpath"
log_command "ls -lartR /dev/mapper" "ls -lartR /dev/mapper"
log_command "multipath -ll" "multipath -ll"
log_command "find /sys/block -ls" "find /sys/block -ls"
log_command "find /dev/mapper -ls" "find /dev/mapper -ls"
log_command "powermt display dev=all" "powermt display dev=all"
log_command "lspci" "lspci"
log_command "mount" "mount"
log_command "mount | grep /tmp" "mount | grep /tmp"
log_command "df -hT" "df -hT"
log_command "df -hT /boot" "df -hT /boot"
log_command "df -hT /var" "df -hT /var"
log_command "df -hT /tmp" "df -hT /tmp"
log_command "free -h" "free -h"
log_command "lsmod" "lsmod"
log_command "ls -lart /dev" "ls -lart /dev"
log_command "ls -l /sys/module/" "ls -l /sys/module/" 
log_command "ls -la /etc/udev/rules.d/" "ls -la /etc/udev/rules.d/"
log_command "tail -n +1 /etc/udev/rules.d/*" "tail -n +1 /etc/udev/rules.d/*"
log_command "grep -vE '^\s*#|^\s*$' /etc/lvm/lvm.conf" "grep -vE '^\s*#|^\s*$' /etc/lvm/lvm.conf" 


echo -e "\n <<<<<<<<<<<<<<<<<<<<<<<<<< Directories >>>>>>>>>>>>>>>>>>>>>>>>>> \n\n"  >> "$LOG_FILE" 2>&1

log_command "ls -lah /boot" "ls -lah /boot"
log_command "ls -lah /usr/src/" "ls -lah /usr/src/"
log_command "ls -lah /usr/src/kernels/" "ls -lah /usr/src/kernels/"
log_command "ls -lah /usr/src/kernels/*" "ls -lah /usr/src/kernels/*"
log_command "ls -lah /lib/modules" "ls -lah /lib/modules"
log_command "ls -lah /lib/modules/*" "ls -lah /lib/modules/*"
log_command "ls -lah /lib/modules/*/build" "ls -lah /lib/modules/*/build"


echo -e "\n <<<<<<<<<<<<<<<<<<<<<<<<<< SELinux >>>>>>>>>>>>>>>>>>>>>>>>>> \n\n"  >> "$LOG_FILE" 2>&1

log_command "SELinux : getenforce" "getenforce"
log_command "cat /etc/sysconfig/selinux" "cat /etc/sysconfig/selinux"


echo -e "\n <<<<<<<<<<<<<<<<<<<<<<<<<< BIOS / UEFI / SecureBoot >>>>>>>>>>>>>>>>>>>>>>>>>> \n\n" >> "$LOG_FILE" 2>&1

log_command "[ -d /sys/firmware/efi ] && echo 'UEFI Boot Detected' || echo 'Legacy BIOS Boot Detected'" "[ -d /sys/firmware/efi ] && echo 'UEFI Boot Detected' || echo 'Legacy BIOS Boot Detected'"
log_command "efibootmgr -v" "efibootmgr -v"
log_command "ls -ld /sys/firmware/efi/" "ls -ld /sys/firmware/efi/"
log_command "ls -la /sys/firmware/efi/" "ls -la /sys/firmware/efi/"
log_command "ls -la /sys/firmware/efi/efivars" "ls -la /sys/firmware/efi/efivars"
log_command "/usr/bin/mokutil --sb-state || mokutil --sb-state" "/usr/bin/mokutil --sb-state || mokutil --sb-state"


echo -e " <<<<<<<<<<<<<<<<<<<<<<<<<< GRUB Configuration Files >>>>>>>>>>>>>>>>>>>>>>>>>> \n\n"  >> "$LOG_FILE" 2>&1

# Check if each GRUB configuration file exists before logging its content
grub_files=(
    "/boot/grub/grub.conf"
    "/boot/grub/grub.cfg"
    "/boot/grub2/grub.cfg"
    "/boot/grub2/grub.conf"
    "/boot/grub/menu.lst"
    "/etc/default/grub"
    "/proc/cmdline"
    "/boot/grub/grubenv"
    "/boot/grub2/grubenv"
)

for grub_file in "${grub_files[@]}"; do
    if [ -e "$grub_file" ]; then
        log_command "cat $grub_file" "cat $grub_file"
    fi
done

check_grub_installation_version

echo -e " <<<<<<<<<<<<<<<<<<<<<<<<<< Packages >>>>>>>>>>>>>>>>>>>>>>>>>> \n\n"   >> "$LOG_FILE" 2>&1

tools=(
    make 
    gcc 
    perl 
    tar 
    gawk
)
for tool in "${tools[@]}"; do
     log_command "$tool --version" "$tool --version"
done

log_command "python --version ; python3 --version" "python --version ; python3 --version"
log_command "rpm -aq | egrep -i 'dhclient|dhcp'" "rpm -aq | egrep -i 'dhclient|dhcp'" 
log_command "apt list --installed | egrep -i 'dhclient|dhcp' (----- Debian/Ubuntu -----)" "apt list --installed | egrep -i 'dhclient|dhcp'" 
log_command "rpm -aq | grep grub2-pc-modules" "rpm -aq | grep grub2-pc-modules"
log_command "rpm -aq | grep grub2-i386-pc (----- SUSE -----)" "rpm -aq | grep grub2-i386-pc"
log_command "apt list --installed | grep grub-pc* (----- Debian/Ubuntu -----)" "apt list --installed | grep grub-pc*" 
log_command "rpm -qa | grep mkinitrd" "rpm -qa | grep mkinitrd"
log_command "rpm -qa | grep dracut" "rpm -qa | grep dracut" 
log_command "rpm -qa | grep elfutils-libelf-devel (----- RHEL 8/CentOS 8/OL 8 -----)" "rpm -qa | grep elfutils-libelf-devel"
log_command "rpm -qa | grep xen-kmp-default (----- SUSE 11 SP4 -----)" "rpm -qa | grep xen-kmp-default" 

### Installed kernels
log_command "rpm -aq kernel" "rpm -aq kernel" 
log_command "rpm -aq | grep kernel" "rpm -aq | grep kernel"
log_command "apt list --installed | grep linux-image" "apt list --installed | grep linux-image"

### Installed kernel-devel/linux-headers
log_command "rpm -aq  | grep kernel-devel (----- RHEL/CENTOS/Oracle/AL -----)" "rpm -aq  | grep kernel-devel"
log_command "rpm -aq | grep kernel-default-devel (----- SUSE -----)" "rpm -aq | grep kernel-default-devel" 
log_command "apt list --installed | grep linux-headers (----- Debian/Ubuntu -----)" "apt list --installed | grep linux-headers" 
log_command "rpm -aq | grep kernel-uek-devel (----- Oracle with Unbreakable Enterprise Kernel -----)" "rpm -aq | grep kernel-uek-devel" 

### Available kernel-devel/linux-headers
log_command "yum list --showduplicates kernel-devel | expand (----- RHEL/CENTOS/Oracle/AL -----) " "yum list --showduplicates kernel-devel | expand"
log_command "zypper search -s kernel-default-devel* (----- SUSE -----)" "zypper search -s kernel-default-devel*"
log_command "apt-cache search linux-headers (----- Debian/Ubuntu -----)" "apt-cache search linux-headers"
log_command "yum list --showduplicates kernel-uek-devel | expand (----- Oracle with Unbreakable Enterprise Kernel -----) " "yum list --showduplicates kernel-uek-devel | expand"


echo -e " <<<<<<<<<<<<<<<<<<<<<<<<<< Initramfs/initrd/Drivers  >>>>>>>>>>>>>>>>>>>>>>>>>> \n\n"  >> "$LOG_FILE" 2>&1

# Check if lsinitramfs or lsinitrd is installed
if command -v lsinitramfs &> /dev/null; then
    INITRD_CMD="lsinitramfs"
elif command -v lsinitrd &> /dev/null; then
    INITRD_CMD="lsinitrd"
else
    echo "Neither lsinitramfs nor lsinitrd is installed..."
    exit 1
fi

grep_mod="egrep -i 'xen|nvme|ena|lvm'"

log_command "$INITRD_CMD | egrep -i 'xen|nvme|ena|lvm'" "$INITRD_CMD | $grep_mod"

log_command_initramfs "/boot/aws-launch-initramfs-$(uname -r).img" "$INITRD_CMD /boot/aws-launch-initramfs-$(uname -r).img | $grep_mod" "$INITRD_CMD /boot/aws-launch-initramfs-$(uname -r).img | $grep_mod"
log_command_initramfs "$REP_AGENT_HOME/aws-launch-initramfs-$(uname -r).img" "$INITRD_CMD $REP_AGENT_HOME/aws-launch-initramfs-$(uname -r).img | $grep_mod" "$INITRD_CMD $REP_AGENT_HOME/aws-launch-initramfs-$(uname -r).img | $grep_mod"
log_command_initramfs "/boot/aws-launch-initrd-$(uname -r)" "$INITRD_CMD /boot/aws-launch-initrd-$(uname -r) | $grep_mod (----- SUSE -----)" "$INITRD_CMD /boot/aws-launch-initrd-$(uname -r) | $grep_mod"
log_command_initramfs "$REP_AGENT_HOME/aws-launch-initrd-$(uname -r)" "$INITRD_CMD $REP_AGENT_HOME/aws-launch-initrd-$(uname -r) | $grep_mod (----- SUSE -----)" "$INITRD_CMD $REP_AGENT_HOME/aws-launch-initrd-$(uname -r) | $grep_mod"
log_command_initramfs "/boot/aws-launch-initrd.img-$(uname -r)" "$INITRD_CMD /boot/aws-launch-initrd.img-$(uname -r) | $grep_mod (----- Debian -----)" "$INITRD_CMD /boot/aws-launch-initrd.img-$(uname -r) | $grep_mod"
log_command_initramfs "$REP_AGENT_HOME/aws-launch-initrd.img-$(uname -r)" "$INITRD_CMD $REP_AGENT_HOME/aws-launch-initrd.img-$(uname -r) | $grep_mod (----- Debian -----)" "$INITRD_CMD $REP_AGENT_HOME/aws-launch-initrd.img-$(uname -r) | $grep_mod"

log_command "cat /proc/sys/kernel/modules_disabled" "cat /proc/sys/kernel/modules_disabled"
log_command "modinfo xen-netfront" "modinfo xen-netfront"
log_command "modinfo xen-blkfront" "modinfo xen-blkfront"
log_command "modinfo nvme_core" "modinfo nvme_core"
log_command "modinfo nvme" "modinfo nvme"
log_command "modinfo ena" "modinfo ena"


echo -e " <<<<<<<<<<<<<<<<<<<<<<<<<< Replication agent >>>>>>>>>>>>>>>>>>>>>>>>>> \n\n"  >> "$LOG_FILE" 2>&1

## Verify if there is an MGN or DRS replication agent installed

if [ -e "$REP_AGENT_HOME" ] ; then

        if grep -q "drs-clients" "$REP_AGENT_HOME/agent.config"; then
                echo -e "---> There is an 'AWS DRS' replication agent installed on this server <---\n\n" >> "$LOG_FILE" 2>&1
        elif grep -q "mgn-clients" "$REP_AGENT_HOME/agent.config"; then
                echo -e "---> There is an 'AWS MGN' replication agent installed on this server <---\n\n" >> "$LOG_FILE" 2>&1
        fi

        log_command "df -hT $REP_AGENT_HOME" "df -hT $REP_AGENT_HOME"
        log_command "ls -lah $REP_AGENT_HOME" "ls -lah $REP_AGENT_HOME"
        log_command "cat $REP_AGENT_HOME/agent.config" "cat $REP_AGENT_HOME/agent.config | sed 's/\(\"awsSecretAccessKey\": \"\)[^\"]*\"/\1************\"/'"
        log_command "cat $REP_AGENT_HOME/VERSION"  "cat $REP_AGENT_HOME/VERSION"
        log_command "cat $REP_AGENT_HOME/aws-replication-prepare.env"  "cat $REP_AGENT_HOME/aws-replication-prepare.env"
        log_command "modinfo aws_replication_driver" "modinfo aws_replication_driver"
        log_command "ps -u aws-replication" "ps -u aws-replication"
        log_command "ls -l /dev | grep aws_replication" "ls -l /dev | grep aws_replication"
        log_command "lsmod | grep aws_replication_driver" "lsmod | grep aws_replication_driver"
        log_command "ps -ef | grep aws- | grep -v grep | wc -l" "ps -ef | grep aws- | grep -v grep | wc -l"
        log_command "netstat -anp | grep -i ':1500'|| ss -anp | grep -i ':1500'" "netstat -anp | grep -i ':1500' || ss -anp | grep -i ':1500'"
        log_command "Active Internet connections (netstat -tupn || ss -tupn)" "netstat -tupn || ss -tupn"
        replication_servers_list

        if [ "$init_system" == "systemd" ]; then
            log_command "systemctl list-units --type=service | grep aws-replication" "systemctl list-units --type=service | grep aws-replication"
            log_command "systemctl status aws-replication-agent" "systemctl status aws-replication-agent"
            log_command "systemctl status aws-replication-run-migration-scripts" "systemctl status aws-replication-run-migration-scripts"
            log_command "systemctl status aws-replication-tailer" "systemctl status aws-replication-tailer"
            log_command "systemctl status aws-replication-update-volumes" "systemctl status aws-replication-update-volumes"
        fi

else
        echo -e "---> There is no AWS MGN or DRS replication agent installed on this server <---\n\n" >> "$LOG_FILE" 2>&1
fi
      

echo -e " <<<<<<<<<<<<<<<<<<<<<<<<<< Permissions >>>>>>>>>>>>>>>>>>>>>>>>>> \n\n"  >> "$LOG_FILE" 2>&1

log_command "lsattr /etc/passwd /etc/group /etc/shadow /etc/sudoers" "lsattr /etc/passwd /etc/group /etc/shadow /etc/sudoers"
log_command "grep aws-replication /etc/sudoers" "grep aws-replication /etc/sudoers"
log_command "tail -n +1 /etc/sudoers.d/*" "tail -n +1 /etc/sudoers.d/*"
log_command "ls -la /etc/sudoers.d/" "ls -la /etc/sudoers.d/"
log_command "id aws-replication" "id aws-replication"
log_command "chage -l aws-replication || passwd -S  aws-replication" "chage -l aws-replication 2> /dev/null || passwd -S aws-replication"
log_command "command -v su" "command -v su"
log_command "ls -l /bin/su | ls -l /usr/bin/su" "ls -l /bin/su | ls -l /usr/bin/su"
log_command "command -v sudo" "command -v sudo"
log_command "ls -l /bin/sudo | ls -l /usr/bin/sudo" "ls -l /bin/sudo | ls -l /usr/bin/sudo"
log_command "su aws-replication -c 'id -u'" "su aws-replication -c 'id -u'"
log_command "su aws-replication -c 'sudo id -u'" "su aws-replication -c 'sudo id -u'"
log_command "lsmod | grep CE_AgentDriver" "lsmod | grep CE_AgentDriver"


echo -e "\n <<<<<<<<<<<<<<<<<<<<<<<<<< Endpoints Connectivity Check >>>>>>>>>>>>>>>>>>>>>>>>>> \n\n" >> "$LOG_FILE" 2>&1

check_endpoints_connectivity "$SERVICE" "$REGION"

echo -e " -------------------------------------"   >> "$LOG_FILE" 2>&1
echo -e " -------------------------------------"   >> "$LOG_FILE" 2>&1

echo -e "Finished gathering info \n"
echo -e "Please attach '/var/log/system_details.log' to the Support ticket \n"
