#!/bin/bash
#
# Nextcloud install script
#
if [ "$USER" != "root" ]
then
    clear
    echo ""
    echo " » NOT ROOT"
    echo ""
    echo "--------------------------"
    echo " » Run this script as root"
    echo "--------------------------"
    echo ""
    exit 1
fi
# THESE VARIABLES MUST BE CONFIGURED!!!!!!!!!!!!

NEXTCLOUDDATAPATH="/data"
NEXTCLOUDADMINUSER="nc_admin"
NCRELEASE="latest.tar.bz2"
PHPVERSION="8.2"
LETSENCRYPT="y"
NEXTCLOUDDNS="group.stickynotes.work"
DATABASE="m"
NCDBUSER="ncdbuser"
CURRENTTIMEZONE='Europe/Berlin'
PHONEREGION='DE'
NEXTCLOUDOFFICE="n"
ONLYOFFICE="n"
UPLOADSIZE='10G'
APTIP4="n"
RESOLVER="176.9.93.198 176.9.1.117"
# VPSIPADDRESS=""

# Random passwords for security purposes

MARIADBROOTPASSWORD=$(openssl rand -hex 16)
NCDBPASSWORD=$(openssl rand -hex 16)
NEXTCLOUDADMINUSERPASSWORD=$(openssl rand -hex 16)
REDISPASSWORD=$(openssl rand -hex 16)

# External IP variables

NEXTCLOUDEXTIP=$(dig +short txt ch whoami.cloudflare @1.0.0.1 | tr -d \")

# Start processes

start=$(date +%s)
# Identify the current user
# Get the current username
USERNAME=$(logname)

# Check if the script is being run as root
if [ "$(id -u)" != "0" ]
then
    clear
    echo ""
    echo "*****************************"
    echo "* Run as root               *"
    echo "*****************************"
    echo ""
    exit 1
fi
###########################
# IPv4 for "APT'          #
###########################

if [ $APTIP4 == "y" ] 
then
${echo} 'Acquire::ForceIPv4 "true";' >> /etc/apt/apt.conf.d/99force-ipv4
fi
#Ensure, admin software is available on the server
if [ -z "$(command -v lsb_release)" ]
then
apt install -y lsb-release
fi
if [ -z "$(command -v curl)" ]
then
apt install -y curl
fi
if [ -z "$(command -v wget)" ]
then
apt install -y wget
fi
if [ -z "$(command -v ping)" ]
then
apt install -y iputils-ping net-tools
fi
#Check system requirements
if [ "$(lsb_release -r | awk '{ print $2 }')" = "20.04" ] || [ "$(lsb_release -r | awk '{ print $2 }')" = "22.04" ]
then
clear
echo "*************************************************"
echo "*  Pre-Installation                             *"
echo "*************************************************"
echo ""
echo "* Test: Root ...............:::::::::::::::: OK *"
echo ""
if [ "$(lsb_release -r | awk '{ print $2 }')" = "20.04" ]
then
echo "* Test: Ubuntu 20 was found ........:::::::: OK *"
fi
if [ "$(lsb_release -r | awk '{ print $2 }')" = "22.04" ]
then
echo "* Test: Ubuntu 22 was found ........:::::::: OK *"
fi
echo ""
else
clear
echo ""
echo "********************************************"
echo "*You're on the wrong OS. Need ubuntu 20/22 *"
echo "********************************************"
echo ""
exit 1
fi
# Uninstall Script
mkdir -p /home/"$USERNAME"/Nextcloud_Install_Script/
touch /home/"$USERNAME"/Nextcloud_Install_Script/uninstall.sh
cat <<EOF >/home/"$USERNAME"/Nextcloud_Install_Script/uninstall.sh
#!/bin/bash
if [ "\$(id -u)" != "0" ]
then
clear
echo ""
echo "*****************************"
echo "* PLEASE OPERATE AS ROOT!   *"
echo "*****************************"
echo ""
exit 1
fi
clear
echo "*********************************************************"
echo "*                       DELETION                        *"
echo "*                                                       *"
echo "* Everything Nextcloud will be removed from the system! *"
echo "*                                                       *"
echo "*********************************************************"
echo
echo "Ctrl+C to stop"
echo
seconds=$((10))
while [ \$seconds -gt 0 ]; do
   echo -ne "Removal begins after: \$seconds\033[0K\r"
   sleep 1
   : \$((seconds--))
done
rm -Rf $NEXTCLOUDDATAPATH
mv /etc/hosts.bak /etc/hosts
apt remove --purge --allow-change-held-packages -y nginx* php* mariadb-* mysql-common libdbd-mariadb-perl galera-* postgresql-* redis* fail2ban ufw
rm -Rf /etc/ufw /etc/fail2ban /var/www /etc/mysql /etc/postgresql /etc/postgresql-common /var/lib/mysql /var/lib/postgresql /etc/letsencrypt /var/log/nextcloud /home/$USERNAME/Nextcloud-Installationsskript/install.log /home/$USERNAME/Nextcloud-Installationsskript/update.sh
rm -Rf /etc/nginx /usr/share/keyrings/nginx-archive-keyring.gpg /usr/share/keyrings/postgresql-archive-keyring.gpg
add-apt-repository ppa:ondrej/php -ry
rm -f /etc/ssl/certs/dhparam.pem /etc/apt/sources.list.d/* /etc/motd /root/.bash_aliases
deluser --remove-all-files acmeuser
crontab -u www-data -r
rm -f /etc/sudoers.d/acmeuser
apt autoremove -y
apt autoclean -y
sed -i '/vm.overcommit_memory = 1/d' /etc/sysctl.conf
echo ""
echo "Done!"
exit 0
EOF
chmod +x /home/"$USERNAME"/Nextcloud_Install_Script/uninstall.sh
##########################
# Prevent Second Run     #
##########################
if [ -e "/var/www/nextcloud/config/config.php" ] || [ -e /etc/nginx/conf.d/nextcloud.conf ]; then
  clear
  echo "*************************************************"
  echo "* Test: Previous installation ......:::::FAILED *"
  echo "*************************************************"
  echo ""
  echo "* Nextcloud has already been installed on this system!"
  echo ""
  echo "* Please remove it completely before proceeding to a new installation."
  echo ""
  echo "* Please find the uninstall script here:"
  echo "* /home/$USERNAME/Nextcloud_Install_Script/uninstall.sh"
  echo ""
  exit 1
else
  echo "*************************************************"
  echo "* No previous installation found ......::::: OK *"
  echo "*************************************************"
  echo ""
fi
# Verify homedirectory    #
if [ ! -d "/home/$USERNAME/" ]; then
  echo "* Creating:  Home Directory ..........:::::: OK *"
  mkdir -p /home/"$USERNAME"/
  echo ""
  else
  echo "* Test: Home directory ..........::::::::::: OK *"
  echo ""
  fi
if [ ! -d "/home/$USERNAME/Nextcloud_Install_Script/" ]; then
  echo "* Creating: Install directory .......::::::: OK *"
  mkdir /home/"$USERNAME"/Nextcloud_Install_Script/
  echo ""
  else
  echo "* Test: INextcloud_Install_Script directory .....::::::: OK *"
  echo ""
  fi
  echo "*************************************************"
  echo "*  All good.                                    *"
  echo "*************************************************"
  echo ""
  sleep 3
#Identify local ip
IPA=$(hostname -I | awk '{print $1}')
#System patches
addaptrepository=$(command -v add-apt-repository)
adduser=$(command -v adduser)
apt=$(command -v apt-get)
aptmark=$(command -v apt-mark)
cat=$(command -v cat)
chmod=$(command -v chmod)
chown=$(command -v chown)
clear=$(command -v clear)
cp=$(command -v cp)
curl=$(command -v curl)
date=$(command -v date)
echo=$(command -v echo)
lsbrelease=$(command -v lsb_release)
ln=$(command -v ln)
mkdir=$(command -v mkdir)
mv=$(command -v mv)
rm=$(command -v rm)
sed=$(command -v sed)
sudo=$(command -v sudo)
su=$(command -v su)
systemctl=$(command -v systemctl)
tar=$(command -v tar)
timedatectl=$(command -v timedatectl)
touch=$(command -v touch)
usermod=$(command -v usermod)
wget=$(command -v wget)
# Timezone
${timedatectl} set-timezone "$CURRENTTIMEZONE"
# E: Modify host file
${cp} /etc/hosts /etc/hosts.bak
${sed} -i '/127.0.1.1/d' /etc/hosts
${cat} <<EOF >> /etc/hosts
127.0.1.1 $(hostname)
EOF
# E: System settings
${apt} install -y figlet
figlet=$(command -v figlet)
${touch} /etc/motd
${figlet} Nextcloud > /etc/motd
${cat} <<EOF >> /etc/motd

    GROUP SIX

EOF
# Logfile
exec > >(tee -i "/home/$USERNAME/Nextcloud-Installationsskript/install.log")
exec 2>&1
# Update-function
function update_and_clean() {
  ${apt} update
  ${apt} upgrade -y
  ${apt} autoclean -y
  ${apt} autoremove -y
  }
# Clean terminal output
CrI() {
  while ps "$!" > /dev/null; do
  echo -n '.'
  sleep '0.5'
  done
  ${echo} ''
  }
#Hold software
function setHOLD() {
  ${aptmark} hold nginx*
  ${aptmark} hold redis*
  ${aptmark} hold mariadb*
  ${aptmark} hold mysql*
  ${aptmark} hold php*
  }
# Restart services
function restart_all_services() {
  ${systemctl} restart nginx
  if [ $DATABASE == "m" ]
  then
        ${systemctl} restart mysql
  else
        ${systemctl} restart postgresql
  fi
  ${systemctl} restart redis-server php$PHPVERSION-fpm
  }
# NC data index
function nextcloud_scan_data() {
  ${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ files:scan --all
  ${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ files:scan-app-data
  ${systemctl} restart fail2ban
  }
# E: Required software    #
${clear}
${echo} "System and software updates"
${echo} ""
sleep 3
${apt} update
${apt} upgrade -y
${apt} install -y apt-transport-https bash-completion bzip2 ca-certificates cron curl dialog dirmngr ffmpeg ghostscript gpg gnupg gnupg2 htop jq \
libfile-fcntllock-perl libfontconfig1 libfuse2 locate net-tools rsyslog screen smbclient socat software-properties-common ssl-cert tree unzip wget zip ubuntu-keyring
#Remove short diffie hellman keys
sudo cp --archive /etc/ssh/moduli /etc/ssh/moduli.bak
sudo awk '$5 >= 3071' /etc/ssh/moduli | sudo tee /etc/ssh/moduli.tmp
sudo mv /etc/ssh/moduli.tmp /etc/ssh/moduli
#Limit sudo users
sudo groupadd sudousers
sudo usermod -aG sudousers j
sudo cp --archive /etc/sudoers /etc/sudoers.bak
cat <<EOF >>/etc/sudoers
%sudousers ALL=(ALL) ALL
EOF
#Secure proc
sudo cp --archive /etc/fstab /etc/fstab.bak
echo -e "\nproc     /proc     proc     defaults,hidepid=2     0     0         # added by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")" | sudo tee -a /etc/fstab
sudo mount -o remount,hidepid=2 /proc
# set up autoupdates
${apt} install -y unattended-upgrades apt-listchanges apticron
cat <<EOF >/etc/apt/apt.conf.d/51myunattended-upgrades
// Enable the update/upgrade script (0=disable)
APT::Periodic::Enable "1";

// Do "apt-get update" automatically every n-days (0=disable)
APT::Periodic::Update-Package-Lists "1";

// Do "apt-get upgrade --download-only" every n-days (0=disable)
APT::Periodic::Download-Upgradeable-Packages "1";

// Do "apt-get autoclean" every n-days (0=disable)
APT::Periodic::AutocleanInterval "7";

// Send report mail to root
//     0:  no report             (or null string)
//     1:  progress report       (actually any string)
//     2:  + command outputs     (remove -qq, remove 2>/dev/null, add -d)
//     3:  + trace on    APT::Periodic::Verbose "2";
APT::Periodic::Unattended-Upgrade "1";

// Automatically upgrade packages from these
Unattended-Upgrade::Origins-Pattern {
      "o=Debian,a=stable";
      "o=Debian,a=stable-updates";
      "origin=Debian,codename=${distro_codename},label=Debian-Security";
};

// You can specify your own packages to NOT automatically upgrade here
Unattended-Upgrade::Package-Blacklist {
};

// Run dpkg --force-confold --configure -a if a unclean dpkg state is detected to true to ensure that updates get installed even when the system got interrupted during a previous run
Unattended-Upgrade::AutoFixInterruptedDpkg "true";

//Perform the upgrade when the machine is running because we wont be shutting our server down often
Unattended-Upgrade::InstallOnShutdown "false";

// Send an email to this address with information about the packages upgraded.
Unattended-Upgrade::Mail "root";

// Always send an e-mail
Unattended-Upgrade::MailOnlyOnError "false";

// Remove all unused dependencies after the upgrade has finished
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// Remove any new unused dependencies after the upgrade has finished
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";

// Automatically reboot WITHOUT CONFIRMATION if the file /var/run/reboot-required is found after the upgrade.
Unattended-Upgrade::Automatic-Reboot "true";

// Automatically reboot even if users are logged in.
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
EOF
# Enable logwatch
{apt} install -y logwatch
sudo cp --archive /etc/cron.daily/00logwatch /etc/cron.daily/00logwatch.bak
sudo chmod -x /etc/cron.daily/00logwatch.bak
sudo sed -i -r -e "s,^($(sudo which logwatch).*?),# \1         # commented by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")\n$(sudo which logwatch) --output mail --format html --mailto root --range yesterday --service all         # added by $(whoami) on $(date +"%Y-%m-%d @ %H:%M:%S")," /etc/cron.daily/00logwatch

#Install Lynis
{apt} install -y apt-transport-https ca-certificates host
sudo wget -O - https://packages.cisofy.com/keys/cisofy-software-public.key | sudo apt-key add -
sudo echo "deb https://packages.cisofy.com/community/lynis/deb/ stable main" | sudo tee /etc/apt/sources.list.d/cisofy-lynis.list
${apt} update
${apt} install -y lynis host
sudo lynis update info
#Install rkhunter
${apt} install -y rkhunter
sudo rkhunter --update

# Change energy mode
${systemctl} mask sleep.target suspend.target hibernate.target hybrid-sleep.target
# PHP 8 Repositories
${addaptrepository} ppa:ondrej/php -y
# NGINX Repositories      #
${curl} https://nginx.org/keys/nginx_signing.key | gpg --dearmor | sudo tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/mainline/ubuntu `lsb_release -cs` nginx" | sudo tee /etc/apt/sources.list.d/nginx.list
# DB Repositories         #
if [ $DATABASE == "m" ]
then
    ${wget} -O- https://mariadb.org/mariadb_release_signing_key.asc | gpg --dearmor | sudo tee /usr/share/keyrings/mariadb-keyring.gpg >/dev/null
    echo "deb [signed-by=/usr/share/keyrings/mariadb-keyring.gpg] https://mirror.kumi.systems/mariadb/repo/10.11/ubuntu $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/mariadb.list
else
    ${wget}  -O- https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor | sudo tee /usr/share/keyrings/postgresql-archive-keyring.gpg >/dev/null
    echo "deb [signed-by=/usr/share/keyrings/postgresql-archive-keyring.gpg] http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" | sudo tee /etc/apt/sources.list.d/pgdg.list      
fi
# Remove unattended upgrades??????
${apt} purge -y unattended-upgrades
# System update
update_and_clean
# Clean Up
${apt} remove -y apache2 nginx nginx-common nginx-full --allow-change-held-packages
${rm} -Rf /etc/apache2 /etc/nginx
# Install NGINX
${clear}
${echo} "NGINX-Installation"
${echo} ""
sleep 3
${apt} update
${apt} install -y nginx --allow-change-held-packages
${systemctl} enable nginx.service
${mv} /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
${touch} /etc/nginx/nginx.conf
${cat} <<EOF >/etc/nginx/nginx.conf
user www-data;
worker_processes auto;
pid /var/run/nginx.pid;
events {
  worker_connections 2048;
  multi_accept on;
  use epoll;
  }
http {
  log_format criegerde escape=json
  '{'
    '"time_local":"\$time_local",'
    '"remote_addr":"\$remote_addr",'
    '"remote_user":"\$remote_user",'
    '"request":"\$request",'
    '"status": "\$status",'
    '"body_bytes_sent":"\$body_bytes_sent",'
    '"request_time":"\$request_time",'
    '"http_referrer":"\$http_referer",'
    '"http_user_agent":"\$http_user_agent"'
  '}';
  server_names_hash_bucket_size 64;
  access_log /var/log/nginx/access.log criegerde;
  error_log /var/log/nginx/error.log warn;
  #set_real_ip_from 127.0.0.1;
  real_ip_header X-Forwarded-For;
  real_ip_recursive on;
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  sendfile on;
  send_timeout 3600;
  tcp_nopush on;
  tcp_nodelay on;
  open_file_cache max=500 inactive=10m;
  open_file_cache_errors on;
  keepalive_timeout 65;
  reset_timedout_connection on;
  server_tokens off;
  resolver $RESOLVER valid=30s;
  resolver_timeout 5s;
  include /etc/nginx/conf.d/*.conf;
  }
EOF
# Restart NGINX
${systemctl} restart nginx
# E: Create directories
${mkdir} -p /var/log/nextcloud /var/www/letsencrypt/.well-known/acme-challenge /etc/letsencrypt/rsa-certs /etc/letsencrypt/ecc-certs
${chmod} -R 775 /var/www/letsencrypt
${chmod} -R 770 /etc/letsencrypt
${chown} -R www-data:www-data /var/log/nextcloud /var/www/ /etc/letsencrypt
# E: Create ACME-user
${adduser} acmeuser --gecos "" --disabled-password
${usermod} -aG www-data acmeuser
${touch} /etc/sudoers.d/acmeuser
${cat} <<EOF >/etc/sudoers.d/acmeuser
acmeuser ALL=NOPASSWD: /bin/systemctl reload nginx.service
EOF
${su} - acmeuser -c "/usr/bin/curl https://get.acme.sh | sh"
${su} - acmeuser -c ".acme.sh/acme.sh --set-default-ca --server letsencrypt"
# Install PHP
${clear}
${echo} "PHP-Installation"
${echo} ""
sleep 3
${apt} install -y php-common php$PHPVERSION-{fpm,gd,curl,xml,zip,intl,mbstring,bz2,ldap,apcu,bcmath,gmp,imagick,igbinary,redis,smbclient,cli,common,opcache,readline} imagemagick ldap-utils nfs-common cifs-utils --allow-change-held-packages
${apt} install -y libmagickcore-6.q16-6-extra --allow-change-held-packages
AvailableRAM=$(/usr/bin/awk '/MemAvailable/ {printf "%d", $2/1024}' /proc/meminfo)
${cp} /etc/php/$PHPVERSION/fpm/pool.d/www.conf /etc/php/$PHPVERSION/fpm/pool.d/www.conf.bak
${cp} /etc/php/$PHPVERSION/fpm/php-fpm.conf /etc/php/$PHPVERSION/fpm/php-fpm.conf.bak
${cp} /etc/php/$PHPVERSION/cli/php.ini /etc/php/$PHPVERSION/cli/php.ini.bak
${cp} /etc/php/$PHPVERSION/fpm/php.ini /etc/php/$PHPVERSION/fpm/php.ini.bak
${cp} /etc/php/$PHPVERSION/mods-available/opcache.ini /etc/php/$PHPVERSION/mods-available/opcache.ini.bak
${cp} /etc/php/$PHPVERSION/mods-available/apcu.ini /etc/php/$PHPVERSION/mods-available/apcu.ini.bak
${cp} /etc/php/$PHPVERSION/fpm/php-fpm.conf /etc/php/$PHPVERSION/fpm/php-fpm.conf.bak
${cp} /etc/ImageMagick-6/policy.xml /etc/ImageMagick-6/policy.xml.bak
# ${sed} -i 's/pm = dynamic/pm = static/' /etc/php/$PHPVERSION/fpm/pool.d/www.conf
${sed} -i 's/;env\[HOSTNAME\] = /env[HOSTNAME] = /' /etc/php/$PHPVERSION/fpm/pool.d/www.conf
${sed} -i 's/;env\[TMP\] = /env[TMP] = /' /etc/php/$PHPVERSION/fpm/pool.d/www.conf
${sed} -i 's/;env\[TMPDIR\] = /env[TMPDIR] = /' /etc/php/$PHPVERSION/fpm/pool.d/www.conf
${sed} -i 's/;env\[TEMP\] = /env[TEMP] = /' /etc/php/$PHPVERSION/fpm/pool.d/www.conf
${sed} -i 's/;env\[PATH\] = /env[PATH] = /' /etc/php/$PHPVERSION/fpm/pool.d/www.conf
if [ "$AvailableRAM" -ge "4096" ];then 
${sed} -i 's/pm.max_children =.*/pm.max_children = 200/' /etc/php/$PHPVERSION/fpm/pool.d/www.conf
${sed} -i 's/pm.start_servers =.*/pm.start_servers = 100/' /etc/php/$PHPVERSION/fpm/pool.d/www.conf
${sed} -i 's/pm.min_spare_servers =.*/pm.min_spare_servers = 60/' /etc/php/$PHPVERSION/fpm/pool.d/www.conf
${sed} -i 's/pm.max_spare_servers =.*/pm.max_spare_servers = 140/' /etc/php/$PHPVERSION/fpm/pool.d/www.conf
${sed} -i 's/;pm.max_requests =.*/pm.max_requests = 1000/' /etc/php/$PHPVERSION/fpm/pool.d/www.conf
else
${sed} -i 's/pm.max_children =.*/pm.max_children = 100/' /etc/php/$PHPVERSION/fpm/pool.d/www.conf
${sed} -i 's/pm.start_servers =.*/pm.start_servers = 50/' /etc/php/$PHPVERSION/fpm/pool.d/www.conf
${sed} -i 's/pm.min_spare_servers =.*/pm.min_spare_servers = 30/' /etc/php/$PHPVERSION/fpm/pool.d/www.conf
${sed} -i 's/pm.max_spare_servers =.*/pm.max_spare_servers = 70/' /etc/php/$PHPVERSION/fpm/pool.d/www.conf
${sed} -i 's/;pm.max_requests =.*/pm.max_requests = 1000/' /etc/php/$PHPVERSION/fpm/pool.d/www.conf
fi
${sed} -i 's/output_buffering =.*/output_buffering = Off/' /etc/php/$PHPVERSION/cli/php.ini
${sed} -i 's/max_execution_time =.*/max_execution_time = 3600/' /etc/php/$PHPVERSION/cli/php.ini
${sed} -i 's/max_input_time =.*/max_input_time = 3600/' /etc/php/$PHPVERSION/cli/php.ini
${sed} -i 's/post_max_size =.*/post_max_size = 10240M/' /etc/php/$PHPVERSION/cli/php.ini
${sed} -i 's/upload_max_filesize =.*/upload_max_filesize = '$UPLOADSIZE'/' /etc/php/$PHPVERSION/cli/php.ini
${sed} -i 's|;date.timezone.*|date.timezone = '$CURRENTTIMEZONE'|' /etc/php/$PHPVERSION/cli/php.ini
${sed} -i 's/;cgi.fix_pathinfo.*/cgi.fix_pathinfo = 0/' /etc/php/$PHPVERSION/cli/php.ini
${sed} -i 's/memory_limit = 128M/memory_limit = 2G/' /etc/php/$PHPVERSION/fpm/php.ini
${sed} -i 's/output_buffering =.*/output_buffering = Off/' /etc/php/$PHPVERSION/fpm/php.ini
${sed} -i 's/max_execution_time =.*/max_execution_time = 3600/' /etc/php/$PHPVERSION/fpm/php.ini
${sed} -i 's/max_input_time =.*/max_input_time = 3600/' /etc/php/$PHPVERSION/fpm/php.ini
${sed} -i 's/post_max_size =.*/post_max_size = 10240M/' /etc/php/$PHPVERSION/fpm/php.ini
${sed} -i 's/upload_max_filesize =.*/upload_max_filesize = '$UPLOADSIZE'/' /etc/php/$PHPVERSION/fpm/php.ini
${sed} -i 's|;date.timezone.*|date.timezone = '$CURRENTTIMEZONE'|' /etc/php/$PHPVERSION/fpm/php.ini
${sed} -i 's/;session.cookie_secure.*/session.cookie_secure = True/' /etc/php/$PHPVERSION/fpm/php.ini
${sed} -i 's/;opcache.enable=.*/opcache.enable=1/' /etc/php/$PHPVERSION/fpm/php.ini
${sed} -i 's/;opcache.enable_cli=.*/opcache.enable_cli=1/' /etc/php/$PHPVERSION/fpm/php.ini
${sed} -i 's/;opcache.memory_consumption=.*/opcache.memory_consumption=256/' /etc/php/$PHPVERSION/fpm/php.ini
${sed} -i 's/;opcache.interned_strings_buffer=.*/opcache.interned_strings_buffer=64/' /etc/php/$PHPVERSION/fpm/php.ini
${sed} -i 's/;opcache.max_accelerated_files=.*/opcache.max_accelerated_files=100000/' /etc/php/$PHPVERSION/fpm/php.ini
${sed} -i 's/;opcache.validate_timestamps=.*/opcache.validate_timestamps=1/' /etc/php/$PHPVERSION/fpm/php.ini
${sed} -i 's/;opcache.revalidate_freq=.*/opcache.revalidate_freq=0/' /etc/php/$PHPVERSION/fpm/php.ini
${sed} -i 's/;opcache.save_comments=.*/opcache.save_comments=1/' /etc/php/$PHPVERSION/fpm/php.ini
${sed} -i 's/allow_url_fopen =.*/allow_url_fopen = 1/' /etc/php/$PHPVERSION/fpm/php.ini
${sed} -i 's/;cgi.fix_pathinfo.*/cgi.fix_pathinfo = 0/' /etc/php/$PHPVERSION/fpm/php.ini
${sed} -i '$aapc.enable_cli=1' /etc/php/$PHPVERSION/mods-available/apcu.ini
${sed} -i 's/opcache.jit=off/; opcache.jit=off/' /etc/php/"$PHPVERSION"/mods-available/opcache.ini
${sed} -i '$aopcache.jit=1255' /etc/php/"$PHPVERSION"/mods-available/opcache.ini
${sed} -i '$aopcache.jit_buffer_size=256M' /etc/php/$PHPVERSION/mods-available/opcache.ini
${sed} -i 's|;emergency_restart_threshold.*|emergency_restart_threshold = 10|g' /etc/php/$PHPVERSION/fpm/php-fpm.conf
${sed} -i 's|;emergency_restart_interval.*|emergency_restart_interval = 1m|g' /etc/php/$PHPVERSION/fpm/php-fpm.conf
${sed} -i 's|;process_control_timeout.*|process_control_timeout = 10|g' /etc/php/$PHPVERSION/fpm/php-fpm.conf
${sed} -i 's/rights=\"none\" pattern=\"PS\"/rights=\"read|write\" pattern=\"PS\"/' /etc/ImageMagick-6/policy.xml
${sed} -i 's/rights=\"none\" pattern=\"EPS\"/rights=\"read|write\" pattern=\"EPS\"/' /etc/ImageMagick-6/policy.xml
${sed} -i 's/rights=\"none\" pattern=\"PDF\"/rights=\"read|write\" pattern=\"PDF\"/' /etc/ImageMagick-6/policy.xml
${sed} -i 's/rights=\"none\" pattern=\"XPS\"/rights=\"read|write\" pattern=\"XPS\"/' /etc/ImageMagick-6/policy.xml
if [ ! -e "/usr/bin/gs" ]; then
${ln} -s /usr/local/bin/gs /usr/bin/gs
fi
# Restart PHP
${systemctl} restart php$PHPVERSION-fpm
${systemctl} restart nginx
# Install DB
${clear}
${echo} "DB-Installation"
${echo} ""
sleep 3
if [ $DATABASE == "m" ]
then
        ${apt} install -y php$PHPVERSION-mysql mariadb-server --allow-change-held-packages
        ${cp} /etc/php/$PHPVERSION/mods-available/mysqli.ini /etc/php/$PHPVERSION/mods-available/mysqli.ini.bak
        ${sed} -i '$a[mysql]' /etc/php/$PHPVERSION/mods-available/mysqli.ini
        ${sed} -i '$amysql.allow_local_infile=On' /etc/php/$PHPVERSION/mods-available/mysqli.ini
        ${sed} -i '$amysql.allow_persistent=On' /etc/php/$PHPVERSION/mods-available/mysqli.ini
        ${sed} -i '$amysql.cache_size=2000' /etc/php/$PHPVERSION/mods-available/mysqli.ini
        ${sed} -i '$amysql.max_persistent=-1' /etc/php/$PHPVERSION/mods-available/mysqli.ini
        ${sed} -i '$amysql.max_links=-1' /etc/php/$PHPVERSION/mods-available/mysqli.ini
        ${sed} -i '$amysql.default_port=3306' /etc/php/$PHPVERSION/mods-available/mysqli.ini
        ${sed} -i '$amysql.connect_timeout=60' /etc/php/$PHPVERSION/mods-available/mysqli.ini
        ${sed} -i '$amysql.trace_mode=Off' /etc/php/$PHPVERSION/mods-available/mysqli.ini
        ${systemctl} stop mysql
        ${cp} /etc/mysql/my.cnf /etc/mysql/my.cnf.bak
        ${cat} <<EOF >/etc/mysql/my.cnf
[client]
default-character-set = utf8mb4
port = 3306
socket = /var/run/mysqld/mysqld.sock
[mysqld_safe]
log_error=/var/log/mysql/mysql_error.log
nice = 0
socket = /var/run/mysqld/mysqld.sock
[mysqld]
# performance_schema=ON
basedir = /usr
bind-address = 127.0.0.1
binlog_format = ROW
character-set-server = utf8mb4
collation-server = utf8mb4_general_ci
datadir = /var/lib/mysql
default_storage_engine = InnoDB
expire_logs_days = 2
general_log_file = /var/log/mysql/mysql.log
innodb_buffer_pool_size = 2G
innodb_log_buffer_size = 32M
innodb_log_file_size = 512M
innodb_read_only_compressed=OFF
join_buffer_size = 2M
key_buffer_size = 512M
lc_messages_dir = /usr/share/mysql
lc_messages = en_US
log_bin = /var/log/mysql/mariadb-bin
log_bin_index = /var/log/mysql/mariadb-bin.index
log_error = /var/log/mysql/mysql_error.log
log_slow_verbosity = query_plan
log_warnings = 2
long_query_time = 1
max_connections = 100
max_heap_table_size = 64M
myisam_sort_buffer_size = 512M
port = 3306
pid-file = /var/run/mysqld/mysqld.pid
query_cache_limit = 0
query_cache_size = 0 
read_buffer_size = 2M
read_rnd_buffer_size = 2M
skip-name-resolve
socket = /var/run/mysqld/mysqld.sock
sort_buffer_size = 2M
table_open_cache = 400
table_definition_cache = 800
tmp_table_size = 32M
tmpdir = /tmp
transaction_isolation = READ-COMMITTED
user = mysql
wait_timeout = 600
[mysqldump]
max_allowed_packet = 16M
quick
quote-names
[isamchk]
key_buffer = 16M
EOF
${systemctl} restart mysql
mysql=$(command -v mysql)
${mysql} -e "CREATE DATABASE nextcloud CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;"
${mysql} -e "CREATE USER ${NCDBUSER}@localhost IDENTIFIED BY '${NCDBPASSWORD}';"
${mysql} -e "CREATE USER ${NCDBUSER}@127.0.0.1 IDENTIFIED BY '${NCDBPASSWORD}';"
${mysql} -e "GRANT ALL PRIVILEGES ON nextcloud.* TO '${NCDBUSER}'@'localhost';"
${mysql} -e "GRANT ALL PRIVILEGES ON nextcloud.* TO '${NCDBUSER}'@'127.0.0.1';"
${mysql} -e "FLUSH PRIVILEGES;"
mysql_secure_installation=$(command -v mysql_secure_installation)
cat <<EOF | ${mysql_secure_installation}
\n
n
y
y
y
y
EOF
        mysql -u root -e "SET PASSWORD FOR root@'localhost' = PASSWORD('$MARIADBROOTPASSWORD'); FLUSH PRIVILEGES;"
else
${apt} install -y php$PHPVERSION-pgsql postgresql-15 --allow-change-held-packages
sudo -u postgres psql <<EOF
CREATE USER ${NCDBUSER} WITH PASSWORD '${NCDBPASSWORD}';
CREATE DATABASE nextcloud TEMPLATE template0 ENCODING 'UNICODE';
ALTER DATABASE nextcloud OWNER TO ${NCDBUSER};
GRANT ALL PRIVILEGES ON DATABASE nextcloud TO ${NCDBUSER};
EOF
${systemctl} restart postgresql
fi
# Install Redis
${clear}
${echo} "REDIS-Installation"
${echo} ""
sleep 3
${apt} install -y redis-server --allow-change-held-packages
${cp} /etc/redis/redis.conf /etc/redis/redis.conf.bak
${sed} -i 's/port 6379/port 0/' /etc/redis/redis.conf
${sed} -i s/\#\ unixsocket/\unixsocket/g /etc/redis/redis.conf
${sed} -i 's/unixsocketperm 700/unixsocketperm 770/' /etc/redis/redis.conf
${sed} -i "s/# requirepass foobared/requirepass $REDISPASSWORD/" /etc/redis/redis.conf
${sed} -i 's/# maxclients 10000/maxclients 10240/' /etc/redis/redis.conf
${cp} /etc/sysctl.conf /etc/sysctl.conf.bak
${sed} -i '$avm.overcommit_memory = 1' /etc/sysctl.conf
${usermod} -a -G redis www-data
# Self-Signed-SSL
${apt} install -y ssl-cert
# NGINX TLS
[ -f /etc/nginx/conf.d/default.conf ] && ${mv} /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default.conf.bak
${touch} /etc/nginx/conf.d/default.conf
${touch} /etc/nginx/conf.d/http.conf
${cat} <<EOF >/etc/nginx/conf.d/http.conf
upstream php-handler {
  server unix:/run/php/php$PHPVERSION-fpm.sock;
  }
map \$arg_v \$asset_immutable {
    "" "";
    default "immutable";
}
  server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name $NEXTCLOUDDNS;
    root /var/www;
    location ^~ /.well-known/acme-challenge {
      default_type text/plain;
      root /var/www/letsencrypt;
      }
    location / {
      return 301 https://\$host\$request_uri;
      }
   }
EOF
${cat} <<EOF >/etc/nginx/conf.d/nextcloud.conf
server {
  listen 443 ssl default_server;
  listen [::]:443 ssl default_server;
  http2 on;
  server_name $NEXTCLOUDDNS;
  ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
  ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
  ssl_trusted_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
  #ssl_certificate /etc/letsencrypt/rsa-certs/fullchain.pem;
  #ssl_certificate_key /etc/letsencrypt/rsa-certs/privkey.pem;
  #ssl_certificate /etc/letsencrypt/ecc-certs/fullchain.pem;
  #ssl_certificate_key /etc/letsencrypt/ecc-certs/privkey.pem;
  #ssl_trusted_certificate /etc/letsencrypt/ecc-certs/chain.pem;
  ssl_dhparam /etc/ssl/certs/dhparam.pem;
  ssl_session_timeout 1d;
  ssl_session_cache shared:SSL:50m;
  ssl_session_tickets off;
  ssl_protocols TLSv1.3 TLSv1.2;
  ssl_ciphers 'TLS-CHACHA20-POLY1305-SHA256:TLS-AES-256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384';
  ssl_ecdh_curve X448:secp521r1:secp384r1;
  ssl_prefer_server_ciphers on;
  ssl_stapling on;
  ssl_stapling_verify on;
  client_max_body_size 10G;
  client_body_timeout 3600s;
  client_body_buffer_size 512k;
  fastcgi_buffers 64 4K;
  gzip on;
  gzip_vary on;
  gzip_comp_level 4;
  gzip_min_length 256;
  gzip_proxied expired no-cache no-store private no_last_modified no_etag auth;
  gzip_types application/atom+xml application/javascript application/json application/ld+json application/manifest+json application/rss+xml application/vnd.geo+json application/vnd.ms-fontobject application/wasm application/x-font-ttf application/x-web-app-manifest+json application/xhtml+xml application/xml font/opentype image/bmp image/svg+xml image/x-icon text/cache-manifest text/css text/plain text/vcard text/vnd.rim.location.xloc text/vtt text/x-component text/x-cross-domain-policy;
  add_header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload;" always;
  add_header Permissions-Policy "interest-cohort=()";
  add_header Referrer-Policy "no-referrer" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header X-Download-Options "noopen" always;
  add_header X-Frame-Options "SAMEORIGIN" always;
  add_header X-Permitted-Cross-Domain-Policies "none" always;
  add_header X-Robots-Tag "noindex, nofollow" always;
  add_header X-XSS-Protection "1; mode=block" always;
  fastcgi_hide_header X-Powered-By;
  include mime.types;
  types {
    text/javascript mjs;
    }
  root /var/www/nextcloud;
  index index.php index.html /index.php\$request_uri;
  location = / {
    if ( \$http_user_agent ~ ^DavClnt ) {
      return 302 /remote.php/webdav/\$is_args\$args;
      }
  }
  location = /robots.txt {
    allow all;
    log_not_found off;
    access_log off;
    }
  location ^~ /.well-known {
    location = /.well-known/carddav { return 301 /remote.php/dav/; }
    location = /.well-known/caldav  { return 301 /remote.php/dav/; }
    location /.well-known/acme-challenge { try_files \$uri \$uri/ =404; }
    location /.well-known/pki-validation { try_files \$uri \$uri/ =404; }
    return 301 /index.php\$request_uri;
    }
  location ~ ^/(?:build|tests|config|lib|3rdparty|templates|data)(?:\$|/)  { return 404; }
  location ~ ^/(?:\.|autotest|occ|issue|indie|db_|console)  { return 404; }
  location ~ \.php(?:\$|/) {
    rewrite ^/(?!index|test|remote|public|cron|core\/ajax\/update|status|ocs\/v[12]|updater\/.+|oc[ms]-provider\/.+|.+\/richdocumentscode\/proxy) /index.php\$request_uri;
    fastcgi_split_path_info ^(.+?\.php)(/.*)\$;
    set \$path_info \$fastcgi_path_info;
    try_files \$fastcgi_script_name =404;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    fastcgi_param PATH_INFO \$path_info;
    fastcgi_param HTTPS on;
    fastcgi_param modHeadersAvailable true;
    fastcgi_param front_controller_active true;
    fastcgi_pass php-handler;
    fastcgi_intercept_errors on;
    fastcgi_request_buffering off;
    fastcgi_read_timeout 3600;
    fastcgi_send_timeout 3600;
    fastcgi_connect_timeout 3600;
    }
  location ~ \.(?:css|js|mjs|svg|gif|png|jpg|ico|wasm|tflite|map)$ {
    try_files \$uri /index.php\$request_uri;
    add_header Cache-Control "public, max-age=15778463, \$asset_immutable";
    expires 6M;
    access_log off;
    location ~ \.wasm\$ {
      default_type application/wasm;
      }
    }
  location ~ \.woff2?\$ {
    try_files \$uri /index.php\$request_uri;
    expires 7d;
    access_log off;
    }
  location /remote {
    return 301 /remote.php\$request_uri;
    }
  location / {
    try_files \$uri \$uri/ /index.php\$request_uri;
    }
}
EOF
${clear}
${echo} "Diffie-Hellman key:"
${echo} ""
/usr/bin/openssl dhparam -dsaparam -out /etc/ssl/certs/dhparam.pem 4096
${echo} ""
sleep 3
# Hostname
${sed} -i "s/server_name cloud.server.io;/server_name $(hostname) $NEXTCLOUDDNS;/" /etc/nginx/conf.d/http.conf
${sed} -i "s/server_name cloud.server.io;/server_name $(hostname) $NEXTCLOUDDNS;/" /etc/nginx/conf.d/nextcloud.conf
# Nextcloud-CRON
(/usr/bin/crontab -u www-data -l ; echo "*/5 * * * * /usr/bin/php -f /var/www/nextcloud/cron.php > /dev/null 2>&1") | /usr/bin/crontab -u www-data -
# Restart NGINX
${systemctl} restart nginx
${clear}
# Download Nextcloud
${echo} "Downloading Nextcloud"
${wget} -q https://download.nextcloud.com/server/releases/latest.tar.bz2 & CrI
${wget} -q https://download.nextcloud.com/server/releases/latest.tar.bz2.md5
${echo} ""
${echo} "Verify Checksum (MD5):"
if [ "$(md5sum -c latest.tar.bz2.md5 < latest.tar.bz2 | awk '{ print $2 }')" = "OK" ]
then
md5sum -c latest.tar.bz2.md5 < latest.tar.bz2
${echo} ""
else
${clear}
${echo} ""
${echo} "CHECKSUM ERROR"
exit 1
fi
${echo} "Extracting Nextcloud"
${apt} install -y bzip2
${tar} -xjf latest.tar.bz2 -C /var/www & CrI
${chown} -R www-data:www-data /var/www/
${rm} -f latest.tar.bz2.md5
restart_all_services
# Nextcloud Installation
${clear}
${echo} "Installing Nextcloud"
${echo} ""
if [[ ! -e $NEXTCLOUDDATAPATH ]];
then
${mkdir} -p $NEXTCLOUDDATAPATH
fi
${chown} -R www-data:www-data $NEXTCLOUDDATAPATH
${echo} "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
${echo} ""
${echo} "Nextcloud being installed quietly... shouldn't be too long"
${echo} ""
if [ $DATABASE == "m" ]
then
sudo -u www-data php /var/www/nextcloud/occ maintenance:install --database "mysql" --database-name "nextcloud" --database-user "${NCDBUSER}" --database-pass "${NCDBPASSWORD}" --admin-user "${NEXTCLOUDADMINUSER}" --admin-pass "${NEXTCLOUDADMINUSERPASSWORD}" --data-dir "${NEXTCLOUDDATAPATH}"
else
sudo -u www-data php /var/www/nextcloud/occ maintenance:install --database "pgsql" --database-name "nextcloud" --database-user "${NCDBUSER}" --database-pass "${NCDBPASSWORD}" --admin-user "${NEXTCLOUDADMINUSER}" --admin-pass "${NEXTCLOUDADMINUSERPASSWORD}" --data-dir "${NEXTCLOUDDATAPATH}"
fi
${echo} ""
sleep 5
declare -l YOURSERVERNAME
YOURSERVERNAME=$(hostname)
# Nextcloud config.php
${sudo} -u www-data ${cp} /var/www/nextcloud/config/config.php /var/www/nextcloud/config/config.php.bak
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ config:system:set trusted_domains 0 --value="$YOURSERVERNAME"
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ config:system:set trusted_domains 1 --value="$NEXTCLOUDDNS"
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ config:system:set trusted_domains 2 --value="$IPA"
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ config:system:set overwrite.cli.url --value=https://"$NEXTCLOUDDNS"
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ config:system:set overwritehost --value="$NEXTCLOUDDNS"
${echo} ""
${echo} "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
${cp} /var/www/nextcloud/.user.ini /usr/local/src/.user.ini.bak
${sudo} -u www-data ${sed} -i 's/output_buffering=.*/output_buffering=0/' /var/www/nextcloud/.user.ini
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ background:cron
# ${sed} -i '/);/d' /var/www/nextcloud/config/config.php
# ${cat} <<EOF >>/var/www/nextcloud/config/config.php
${sudo} -u www-data ${touch} /var/www/nextcloud/config/tweaks.config.php
${cat} <<EOF >>/var/www/nextcloud/config/tweaks.config.php
<?php
\$CONFIG = array (
  'activity_expire_days' => 14,
  'allow_local_remote_servers' => true,
  'auth.bruteforce.protection.enabled' => true,
  'blacklisted_files' =>
  array (
    0 => '.htaccess',
    1 => 'Thumbs.db',
    2 => 'thumbs.db',
    ),
    'cron_log' => true,
    'default_phone_region' => '$PHONEREGION',
    'enable_previews' => true,
    'enabledPreviewProviders' =>
    array (
      0 => 'OC\\Preview\\PNG',
      1 => 'OC\\Preview\\JPEG',
      2 => 'OC\\Preview\\GIF',
      3 => 'OC\\Preview\\BMP',
      4 => 'OC\\Preview\\XBitmap',
      5 => 'OC\\Preview\\Movie',
      6 => 'OC\\Preview\\PDF',
      7 => 'OC\\Preview\\MP3',
      8 => 'OC\\Preview\\TXT',
      9 => 'OC\\Preview\\MarkDown',
      ),
      'filesystem_check_changes' => 0,
      'filelocking.enabled' => 'true',
      'htaccess.RewriteBase' => '/',
      'integrity.check.disabled' => false,
      'knowledgebaseenabled' => false,
      'log_rotate_size' => '104857600',
      'logfile' => '/var/log/nextcloud/nextcloud.log',
      'loglevel' => 2,
      'logtimezone' => '$CURRENTTIMEZONE',
      'memcache.local' => '\\\\OC\\\\Memcache\\\\APCu',
      'memcache.locking' => '\\\\OC\\\\Memcache\\\\Redis',
      'overwriteprotocol' => 'https',
      'preview_max_x' => 1024,
      'preview_max_y' => 768,
      'preview_max_scale_factor' => 1,
      'profile.enabled' => false,
      'redis' =>
      array (
        'host' => '/var/run/redis/redis-server.sock',
        'port' => 0,
        'password' => '$REDISPASSWORD',
        'timeout' => 0.5,
        'dbindex' => 1,
        ),
        'quota_include_external_storage' => false,
        'share_folder' => '/Freigaben',
        'skeletondirectory' => '',
        'trashbin_retention_obligation' => 'auto, 7',
        );
EOF
${sed} -i 's/^[ ]*//' /var/www/nextcloud/config/config.php
# Nextcloud Permissions
${chown} -R www-data:www-data /var/www
# Restart
restart_all_services
# Install fail2ban
${clear}
${echo} "fail2ban-Installation"
${echo} ""
sleep 3
${apt} install -y fail2ban --allow-change-held-packages
${touch} /etc/fail2ban/filter.d/nextcloud.conf
${cat} <<EOF >/etc/fail2ban/filter.d/nextcloud.conf
[Definition]
_groupsre = (?:(?:,?\s*"\w+":(?:"[^"]+"|\w+))*)
failregex = ^\{%(_groupsre)s,?\s*"remoteAddr":"<HOST>"%(_groupsre)s,?\s*"message":"Login failed:
            ^\{%(_groupsre)s,?\s*"remoteAddr":"<HOST>"%(_groupsre)s,?\s*"message":"Trusted domain error.
datepattern = ,?\s*"time"\s*:\s*"%%Y-%%m-%%d[T ]%%H:%%M:%%S(%%z)?"
EOF
${touch} /etc/fail2ban/jail.d/nextcloud.local
${cat} <<EOF >/etc/fail2ban/jail.d/nextcloud.local
[DEFAULT]
maxretry=3
bantime=1800
findtime = 1800
[nextcloud]
backend = auto
enabled = true
port = 80,443
protocol = tcp
filter = nextcloud
maxretry = 5
logpath = /var/log/nextcloud/nextcloud.log
[nginx-http-auth]
enabled = true
EOF
# Install ufw
${clear}
${echo} ""
${echo} " » install ufw"
${echo} ""
sleep 3
${apt} install -y ufw --allow-change-held-packages
ufw=$(command -v ufw)
${ufw} allow 80/tcp comment "LetsEncrypt(http)"
${ufw} allow 443/tcp comment "TLS(https)"
SSHPORT=$(grep -w Port /etc/ssh/sshd_config | awk '/Port/ {print $2}')
${ufw} allow "$SSHPORT"/tcp comment "SSH"
${ufw} logging medium && ${ufw} default deny incoming
${cat} <<EOF | ${ufw} enable
y
EOF
${systemctl} restart redis-server ufw$
${systemctl} enable fail2ban.service
${systemctl} restart fail2ban
# Customize Nextcloud
${clear}
${echo} "Nextcloud Tweaks"
${echo} ""
sleep 3
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ app:disable survey_client
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ app:disable firstrunwizard
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ app:disable federation
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ app:disable support
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ config:app:set settings profile_enabled_by_default --value="0"
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ app:enable admin_audit
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ app:enable files_pdfviewer
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ app:enable contacts
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ app:enable calendar
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ app:enable groupfolders
if [ $NEXTCLOUDOFFICE == "y" ]
then
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ app:install richdocuments
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ app:install richdocumentscode
fi
if [ $ONLYOFFICE == "y" ]
then
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ app:install documentserver_community
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ app:install onlyoffice
fi
rediscli=$(command -v redis-cli)
${rediscli} -s /var/run/redis/redis-server.sock <<EOF
FLUSHALL
quit
EOF
${systemctl} stop nginx
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ db:add-missing-primary-keys
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ db:add-missing-indices
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ db:add-missing-columns
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ db:convert-filecache-bigint
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ security:certificates:import /etc/ssl/certs/ssl-cert-snakeoil.pem
${sudo} -u www-data /usr/bin/php /var/www/nextcloud/occ config:app:set settings profile_enabled_by_default --value="0"
${clear}
nextcloud_scan_data
${systemctl} restart nginx
${echo} ""
${echo} "System optimizations... shouldn't take too long"
${echo} ""
${sudo} -u www-data /usr/bin/php -f /var/www/nextcloud/cron.php & CrI
# Hold Software
setHOLD
# E: LE certificates
if [ $LETSENCRYPT == "y" ]
then
${sudo} -i -u acmeuser bash << EOF
/home/acmeuser/.acme.sh/acme.sh --issue -d "${NEXTCLOUDDNS}" --server letsencrypt --keylength 4096 -w /var/www/letsencrypt --key-file /etc/letsencrypt/rsa-certs/privkey.pem --ca-file /etc/letsencrypt/rsa-certs/chain.pem --cert-file /etc/letsencrypt/rsa-certs/cert.pem --fullchain-file /etc/letsencrypt/rsa-certs/fullchain.pem --reloadcmd "sudo /bin/systemctl reload nginx.service"
EOF
${sudo} -i -u acmeuser bash << EOF
/home/acmeuser/.acme.sh/acme.sh --issue -d "${NEXTCLOUDDNS}" --server letsencrypt --keylength ec-384 -w /var/www/letsencrypt --key-file /etc/letsencrypt/ecc-certs/privkey.pem --ca-file /etc/letsencrypt/ecc-certs/chain.pem --cert-file /etc/letsencrypt/ecc-certs/cert.pem --fullchain-file /etc/letsencrypt/ecc-certs/fullchain.pem --reloadcmd "sudo /bin/systemctl reload nginx.service"
EOF
${sed} -i '/ssl-cert-snakeoil/d' /etc/nginx/conf.d/nextcloud.conf
${sed} -i s/#\ssl/\ssl/g /etc/nginx/conf.d/nextcloud.conf
${systemctl} restart nginx
fi
# System info
${echo} ""
${echo} "$CURRENTTIMEZONE"
${echo} ""
${date}
${echo} ""
$lsbrelease -ar
# Create Update Script
cd /home/"$USERNAME"/
${wget} -q https://github.com/JonathanHutchison/NextCloudInstallScript.git
${chmod} +x /home/"$USERNAME"/update.sh
# Final screen
${clear}
${echo} "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
${echo} ""
${echo} "Server - IP(v4):"
${echo} "----------------"
${echo} "$IPA"
${echo} ""
${echo} "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
${echo} ""
${echo} "Nextcloud:"
${echo} ""
${echo} "https://$NEXTCLOUDDNS or https://$IPA"
${echo} ""
${echo} "*******************************************************************************"
${echo} ""
${echo} "Nextcloud User/Pwd: $NEXTCLOUDADMINUSER // $NEXTCLOUDADMINUSERPASSWORD"
${echo} ""
${echo} "Passwordreset     : nocc user:resetpassword $NEXTCLOUDADMINUSER"
${echo} "                    <exit> and re-login <sudo -s> first, then <nocc> will work!"
${echo} ""
${echo} "Nextcloud datapath: $NEXTCLOUDDATAPATH"
${echo} ""
${echo} "Nextcloud DB      : nextcloud"
${echo} "Nextcloud DB-User : $NCDBUSER / $NCDBPASSWORD"
if [ $DATABASE == "m" ]
then
${echo} ""
${echo} "MariaDB-Rootpwd   : $MARIADBROOTPASSWORD"
fi
${echo} ""
${echo} "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
${echo} ""
${cat} /etc/motd
# Nextcloud-Log
${rm} -f /var/log/nextcloud/nextcloud.log
${sudo} -u www-data ${touch} /var/log/nextcloud/nextcloud.log
# occ Aliases (nocc)
if [ ! -f /root/.bash_aliases ]; then touch /root/.bash_aliases; fi
cat <<EOF >> /root/.bash_aliases
alias nocc="sudo -u www-data php /var/www/nextcloud/occ"
EOF
source /root/.bash_aliases
# Clean Up
${cat} /dev/null > ~/.bash_history && history -c && history -w
# Calculating runtime
${echo} ""
end=$(date +%s)
runtime=$((end-start))
echo ""
if [ "$runtime" -lt 60 ] || [ $runtime -ge "120" ]; then
echo "Installation completed in $((runtime/60)) minutes and $((runtime%60)) seconds."
else
echo "Installation completed in $((runtime/60)) minute and $((runtime%60)) seconds."
echo ""
fi
${echo} "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
${echo} ""
exit 0
