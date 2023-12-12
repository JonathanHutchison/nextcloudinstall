#!/bin/bash

# Check if the script is being run as root
if [ "$(id -u)" != "0" ]; then
    clear
    echo ""
    echo "*****************************"
    echo "* Run as root               *"
    echo "*****************************"
    echo ""
    exit 1
fi

read -p "Full domain name for server ex: example.test.com: " DOMAINNAME

cat=$(command -v cat)
apt=$(command -v apt-get)
chmod=$(command -v chmod)
${apt} install -y nginx
${cat} <<EOF > /etc/nginx/sites-available/$DOMAINNAME
stream {
    upstream backend {
        server https://$DOMAINNAME:55108/login;  # Nextcloud url and SSL port
    }

    server {
        listen 443;
        proxy_pass backend;
        proxy_buffering off;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;
        ssl_preread on;  # Enables SNI support and lets Nginx read SSL information without decrypting
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/$DOMAINNAME /etc/nginx/sites-enabled/$DOMAINNAME
sudo rm /etc/nginx/sites-enabled/default
service nginx configtest
sudo systemctl restart nginx
sudo systemctl enable nginx
