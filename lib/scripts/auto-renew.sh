#!/bin/bash
# Created by Shane Nielson <snielson@projectuminfinitas.com>
# Bash script to check the time left on mobility certs, and renew with LetsEncrypt if needed

if [ -z $1 ] || [ -z $2 ] || [ -z $3 ];then
    echo "Usage: ${0##*/} <domain name> <days left> <tls port>"
    exit 1
fi

ACME_PATH="/root/.acme.sh"
DOMAIN="$1"
GMS_DEVICE_CERT_PATH="/var/lib/datasync/device"
GMS_ADMIN_CERT_PATH="/var/lib/datasync/webadmin"
DAYS_LEFT=$(expr $2 \* 24 \* 60 \* 60)
UPDATED=false
ACME_LOG="/opt/novell/datasync/tools/dsapp/logs/acme.log"

# Get expiry
function getExpiry {
    expire=`/usr/bin/openssl x509 -checkend "$DAYS_LEFT" -in "$GMS_DEVICE_CERT_PATH"/mobility.pem`
    if (`echo $expire | grep -q "will expire"`); then
        return 1
    else
        return 0
    fi
}

# If expiry close, generate new cert
getExpiry
return_code=$?
if [ $return_code -eq 1 ]; then
    /etc/init.d/gms stop
    $ACME_PATH/acme.sh --issue -d $DOMAIN --tls --tlsport $3 --force --debug --log $ACME_LOG --no-color
    
    # Create the new mobility.pem
    cat "$ACME_PATH"/"$DOMAIN"/"$DOMAIN".key "$ACME_PATH"/"$DOMAIN"/fullchain.cer > "$GMS_DEVICE_CERT_PATH"/mobility.pem
    cat "$ACME_PATH"/"$DOMAIN"/"$DOMAIN".key "$ACME_PATH"/"$DOMAIN"/fullchain.cer > "$GMS_ADMIN_CERT_PATH"/server.pem
    /etc/init.d/gms start
    UPDATED=true

elif [ $return_code -eq 0 ]; then
    echo "Certificate is still valid"
fi

# Print new mobility.pem dates
if ($UPDATED); then
    /usr/bin/openssl x509 -noout -dates -in "$GMS_DEVICE_CERT_PATH"/mobility.pem
fi
