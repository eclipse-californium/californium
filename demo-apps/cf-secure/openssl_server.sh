#! /bin/sh

echo "start openssl dtls server"

export CIPHERS_ECDSA=ECDHE-ECDSA-AES128-CCM8:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA384
export CIPHERS_PSK=PSK-AES128-CCM8:ECDHE-PSK-AES128-CBC-SHA256:PSK-AES128-GCM-SHA256:PSK-AES128-CBC-SHA256:PSK-AES128-CCM:PSK-AES256-CCM:PSK-AES256-GCM-SHA384
export PSK=73656372657450534b
export CURVE="-named_curve prime256v1"

echo "ciphers ecdsa:" ${CIPHERS_ECDSA}
echo "ciphers psk  :" ${CIPHERS_PSK}

openssl s_server -dtls1_2 -accept 127.0.0.1:5684 -listen -no-CAfile -cert server.pem ${CURVE} -cipher ${CIPHERS_ECDSA}:${CIPHERS_PSK} -psk ${PSK}
