#!/bin/sh

#/*******************************************************************************
# * Copyright (c) 2020 Bosch.IO GmbH and others.
# * 
# * All rights reserved. This program and the accompanying materials
# * are made available under the terms of the Eclipse Public License v2.0
# * and Eclipse Distribution License v1.0 which accompany this distribution.
# * 
# * The Eclipse Public License is available at
# *    http://www.eclipse.org/legal/epl-v20.html
# * and the Eclipse Distribution License is available at
# *    http://www.eclipse.org/org/documents/edl-v10.html.
# * 
# * Contributors:
# *    Achim Kraus (Bosch.IO GmbH) - initial script
# ******************************************************************************/

# create benchmark statistic

echo "Californium CoAP Benchmark"
echo
echo "Requires a cf-extplugtest-server for exchanging messages."
echo
echo "Please check the available RAM (e.g.: on linux use \"free -m\") and"
echo "adjust the \"-Xmx6g\" argument in \"CF_OPT\" to about 50% of the available RAM."
echo "For newer JVMs the \"-XX:MaxRAMPercentage=50\" argument in \"CF_OPT\" may be used instead."
echo
echo "The required server may be started using:"
echo "java -Xmx6g -XX:+UseG1GC -jar cf-extplugtest-server-3.10.0.jar --no-external --no-plugtest"
echo "Adjust the \"-Xmx6g\" argument also to about 50% of the available RAM."
echo "For newer JVMs the \"-XX:MaxRAMPercentage=50\" argument in \"CF_OPT\" may also be used instead."
echo "If the benchmark is mainly used with the loopback interface (localhost), use the --no-external as above."
echo "To use client and server on different hosts, provide --no-loopback instead."
echo
echo "If the cf-extplugtest-server reports:"
echo
echo "   Maxium heap size: ????M 84% used."
echo "   Heap may exceed! Enlarge the maxium heap size."
echo "   Or consider to reduce the value of EXCHANGE_LIFETIME"
echo "   in \"CaliforniumReceivetest.properties\" or set"
echo "   DEDUPLICATOR to NO_DEDUPLICATOR there."
echo
echo "you have a too fast CPU for the available amount of RAM :-)."
echo "Try to adjust the \"-Xmx\" to a larger value than the 50%."
echo
echo "Depending on your OS and configuration, the maximum number of sockets or threads may be limited."
echo
echo "Some cloud-provider use containers instead of real (or virtual) machines, which results in many"
echo "cases in lower limits. Check, if \"/proc/user_beancounters\" is available, and if so, check the"
echo "number of \"numproc\". That is mostly enough for servers, but for the benchmark client this limits"
echo "currently the number of clients to less than the half of the value of \"numproc\"."
echo
echo "For real (or virtual) machines with linux, the maximum number may be increased, if the host has"
echo "enough resources (RAM and CPU) to execute it. On Ubuntu 18.04, please adjust the values"
echo "\"DefaultLimitNOFILE\" in \"/etc/systemd/user.conf\" and \"/etc/systemd/system.conf\" accordingly"
echo "to the number of wanted sockets, and uncomment it by removing the leading \"#\"."
echo "For plain coap, currently more threads are required. Adjust \"UserTasksMax\" in"
echo "\"/etc/systemd/logind.conf\" to twice the number of sockets plus 500 more. With that, up to 10000"
echo "clients my be used for the benchmark. It's not recommended to use that many clients from one process"
echo "and it's even less recommended to use more than that!"
echo
echo "Variables:"
echo "   USE_TCP, USE_UDP, USE_PLAIN, USE_SECURE, USE_CON, USE_NON"
echo "   UDP_CLIENTS, TCP_CLIENTS, OBS_CLIENTS"
echo "   PLAIN_PORT, SECURE_PORT"
echo "   USE_REVERSE, USE_OBSERVE"
echo "   REQS, NOTIFIES"
echo "   PAYLOAD, PAYLOAD_LARGE, CALI_AUTH"
echo "   USE_HTTP (coap2http proxy only!)"
echo
echo "These variables maybe override in the calling shell by"
echo
echo "export USE_TCP=0"
echo "export REQS=10"
echo
echo "Note: sometimes the recommended default configuration is changed."
echo "      Please delete therefore the \"Californium???.properties\" to apply the changes."
echo

# commands to check several limits
# cat /proc/sys/kernel/threads-max
# cat /proc/sys/kernel/pid_max
# cat /proc/sys/vm/max_map_count
# prlimit

CF_JAR=cf-extplugtest-client-3.11.0.jar
CF_JAR_FIND="cf-extplugtest-client-*.jar"
CF_EXEC="org.eclipse.californium.extplugtests.BenchmarkClient"
#CF_OPT="-XX:+UseG1GC -Xmx6g -Xverify:none"
CF_OPT="-XX:+UseZGC -Xmx10g"

export CALIFORNIUM_STATISTIC="3.11.0"

if [ -z "$1" ]  ; then
     CF_HOST=localhost
else
    CF_HOST=$1
    shift
fi

if [ -z "$1" ]  ; then
     CLIENTS_MULTIPLIER=10
else
    CLIENTS_MULTIPLIER=$1
    shift
fi

if [ -z "$1" ]  ; then
     CF_SEC=
else
    CF_SEC=$1
    shift
fi

: "${PLAIN_PORT:=5783}"
: "${SECURE_PORT:=5784}"
: "${RESOURCE_PATH:=benchmark}"

# 0 := disable, 1 := enable
: "${USE_TCP:=1}"
: "${USE_UDP:=1}"
: "${USE_PLAIN:=1}"
: "${USE_SECURE:=1}"
: "${USE_CON:=3}"                         # 0:= not used, 1 := used with piggybacked response, 2 := with separate response, 3 := both variants  
: "${USE_NON:=1}"
: "${USE_LARGE_BLOCK1:=1}"

: "${USE_REQUEST:=1}"
: "${USE_OBSERVE:=1}"
: "${USE_REVERSE:=1}"
: "${USE_REVERSE_OBSERVE:=1}"
: "${USE_HANDSHAKES:=1}"
: "${USE_PROXY:=0}"
: "${USE_HTTP:=0}"

: "${USE_NONESTOP:=--no-stop}"
# may be "misused" for other arguments, e.g. "--no-stop --handshakes-full=5" for full handshakes after 5 requests.

: "${USE_NSTART:=--nstart 1}"

# export EXECUTER_REMOVE_ON_CANCEL=true
# export EXECUTER_LOGGING_QUEUE_SIZE_DIFF=1000

# adjust the multiplier according the speed of your CPU

MULTIPLIER=10
: "${REQS:=$((1000 * $MULTIPLIER))}"
REQS_EXTRA=$(($REQS + ($REQS/10)))
REV_REQS=$((2 * $REQS))
: "${NOTIFIES:=$((350 * $MULTIPLIER))}"
: "${REV_NOTIFIES:=$NOTIFIES}"

: "${PAYLOAD:=40}"
: "${PAYLOAD_MEDIUM:=400}"
: "${PAYLOAD_LARGE:=5000}"
: "${REQS_LARGE:=$(($PAYLOAD * $REQS / $PAYLOAD_LARGE))}"

: "${UDP_CLIENTS:=$((200 * $CLIENTS_MULTIPLIER))}"
: "${TCP_CLIENTS:=$((100 * $CLIENTS_MULTIPLIER))}"
: "${OBS_CLIENTS:=$((100 * $CLIENTS_MULTIPLIER))}"

: "${CALI_AUTH:=--psk-store cali.psk}"

if [ ! -s "${CF_JAR}" ] ; then
   echo "search for ${CF_JAR}"
# search for given version
   CF_JAR_TEST=`find -name ${CF_JAR} | head -n 1`
   if  [ -z "${CF_JAR_TEST}" ] ; then
     CF_JAR_TEST=`find .. -name ${CF_JAR} | head -n 1`
   fi
   if  [ -n "${CF_JAR_TEST}" ] ; then
      CF_JAR=${CF_JAR_TEST}
   fi
fi

if [ ! -s "${CF_JAR}" ] ; then
   echo "search for ${CF_JAR_FIND}"
# search for alternative available version
   CF_JAR_TEST=`find -name "${CF_JAR_FIND}" ! -name "*sources.jar" | sort -r | head -n 1`
   if  [ -z "${CF_JAR_TEST}" ] ; then
     CF_JAR_TEST=`find .. -name "${CF_JAR_FIND}" ! -name "*sources.jar" | sort -r | head -n 1`
   fi
   echo "found ${CF_JAR_TEST}"
   if  [ -n "${CF_JAR_TEST}" ] ; then
      echo "Found different version."
      echo "Using   ${CF_JAR_TEST}"
      echo "instead ${CF_JAR}"
      CF_JAR=${CF_JAR_TEST}
  fi
fi

if [ ! -s "${CF_JAR}" ] ; then
   echo "Missing ${CF_JAR}"
   exit -1
fi

echo ${CF_JAR}

benchmark_udp()
{
   if [ ${USE_UDP} -eq 0 ] ; then return; fi
   if [ ${USE_PLAIN} -ne 0 ] ; then
      java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} coap://${CF_HOST}:${PLAIN_PORT}/$@
      if [ ! $? -eq 0 ] ; then exit $?; fi
      sleep 5
   fi
   if [ ${USE_SECURE} -ne 0 ] ; then
      java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} ${CF_SEC} ${CALI_AUTH} coaps://${CF_HOST}:${SECURE_PORT}/$@
      if [ ! $? -eq 0 ] ; then exit $?; fi
      sleep 5
   fi
 }

benchmark_tcp()
{
   if [ ${USE_TCP} -eq 0 ] ; then return; fi
   if [ ${USE_PLAIN} -ne 0 ] ; then
      java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} coap+tcp://${CF_HOST}:${PLAIN_PORT}/$@
      if [ ! $? -eq 0 ] ; then exit $?; fi
      sleep 5
   fi
   if [ ${USE_SECURE} -ne 0 ] ; then
      java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} coaps+tcp://${CF_HOST}:${SECURE_PORT}/$@
      if [ ! $? -eq 0 ] ; then exit $?; fi
      sleep 5
   fi
}

benchmark()
{
   benchmark_udp $@
   benchmark_tcp $@
}

benchmark_all()
{
# POST
   if [ ${USE_REQUEST} -eq 1 ] ; then
#    Large Payload
      if [ ${USE_LARGE_BLOCK1} -ne 0 ] ; then
         if [ ${USE_CON} -eq 1 ] || [ ${USE_CON} -eq 3 ] ; then
            benchmark_udp "${RESOURCE_PATH}?rlen=${PAYLOAD}" --clients ${UDP_CLIENTS} --requests ${REQS_LARGE} ${USE_NONESTOP} --payload-random ${PAYLOAD_LARGE} --blocksize 64
         fi
         if [ ${USE_NON} -ne 0 ] ; then
            benchmark_udp "${RESOURCE_PATH}?rlen=${PAYLOAD}" --clients ${UDP_CLIENTS} --non --requests ${REQS_LARGE} ${USE_NONESTOP} --payload-random ${PAYLOAD_LARGE} --blocksize 64
         fi
         benchmark_tcp "${RESOURCE_PATH}?rlen=${PAYLOAD}" --clients ${TCP_CLIENTS} --requests ${REQS_LARGE} ${USE_NONESTOP} --payload-random ${PAYLOAD_LARGE} --bertblocks 4
      fi

#    Small Payload
      if [ ${USE_CON} -eq 1 ] || [ ${USE_CON} -eq 3 ] ; then
         benchmark_udp "${RESOURCE_PATH}?rlen=${PAYLOAD}" --clients ${UDP_CLIENTS} --requests ${REQS} ${USE_NONESTOP} ${USE_NSTART} --payload-random ${PAYLOAD}
      fi

      if [ ${USE_NON} -ne 0 ] ; then
         benchmark_udp "${RESOURCE_PATH}?rlen=${PAYLOAD}" --clients ${UDP_CLIENTS} --non --requests ${REQS} ${USE_NONESTOP} ${USE_NSTART} --payload-random ${PAYLOAD}
      fi
      benchmark_tcp "${RESOURCE_PATH}?rlen=${PAYLOAD}" --clients ${TCP_CLIENTS} --requests ${REQS} ${USE_NONESTOP} --payload-random ${PAYLOAD}

# POST separate response
      if [ ${USE_CON} -eq 2 ] || [ ${USE_CON} -eq 3 ] ; then
         benchmark_udp "${RESOURCE_PATH}?rlen=${PAYLOAD}&ack" --clients ${UDP_CLIENTS} --requests ${REQS} ${USE_NONESTOP} ${USE_NSTART} --payload-random ${PAYLOAD}
      fi
   fi

   if [ ${USE_OBSERVE} -eq 1 ] ; then
      benchmark_udp "${RESOURCE_PATH}?rlen=${PAYLOAD}" --clients ${OBS_CLIENTS} --requests 1 ${USE_NONESTOP} --notifies ${NOTIFIES} --reregister 25 --register 75 
      benchmark_udp "${RESOURCE_PATH}?rlen=${PAYLOAD}" --clients ${OBS_CLIENTS} --requests 1 ${USE_NONESTOP} --notifies ${NOTIFIES} --reregister 25 --register 75 --cancel-proactive
      benchmark_tcp "${RESOURCE_PATH}?rlen=${PAYLOAD}" --clients ${OBS_CLIENTS} --requests 1 ${USE_NONESTOP} --notifies ${NOTIFIES} --reregister 25 --register 75
      benchmark_tcp "${RESOURCE_PATH}?rlen=${PAYLOAD}" --clients ${OBS_CLIENTS} --requests 1 ${USE_NONESTOP} --notifies ${NOTIFIES} --reregister 25 --register 75 --cancel-proactive
   fi

   if [ ${USE_REVERSE} -eq 1 ] ; then
# reverse GET
      if [ ${USE_CON} -ne 0 ] ; then
         benchmark_udp "reverse-request?req=${REQS_EXTRA}&res=feed-CON&rlen=${PAYLOAD}" --clients ${UDP_CLIENTS} --requests 2 ${USE_NONESTOP} --reverse ${REV_REQS}
      fi
      if [ ${USE_NON} -ne 0 ] ; then
         benchmark_udp "reverse-request?req=${REQS_EXTRA}&res=feed-CON&rlen=${PAYLOAD}" --clients ${UDP_CLIENTS} --non --requests 2 ${USE_NONESTOP} --reverse ${REV_REQS}
      fi
      benchmark_tcp "reverse-request?req=${REQS_EXTRA}&res=feed-CON&rlen=${PAYLOAD}" --clients ${TCP_CLIENTS} --requests 2 ${USE_NONESTOP} --reverse ${REV_REQS}
   fi

   if [ ${USE_REVERSE_OBSERVE} -eq 1 ] ; then
# reverse observe CON
      if [ ${USE_CON} -ne 0 ] ; then
          benchmark_udp "reverse-observe?obs=25000&res=feed-CON&rlen=${PAYLOAD_MEDIUM}" --clients ${OBS_CLIENTS} --requests 1 ${USE_NONESTOP} --reverse ${REV_NOTIFIES} --min -200 --max 200 --blocksize 64
      fi
# reverse observe NON
      if [ ${USE_CON} -ne 0 ] ; then
         benchmark_udp "reverse-observe?obs=25000&res=feed-NON&rlen=${PAYLOAD_MEDIUM}" --clients ${OBS_CLIENTS} --requests 1 ${USE_NONESTOP} --reverse ${REV_NOTIFIES} --min -200 --max 200 --blocksize 64
      fi
      benchmark_tcp "reverse-observe?obs=25000&res=feed-CON&rlen=${PAYLOAD_MEDIUM}" --clients ${OBS_CLIENTS} --requests 1 ${USE_NONESTOP} --reverse ${REV_NOTIFIES} --min -200 --max 200 --blocksize 64
   fi
}

benchmark_dtls_handshake()
{
   if [ ${USE_UDP} -eq 0 ] ; then return; fi
   if [ ${USE_SECURE} -ne 0 ] ; then
      START_HS=`date +%s`
      i=0

      while [ $i -lt $1 ] ; do
         java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} $2 "coaps://${CF_HOST}:${SECURE_PORT}/${RESOURCE_PATH}?rlen=${PAYLOAD}" --clients ${UDP_CLIENTS} --requests 10 ${USE_NONESTOP}
         if [ ! $? -eq 0 ] ; then exit $?; fi
         sleep 2
         i=$(($i + 1))
      done
      END_HS=`date +%s`
      TIME=$((${END_HS} - ${START_HS}))
      return $TIME
   fi
}

benchmark_dtls_handshakes()
{
   if [ ${USE_HANDSHAKES} -eq 0 ] || [ ${USE_UDP} -eq 0 ] || [ ${USE_SECURE} -eq 0 ] ; then return; fi

   old=$CALIFORNIUM_STATISTIC
   export CALIFORNIUM_STATISTIC=
   LOOPS=10

   benchmark_dtls_handshake $LOOPS
   TIME1=$?
   benchmark_dtls_handshake $LOOPS --auth=ECDHE_PSK
   TIME2=$?
   benchmark_dtls_handshake $LOOPS --auth=RPK
   TIME3=$?
   benchmark_dtls_handshake $LOOPS --auth=X509
   TIME4=$?

   echo "PSK      :" $TIME1
   echo "PSK/ECDHE:" $TIME2
   echo "RPK      :" $TIME3
   echo "X509     :" $TIME4

   export CALIFORNIUM_STATISTIC=$old
}

longterm()
{
# in seconds
   LONG_INTERVAL_S=$((60 * 5))
   LONG_INTERVAL_MS=$(($LONG_INTERVAL_S * 1000))
   LONG_INTERVAL_TIMEOUT_S=$(($LONG_INTERVAL_S + 30))

# long term observe NON
   benchmark_udp "reverse-observe?obs=2500000&res=feed-NON&timeout=${LONG_INTERVAL_TIMEOUT_S}&rlen=${PAYLOAD}" --clients ${UDP_CLIENTS} -requests --requests 1 ${USE_NONESTOP} --reverse ${NOTIFIES} --min ${LONG_INTERVAL_MS}
}

proxy()
{
   if [ ${USE_PROXY} -eq 0 ] || [ ${USE_UDP} -eq 0 ] ; then return; fi
   if [ ${USE_PLAIN} -ne 0 ] ; then
      if [ ${USE_HTTP} -ne 0 ] ; then 
         java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} "coap://${CF_HOST}:8000/http-target" --clients ${UDP_CLIENTS} --requests ${REQS} --proxy "localhost:5683:http"
         if [ ! $? -eq 0 ] ; then exit $?; fi
         sleep 5
      fi
      java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} "coap://${CF_HOST}:${PLAIN_PORT}/${RESOURCE_PATH}?rlen=${PAYLOAD}" --clients ${UDP_CLIENTS} --requests ${REQS} --proxy "localhost:5683:coap"
      if [ ! $? -eq 0 ] ; then exit $?; fi
      sleep 5
   fi 
   if [ ${USE_SECURE} -ne 0 ] ; then
      java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} "coap://${CF_HOST}:${SECURE_PORT}/${RESOURCE_PATH}?rlen=${PAYLOAD}" --clients ${UDP_CLIENTS} --requests ${REQS} --proxy "localhost:5683:coaps"
      if [ ! $? -eq 0 ] ; then exit $?; fi
      sleep 5
   fi 
}

START_BENCHMARK=$(date +%s)

proxy
benchmark_all
benchmark_dtls_handshakes

END_BENCHMARK=$(date +%s)

echo "ALL:" $((${END_BENCHMARK} - ${START_BENCHMARK}))
