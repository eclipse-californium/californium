# !/bin/sh
# create benchmark statistic

echo "Californium CoAP Benchmark"
echo
echo "Requires a cf-extplugtest-server for exchanging messages."
echo
echo "Please check the available RAM (e.g.: on linux use \"free -m\") and"
echo "adjust the \"-Xmx6g\" argument in \"CF_OPT\" to about 30% of the available RAM"
echo
echo "The required server may be started using:"
echo "java -d64 -Xmx6g -XX:+UseG1GC -jar cf-extplugtest-server-2.2.0-SNAPSHOT.jar -onlyLoopback -noPlugtest"
echo "Adjust the \"-Xmx6g\" argument also to about 30% of the available RAM."
echo "The benchmark is mainly used with the loopback interface (localhost), therefore -onlyLoopback is provided."
echo "To use client and server on different hosts, provide -noLoopback."
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
echo "Try to adjust the \"-Xmx\" to a larger value than the 30%."
echo
echo "Depending on your OS and configuration, the maximum number of sockets or threads may be limited."
echo "For linux, these maximum number may be increased, if the host has enough resources (RAM and CPU)"
echo "to execute it. On Ubunut 18.04, please adjust the values \"DefaultLimitNOFILE\" in \"/etc/systemd/user.conf\""
echo "and \"/etc/systemd/system.conf\" accordingly to the number of wanted sockets, and uncomment it by removing"
echo "the leading \"#\". For plain coap, currently more threads are required. Adjust \"UserTasksMax\" in"
echo "\"/etc/systemd/logind.conf\" to twice the number of sockets plus 500 more. With that, up to 10000"
echo "clients my be used for the benchmark. It's not recommended to use that many clients from one process"
echo "and it's even less recommended to use more!"
echo
echo "Variables:"
echo "   REQS"
echo "   NOTIFIES"
echo "   PAYLOAD"
echo "   PAYLOAD_LARGE"
echo "   UDP_CLIENTS"
echo "   TCP_CLIENTS"
echo "   OBS_CLIENTS"
echo "   CALI_AUTH"
echo
echo "These variables maybe override in the calling shell by"
echo
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

CF_JAR=cf-extplugtest-client-2.4.0-SNAPSHOT.jar
CF_JAR_FIND='cf-extplugtest-client-*.jar'
CF_EXEC="org.eclipse.californium.extplugtests.BenchmarkClient"
CF_OPT="-XX:+UseG1GC -Xmx6g -Xverify:none"

export CALIFORNIUM_STATISTIC="2.4.0"

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

# adjust the multiplier according the speed of your CPU
USE_TCP=1
USE_UDP=1
USE_PLAIN=1
USE_SECURE=1
USE_HTTP=0
USE_REVERSE=1
USE_OBSERVE=1
USE_NONESTOP=--no-stop

MULTIPLIER=10
: "${REQS:=$((500 * $MULTIPLIER))}"
REQS_EXTRA=$(($REQS + ($REQS/10)))
REV_REQS=$((2 * $REQS))
: "${NOTIFIES:=$((100 * $MULTIPLIER))}"

: "${PAYLOAD:=40}"
: "${PAYLOAD_LARGE:=400}"

: "${UDP_CLIENTS:=$((200 * $CLIENTS_MULTIPLIER))}"
: "${TCP_CLIENTS:=$((50 * $CLIENTS_MULTIPLIER))}"
: "${OBS_CLIENTS:=$((50 * $CLIENTS_MULTIPLIER))}"

: "${CALI_AUTH:=--psk-store cali.psk}"


if [ ! -s ${CF_JAR} ] ; then
# search for given version
   CF_JAR_TEST=`find -name ${CF_JAR} | head -n 1`
   if  [ -z "${CF_JAR_TEST}" ] ; then
     CF_JAR_TEST=`find .. -name ${CF_JAR} | head -n 1`
   fi
   if  [ -n "${CF_JAR_TEST}" ] ; then
      CF_JAR=${CF_JAR_TEST}
  fi
fi

if [ ! -s ${CF_JAR} ] ; then
# search for alternative available version
   CF_JAR_TEST=`find -name ${CF_JAR_FIND} ! -name "*sources.jar" | head -n 1`
   if  [ -z "${CF_JAR_TEST}" ] ; then
     CF_JAR_TEST=`find .. -name ${CF_JAR_FIND} ! -name "*sources.jar" | head -n 1`
   fi
   if  [ -n "${CF_JAR_TEST}" ] ; then
      echo "Found different version."
      echo "Using   ${CF_JAR_TEST}"
      echo "instead ${CF_JAR}"
      CF_JAR=${CF_JAR_TEST}
  fi
fi

if [ ! -s ${CF_JAR} ] ; then
   echo "Missing ${CF_JAR}"
   exit -1
fi

echo ${CF_JAR}

benchmark_udp()
{
   if [ ${USE_UDP} -eq 0 ] ; then return; fi
   if [ ${USE_PLAIN} -ne 0 ] ; then 
      java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} coap://${CF_HOST}:5783/$@
      if [ ! $? -eq 0 ] ; then exit $?; fi
      sleep 5
   fi   
   if [ ${USE_SECURE} -ne 0 ] ; then 
      java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} ${CF_SEC} ${CALI_AUTH} coaps://${CF_HOST}:5784/$@
      if [ ! $? -eq 0 ] ; then exit $?; fi
      sleep 5
   fi   
 }

benchmark_tcp()
{
   if [ ${USE_TCP} -eq 0 ] ; then return; fi
   if [ ${USE_PLAIN} -ne 0 ] ; then 
      java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} coap+tcp://${CF_HOST}:5783/$@
      if [ ! $? -eq 0 ] ; then exit $?; fi
      sleep 5
   fi
   if [ ${USE_SECURE} -ne 0 ] ; then 
      java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} coaps+tcp://${CF_HOST}:5784/$@
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
# GET
   benchmark_udp "benchmark?rlen=${PAYLOAD}" --clients ${UDP_CLIENTS} --requests ${REQS} ${USE_NONESTOP}
   benchmark_tcp "benchmark?rlen=${PAYLOAD}" --clients ${TCP_CLIENTS} --requests ${REQS} ${USE_NONESTOP}

# GET with separate response
   benchmark_udp "benchmark?rlen=${PAYLOAD}&ack" --clients ${UDP_CLIENTS} --requests ${REQS} ${USE_NONESTOP}

   if [ ${USE_OBSERVE} -eq 1 ] ; then
# reverse GET
      benchmark_udp "reverse-request?req=${REQS_EXTRA}&res=feed-CON&rlen=${PAYLOAD}" --clients ${UDP_CLIENTS} --requests 2 ${USE_NONESTOP} --reverse ${REV_REQS}
      benchmark_tcp "reverse-request?req=${REQS_EXTRA}&res=feed-CON&rlen=${PAYLOAD}" --clients ${TCP_CLIENTS} --requests 2 ${USE_NONESTOP} --reverse ${REV_REQS}
   fi
   
   if [ ${USE_OBSERVE} -eq 1 ] ; then
   
# observe CON 
      benchmark "reverse-observe?obs=25000&res=feed-CON&rlen=${PAYLOAD_LARGE}" --clients ${OBS_CLIENTS} --requests 1 ${USE_NONESTOP} --reverse ${NOTIFIES} --min 20 --max 100

# observe NON
      benchmark_udp "reverse-observe?obs=25000&res=feed-NON&rlen=${PAYLOAD_LARGE}" --clients ${OBS_CLIENTS} --requests 1 ${USE_NONESTOP} --reverse ${NOTIFIES} --min 20 --max 100	
   fi
}

benchmark_dtls_handshake()
{
   if [ ${USE_UDP} -eq 0 ] ; then return; fi
   if [ ${USE_SECURE} -ne 0 ] ; then 
      START_HS=`date +%s`
      i=0

      while [ $i -lt $1 ] ; do
         java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} $2 "coaps://${CF_HOST}:5784/benchmark?rlen=${PAYLOAD}" --clients ${UDP_CLIENTS} --requests 10
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
   if [ ${USE_UDP} -eq 0 ] ; then return; fi
   if [ ${USE_PLAIN} -ne 0 ] ; then
      if [ ${USE_HTTP} -ne 0 ] ; then 
         java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} "coap://${CF_HOST}:8000/http-target" --clients ${UDP_CLIENTS} --requests ${REQS} --proxy "localhost:5683:http"
         if [ ! $? -eq 0 ] ; then exit $?; fi
         sleep 5
      fi
      java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} "coap://${CF_HOST}:5783/benchmark?rlen=${PAYLOAD}" --clients ${UDP_CLIENTS} --requests ${REQS} --proxy "localhost:5683:coap"
      if [ ! $? -eq 0 ] ; then exit $?; fi
      sleep 5
   fi 
   if [ ${USE_SECURE} -ne 0 ] ; then
      java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} "coap://${CF_HOST}:5784/benchmark?rlen=${PAYLOAD}" --clients ${UDP_CLIENTS} --requests ${REQS} --proxy "localhost:5683:coaps"
      if [ ! $? -eq 0 ] ; then exit $?; fi
      sleep 5
   fi 
}

START_BENCHMARK=`date +%s`

#proxy
benchmark_all
benchmark_dtls_handshakes

END_BENCHMARK=`date +%s`

echo "ALL:" $((${END_BENCHMARK} - ${START_BENCHMARK}))
