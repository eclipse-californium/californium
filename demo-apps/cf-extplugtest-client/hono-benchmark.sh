# !/bin/sh
# create benchmark statistic

echo "Californium CoAP Benchmark for Hono"
echo
echo "Requires a hono coap-adapter for exchanging messages."
echo
echo "Please check the available RAM (e.g.: on linux use \"free -m\") and"
echo "adjust the \"-Xmx6g\" argument in \"CF_OPT\" to about 30% of the available RAM"
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
echo "   USE_INTERVAL"
echo "   REQS"
echo "   UDP_CLIENTS"
echo "   HONO_AUTH"
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

export CALIFORNIUM_STATISTIC="2.4.0-hono"

# store psk credentials in "hono.psk"
#   format:
# auth-id@tenant-id=secret-in-base64
#   e.g.:
#A580000@DEFAULT_TENANT=Y29hcC1zZWNyZXQ=
#A580001@DEFAULT_TENANT=Y29hcC1zZWNyZXQ=
#A580002@DEFAULT_TENANT=Y29hcC1zZWNyZXQ=
#A580003@DEFAULT_TENANT=Y29hcC1zZWNyZXQ=
#...

: "${HONO_AUTH:=--psk-store hono.psk}"

if [ -z "$1" ]  ; then
     CLIENTS_MULTIPLIER=100
else 
    CLIENTS_MULTIPLIER=$1
    shift
fi

if [ -z "$1" ]  ; then
	kubectl="kubectl"
	if ! [ -x "$(command -v kubectl)" ]; then
	  if [ -x "$(command -v microk8s.kubectl)" ]; then
	     kubectl="microk8s.kubectl"
	  else
	     echo "missing kubectl, please provid hono-host!"
	     exit 1
	  fi
	fi

     CF_HOST=$($kubectl -n hono get service eclipse-hono-adapter-coap-vertx --output='jsonpath={.spec.clusterIP}')
     COAP_PORT=$($kubectl -n hono get service eclipse-hono-adapter-coap-vertx --output='jsonpath={.spec.ports[?(@.targetPort=="coap")].port}')
     COAPS_PORT=$($kubectl -n hono get service eclipse-hono-adapter-coap-vertx --output='jsonpath={.spec.ports[?(@.targetPort=="coaps")].port}')
 else 
    CF_HOST=$1
    shift
    if [ -z "$1" ]  ; then
       COAP_PORT=5683
       COAPS_PORT=5684
    else
      COAP_PORT=30683
      COAPS_PORT=30684
      shift
    fi
fi

# adjust the multiplier according the speed of your CPU
USE_PLAIN=0      # currently not implemented in benchmark!
USE_SECURE=1
USE_CAC=1
USE_NO_CAC=1
USE_EVENT=1
USE_TELEMETRY=1

USE_NONESTOP=--no-stop
: "${USE_INTERVAL:=--interval 50}"
MULTIPLIER=10
: "${REQS:=$((5 * $MULTIPLIER))}"
: "${UDP_CLIENTS:=$((1 * $CLIENTS_MULTIPLIER))}"

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

START_BENCHMARK=`date +%s`
echo ${CF_JAR}

benchmark_udp()
{
   if [ ${USE_PLAIN} -ne 0 ] ; then 
      java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} coap://${CF_HOST}:${COAP_PORT}/$@
      if [ ! $? -eq 0 ] ; then exit $?; fi
      sleep 5
   fi   
   if [ ${USE_SECURE} -ne 0 ] ; then 
      java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} ${HONO_AUTH} coaps://${CF_HOST}:${COAPS_PORT}/$@
      if [ ! $? -eq 0 ] ; then exit $?; fi
      sleep 5
   fi   
 }

benchmark_all()
{
   if [ ${USE_NO_CAC} -ne 0 ] ; then 
      if [ ${USE_TELEMETRY} -ne 0 ] ; then 
         benchmark_udp "telemetry"  --hono --clients ${UDP_CLIENTS} --requests ${REQS} ${USE_NONESTOP} ${USE_INTERVAL}
      fi
      if [ ${USE_EVENT} -ne 0 ] ; then 
         benchmark_udp "event"  --hono --clients ${UDP_CLIENTS} --requests ${REQS} ${USE_NONESTOP} ${USE_INTERVAL}
      fi
   fi
   if [ ${USE_CAC} -ne 0 ] ; then 
      if [ ${USE_TELEMETRY} -ne 0 ] ; then 
         benchmark_udp "telemetry?hono-ttd=10"  --hono --clients ${UDP_CLIENTS} --requests ${REQS} ${USE_NONESTOP} ${USE_INTERVAL}
      fi
      if [ ${USE_EVENT} -ne 0 ] ; then 
         benchmark_udp "event?hono-ttd=10"  --hono --clients ${UDP_CLIENTS} --requests ${REQS} ${USE_NONESTOP} ${USE_INTERVAL}
      fi
   fi
}

benchmark_dtls_handshake()
{
   if [ ${USE_SECURE} -ne 0 ] ; then 
      START_HS=`date +%s`
      i=0

      while [ $i -lt $1 ] ; do
         java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} $2 ${HONO_AUTH} "coaps://${CF_HOST}:${COAPS_PORT}/telemetry" --hono --clients ${UDP_CLIENTS} --requests 10
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

   echo "PSK      :" $TIME1
   echo "PSK/ECDHE:" $TIME2

   export CALIFORNIUM_STATISTIC=$old
}

START_BENCHMARK=`date +%s`

benchmark_all
benchmark_dtls_handshakes

END_BENCHMARK=`date +%s`

echo "ALL:" $((${END_BENCHMARK} - ${START_BENCHMARK}))
