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
echo "java -d64 -Xmx6g -XX:+UseG1GC -jar cf-extplugtest-server-2.1.0-SNAPSHOT.jar -onlyLoopback -noPlugtest"
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
echo "Note: sometimes the recommended default configuration is changed." 
echo "      Please delete therefore the \"Californium???.properties\" to apply the changes." 
echo

# commands to check several limits
# cat /proc/sys/kernel/threads-max
# cat /proc/sys/kernel/pid_max
# cat /proc/sys/vm/max_map_count
# prlimit

export COAP_HONO="true"
export PSK_CREDENTIALS="hono.psk"

CF_JAR=cf-extplugtest-client-2.3.0-SNAPSHOT.jar
CF_EXEC="org.eclipse.californium.extplugtests.BenchmarkClient"
CF_OPT="-XX:+UseG1GC -Xmx6g -Xverify:none -Dcalifornium.statistic=2.3.0-hono"

if [ -z "$1" ]  ; then
     CF_HOST=coap-int.bosch-iot-hub.com
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
     COAP_PORT=5683
     COAPS_PORT=5684
else 
     COAP_PORT=30683
     COAPS_PORT=30684
    shift
fi

# adjust the multiplier according the speed of your CPU
USE_PLAIN=0
USE_SECURE=1
REQS=$((5000 * $CLIENTS_MULTIPLIER))

UDP_CLIENTS=$((50 * $CLIENTS_MULTIPLIER))

if [ ! -s ${CF_JAR} ] ; then
   if  [ -s target/${CF_JAR} ] ; then
      CF_JAR=target/${CF_JAR}
   elif [ -s ../${CF_JAR} ] ; then
      CF_JAR=../${CF_JAR}
   elif [ -s ../target/${CF_JAR} ] ; then
      CF_JAR=../target/${CF_JAR}
   fi
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
      java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} coaps://${CF_HOST}:${COAPS_PORT}/$@
      if [ ! $? -eq 0 ] ; then exit $?; fi
      sleep 5
   fi   
 }


benchmark_all()
{
# GET
	benchmark_udp "telemetry" ${UDP_CLIENTS} ${REQS}
}

benchmark_dtls_handshake()
{
   if [ ${USE_SECURE} -ne 0 ] ; then 
      START_HS=`date +%s`
      i=0
      while [ $i -lt $1 ] ; do
	java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} $2 "coaps://${CF_HOST}:${COAPS_PORT}/telemetry" ${UDP_CLIENTS} 10
	if [ ! $? -eq 0 ] ; then exit $?; fi
	sleep 2
	i=$(($i + 1))
      done
      END_HS=`date +%s`
      TIME=$(($END_HS - $START_HS))
      return $TIME	
   fi 
}

benchmark_all
benchmark_dtls_handshake 10 
TIME1=$?

echo "PSK      :" $TIME1

END_BENCHMARK=`date +%s`

echo "ALL:" $(($END_BENCHMARK - $START_BENCHMARK))
