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
echo "java -d64 -Xmx6g -XX:+UseG1GC -jar cf-extplugtest-server-2.0.0-SNAPSHOT.jar -onlyLoopback -noPlugtest"
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
echo "Note: sometimes the recommended default configuration is changed." 
echo "      Please delete therefore the \"Californium???.properties\" to apply the changes." 
echo

CF_JAR=cf-extplugtest-client-2.0.0-SNAPSHOT.jar
CF_EXEC="org.eclipse.californium.extplugtests.BenchmarkClient"
CF_OPT="-d64 -XX:+UseG1GC -Xmx6g -Dcalifornium.statistic=M18"
CF_HOST=localhost

# adjust the multiplier according the speed of your CPU
USE_TCP=0
USE_PLAIN=1
USE_SECURE=1
MULTIPLIER=10
REQS=$((500 * $MULTIPLIER))
REQS_EXTRA=$(($REQS + ($REQS/10)))
REV_REQS=$((2 * $REQS))
NOTIFIES=$((100 * $MULTIPLIER))

PAYLOAD=40
PAYLOAD_LARGE=400

echo ${REV_REQS2}

CLIENTS_MULTIPLIER=10
UDP_CLIENTS=$((200 * $CLIENTS_MULTIPLIER))
TCP_CLIENTS=$((50 * $CLIENTS_MULTIPLIER))
OBS_CLIENTS=$((50 * $CLIENTS_MULTIPLIER))

if [ ! -s ${CF_JAR} ] && [ -s target/${CF_JAR} ]  ; then
   CF_JAR=target/${CF_JAR}
elif [ ! -s ${CF_JAR} ] && [ -s ../${CF_JAR} ]  ; then
   CF_JAR=../${CF_JAR}
fi

START_BENCHMARK=`date +%s`
ulimit -S -n 4096
ulimit -S -n
echo ${CF_JAR}

benchmark_udp()
{
   if [ ${USE_PLAIN} -ne 0 ] ; then 
      java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} coap://${CF_HOST}:5783/$@
      if [ ! $? -eq 0 ] ; then exit $?; fi
      sleep 5
   fi   
   if [ ${USE_SECURE} -ne 0 ] ; then 
      java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} coaps://${CF_HOST}:5784/$@
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
	benchmark_udp "benchmark?rlen=${PAYLOAD}" ${UDP_CLIENTS} ${REQS}
	benchmark_tcp "benchmark?rlen=${PAYLOAD}" ${TCP_CLIENTS} ${REQS}

# reverse GET
	benchmark_udp "reverse-request?req=${REQS_EXTRA}&res=feed-CON&rlen=${PAYLOAD}" ${UDP_CLIENTS} 2 stop ${REV_REQS}
	benchmark_tcp "reverse-request?req=${REQS_EXTRA}&res=feed-CON&rlen=${PAYLOAD}" ${TCP_CLIENTS} 2 stop ${REV_REQS}

# observe CON 
	benchmark "reverse-observe?obs=25000&res=feed-CON&rlen=${PAYLOAD_LARGE}" ${OBS_CLIENTS} 1 stop ${NOTIFIES} 20 100

# observe NON
	benchmark_udp "reverse-observe?obs=25000&res=feed-NON&rlen=${PAYLOAD_LARGE}" ${OBS_CLIENTS} 1 stop ${NOTIFIES} 20 100
	
}

benchmark_dtls_handshake()
{
   if [ ${USE_SECURE} -ne 0 ] ; then 
      i=0
      while [ $i -lt $1 ] ; do
	java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} -r "coaps://${CF_HOST}:5784/benchmark?rlen=${PAYLOAD}" ${UDP_CLIENTS} 10
	if [ ! $? -eq 0 ] ; then exit $?; fi
	sleep 2
	i=$(($i + 1))
      done
   fi   
}

longterm()
{
# in seconds
	LONG_INTERVAL_S=$((60 * 5))
	LONG_INTERVAL_MS=$(($LONG_INTERVAL_S * 1000))
	LONG_INTERVAL_TIMEOUT_S=$(($LONG_INTERVAL_S + 30))

# long term observe NON
	benchmark_udp "reverse-observe?obs=2500000&res=feed-NON&timeout=${LONG_INTERVAL_TIMEOUT_S}&rlen=${PAYLOAD}" ${UDP_CLIENTS} 1 stop ${NOTIFIES} ${LONG_INTERVAL_MS}
}

benchmark_all
benchmark_all
benchmark_all
benchmark_dtls_handshake 25
#longterm

END_BENCHMARK=`date +%s`

echo $(($END_BENCHMARK - $START_BENCHMARK))
