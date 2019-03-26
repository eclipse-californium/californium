# !/bin/sh
# create benchmark statistic

CF_JAR=cf-extplugtest-client-2.0.0-SNAPSHOT.jar
CF_EXEC=org.eclipse.californium.extplugtests.BenchmarkClient
CF_OPT="-d64 -XX:+UseG1GC -Xmx6g -Dcalifornium.statistic=M13"
CF_HOST=localhost

if [ ! -s ${CF_JAR} ] && [ -s target/${CF_JAR} ]  ; then
   CF_JAR=target/${CF_JAR}
fi

START_BENCHMARK=`date +%s`
ulimit -S -n 4096
ulimit -S -n
echo ${CF_JAR}

benchmark_udp()
{
   java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} coap://${CF_HOST}:5783/$@
   if [ ! $? -eq 0 ] ; then exit $?; fi
   sleep 5
   java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} coaps://${CF_HOST}:5784/$@
   if [ ! $? -eq 0 ] ; then exit $?; fi
   sleep 5
}

benchmark_tcp()
{
   java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} coap+tcp://${CF_HOST}:5783/$@
   if [ ! $? -eq 0 ] ; then exit $?; fi
   sleep 5
   java ${CF_OPT} -cp ${CF_JAR} ${CF_EXEC} coaps+tcp://${CF_HOST}:5784/$@
   if [ ! $? -eq 0 ] ; then exit $?; fi
   sleep 5
}

benchmark()
{
   benchmark_udp $@
   benchmark_tcp $@
}

# GET
benchmark_udp "benchmark?rlen=40" 2000 5000
benchmark_tcp "benchmark?rlen=40" 500 5000

# reverse GET
benchmark_udp "reverse-request?req=6000&res=feed-CON&rlen=40" 2000 2 stop 10000
benchmark_tcp "reverse-request?req=6000&res=feed-CON&rlen=40" 500 2 stop 10000

# observe CON 
benchmark "reverse-observe?obs=25000&res=feed-CON&rlen=400" 500 1 stop 1000 20 100

# observe NON
benchmark_udp "reverse-observe?obs=25000&res=feed-NON&rlen=400" 500 1 stop 1000 20 100

END_BENCHMARK=`date +%s`

echo $(($END_BENCHMARK - $START_BENCHMARK))

