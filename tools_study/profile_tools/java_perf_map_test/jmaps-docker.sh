#!/bin/bash

AGENT_HOME=${AGENT_HOME:-/usr/lib/jvm/perf-map-agent}  # from https://github.com/jvm-profiling-tools/perf-map-agent
debug=1

if [[ "$USER" != root ]]; then
	echo "ERROR: not root user? exiting..."
	exit
fi

if [[ $# == 0 ]]; then
    echo "Help: ./jmaps-docker [-u] <container-id>"
    exit
elif [[ $# > 2 ]]; then
    echo "ERROR: to many arguments"
    exit
fi

CONTAINERID=$1
if [[ "$1" == "-u" ]]; then
	opts=unfoldall
    CONTAINERID=$2
fi

CONTAINER_JAVA_HOME=$(sudo docker exec -it $CONTAINERID /bin/bash -c 'echo $JAVA_HOME' | tr -d '\n\r')
if [[ -z $CONTAINER_JAVA_HOME ]]; then
	echo "ERROR: CONTAINER_JAVA_HOME not set correctly"
	exit
fi
(( debug )) && echo "CONTAINER_JAVA_HOME=$CONTAINER_JAVA_HOME"

# TODO: 判断docker的drive stroage
pid=$(sudo docker inspect $CONTAINERID | jq -r .[0].State.Pid)  # overlay2
if [[ -z pid ]]; then 
    echo "ERROR: get container $CONTAINERID pid for failed"
    exit
fi

if [[ ! -x $AGENT_HOME ]]; then
	echo "ERROR: AGENT_HOME not set correctly; edit $0 and fix"
	exit
fi


# 在宿主上获取容器目录
MERGEDIR=$(sudo docker inspect $CONTAINERID | jq -r .[0].GraphDriver.Data.MergedDir)   # overlay2
if [[ ! -n $MERGEDIR ]]; then
    echo "ERROR: get container $CONTAINERID MERGEDIR for failed"
    exit
fi
(( debug )) && echo "MERGEDIR=$MERGEDIR"

# figure out where the agent files are:
AGENT_OUT=""
AGENT_JAR=""
if [[ -e $AGENT_HOME/out/attach-main.jar ]]; then
	AGENT_JAR=$AGENT_HOME/out/attach-main.jar
elif [[ -e $AGENT_HOME/attach-main.jar ]]; then
	AGENT_JAR=$AGENT_HOME/attach-main.jar
fi
if [[ -e $AGENT_HOME/out/libperfmap.so ]]; then
	AGENT_OUT=$AGENT_HOME/out
elif [[ -e $AGENT_HOME/libperfmap.so ]]; then
	AGENT_OUT=$AGENT_HOME
fi
if [[ "$AGENT_OUT" == "" || "$AGENT_JAR" == "" ]]; then
	echo "ERROR: Missing perf-map-agent files in $AGENT_HOME. Check installation."
	exit
fi

# 复制到容器中
TMP_PERF_MAP_DIR=$MERGEDIR/tmp_perf_map
[[ -e $TMP_PERF_MAP_DIR ]] && rm -r $TMP_PERF_MAP_DIR
mkdir -p $TMP_PERF_MAP_DIR

cp $AGENT_JAR $TMP_PERF_MAP_DIR
cp $AGENT_OUT/libperfmap.so $TMP_PERF_MAP_DIR

# 符号映射文件
mapfile=/tmp/perf-$pid.map
[[ -e $mapfile ]] && rm $mapfile

# 执行
# $MERGEDIR$JAVA_HOME/lib/tools.jar 自从openjdk-9版本后此jar包被删除以jdk.attach module替代; pid固定为容器的1号进程
DEFAULT_CONTAINER_PID=1
CONTAINER_JAR=$TMP_PERF_MAP_DIR/attach-main.jar
cmd="cd $TMP_PERF_MAP_DIR; $MERGEDIR$CONTAINER_JAVA_HOME/bin/java -Xms32m -Xmx128m -cp $CONTAINER_JAR:$MERGEDIR$CONTAINER_JAVA_HOME/lib/tools.jar net.virtualvoid.perf.AttachOnce $pid $opts"
(( debug )) && echo $cmd

user=$(ps ho user -p $pid)
group=$(ps ho group -p $pid)
if [[ "$user" != root ]]; then
    if [[ "$user" == [0-9]* ]]; then
        # UID only, likely GID too, run sudo with #UID:
        cmd="sudo -u '#'$user -g '#'$group sh -c '$cmd'"
    else
        cmd="sudo -u $user -g $group sh -c '$cmd'"
    fi
fi

# 输出
echo "Mapping PID $pid (user $user):"
if (( debug )); then
    time eval $cmd
else
    eval $cmd
fi

CONTAINER_MAP_FILE=$MERGEDIR/tmp/perf-$DEFAULT_CONTAINER_PID.map        # 容器中生成的符号映射文件
if [[ -e "$CONTAINER_MAP_FILE" ]]; then
    chown root $CONTAINER_MAP_FILE
    chmod 666 $CONTAINER_MAP_FILE
    # 移动到宿主机目录
    mv CONTAINER_MAP_FILE $mapfile
else
    echo "ERROR: $mapfile not created."
    # 删除docker中临时目录
    echo "delete $MERGEDIR/tmp_perf_map tmp file..."
    rm -rf $MERGEDIR/tmp_perf_map
fi

echo "wc(1): $(wc $mapfile)"
echo
