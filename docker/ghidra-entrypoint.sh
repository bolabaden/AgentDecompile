#!/bin/bash
## ###
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##
# Official Ghidra Docker entrypoint (from ghidra_12.0_PUBLIC/docker/entrypoint.sh).
# Supports MODE: gui, headless, ghidra-server, bsim, bsim-server, pyghidra.

MODE=${MODE:="gui"}

echo "$@"
MAXMEM=${MAXMEM:=2G}

if [[ $MODE == "gui" ]] then
	/ghidra/support/launch.sh bg jdk Ghidra "${MAXMEM}" "" ghidra.GhidraRun "$@"
	# need to do this since the launched process is not blocking terminal exit
	while !	tail -f ~/.config/ghidra/ghidra_*/application.log; do sleep 1 ; done
elif [[ $MODE == "headless" ]] then
	LAUNCH_MODE=${LAUNCH_MODE:=fg}
	DEBUG_ADDRESS=${DEBUG_ADDRESS:=127.0.0.1:13002}
	VMARG_LIST=${VMARG_LIST:="-XX:ParallelGCThreads=2 -XX:CICompilerCount=2 -Djava.awt.headless=true "}
	DEBUG_ADDRESS=${DEBUG_ADDRESS} /ghidra/support/launch.sh "${LAUNCH_MODE}" jdk Ghidra-Headless "${MAXMEM}" "${VMARG_LIST}" ghidra.app.util.headless.AnalyzeHeadless "$@"	
elif [[ $MODE == "ghidra-server" ]] then
	# Note, for svrAdmin, you will need to exec into the container running the ghidra server and use the CLI there.
	#
	# GHIDRA_IP / java.rmi.server.hostname
	# Docker containers advertise their internal IP (e.g. 172.17.0.x) in RMI stubs,
	# making the server unreachable from clients outside the container network.
	# GHIDRA_IP sets java.rmi.server.hostname via JAVA_TOOL_OPTIONS so RMI stubs
	# contain the correct externally-reachable address.  Equivalent to the -ip flag
	# in server.conf / GhidraServer CLI.
	# See: GhidraServer.java initRemoteAccessHostname(), svrREADME -ip docs.
	if [[ -z "${GHIDRA_IP:-}" ]]; then
		# Auto-detect public IP; fall back to hostname resolution.
		GHIDRA_IP="$(python3 -c "
import urllib.request, socket, sys
for url in ('https://api.ipify.org', 'https://ifconfig.me/ip'):
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            ip = r.read().decode().strip()
            if ip:
                print(ip); sys.exit(0)
    except Exception:
        pass
try:
    print(socket.gethostbyname(socket.gethostname()))
except Exception:
    pass
" 2>/dev/null || true)"
	fi
	if [[ -n "${GHIDRA_IP:-}" ]]; then
		# Validate: hostname/IP only (no spaces or injection)
		if [[ "${GHIDRA_IP}" =~ ^[a-zA-Z0-9._:-]+$ ]]; then
			export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} -Djava.rmi.server.hostname=${GHIDRA_IP}"
			echo "GHIDRA_IP=${GHIDRA_IP}: java.rmi.server.hostname set for external RMI access"
		else
			echo "ERROR: Invalid GHIDRA_IP value '${GHIDRA_IP}' — must be a valid hostname or IP."
			exit 1
		fi
	else
		echo "WARNING: GHIDRA_IP not set and auto-detection failed."
		echo "  External clients may not connect. Set GHIDRA_IP=<host-ip> in environment."
	fi
	/ghidra/server/ghidraSvr console
elif [[ $MODE == "bsim" ]] then
	LAUNCH_MODE=${LAUNCH_MODE:=fg}
	VMARG_LIST=${VMARG_LIST:="-Djava.awt.headless=true "}
	/ghidra/support/launch.sh $LAUNCH_MODE jdk "BSim" "${MAXMEM}" "${VMARG_LIST}" ghidra.features.bsim.query.ingest.BSimLaunchable "$@"
elif [[ $MODE == "bsim-server" ]] then
	LAUNCH_MODE=${LAUNCH_MODE:=fg}
	VMARG_LIST=${VMARG_LIST:="-Djava.awt.headless=true -Xshare:off"}
	if [[ ! $# -eq 0 ]] then
		/ghidra/support/launch.sh "$LAUNCH_MODE" jdk BSimControl "$MAXMEM" "$VMARG_LIST" ghidra.features.bsim.query.BSimControlLaunchable start $@
		# need to do this since the launched process is not blocking terminal exit
		while !	tail -f $1/logfile; do sleep 1 ; done
	else
		echo "ERROR: Must pass args for bsim_ctl start command."
		/ghidra/support/launch.sh "$LAUNCH_MODE" jdk BSimControl "$MAXMEM" "$VMARG_LIST" ghidra.features.bsim.query.BSimControlLaunchable start $@
		exit 1
	fi
elif [[ $MODE == "pyghidra" ]] then
	# Add optional JVM args inside the quotes
	VMARG_LIST=${VMARG_LIST:=""}
	PYGHIDRA_LAUNCHER="/ghidra/Ghidra/Features/PyGhidra/support/pyghidra_launcher.py"
	set -e
	source /ghidra/venv/bin/activate
	/ghidra/venv/bin/python3 "${PYGHIDRA_LAUNCHER}" "/ghidra" ${VMARG_LIST} "$@"
else
	echo "Unknown MODE: $MODE. Valid MODE's are gui, headless, ghidra-server, bsim, bsim_ctl, or pyghidra." 
fi
