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
#
# Entrypoint for the Ghidra Docker image.
# This is the official Ghidra docker/entrypoint.sh with one addition
# (marked "AgentDecompile addition" below):
#
#   Auto-detect RMI hostname for ghidra-server mode so Docker networking
#   works without manually configuring -ip in server.conf.
#
# The only other difference from official is in the Dockerfile (auto-download
# of the latest Ghidra release instead of COPY from a local release).
#

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

	# ---- AgentDecompile addition: auto-detect RMI hostname for Docker ----
	#
	# Official Ghidra Docker does not handle IP configuration; users must
	# manually set -ip in their mounted server.conf.  We add automatic
	# detection so "docker compose up" works without manual IP config.
	#
	# How it works:
	#   - If server.conf already has -ip in wrapper.app.parameter, we skip
	#     entirely (the user configured it manually — respect that).
	#   - Otherwise, resolve the RMI hostname:
	#       GHIDRA_IP=<addr>  → use that explicit IP/hostname/FQDN
	#       GHIDRA_IP=*       → skip (use system default; for --net host)
	#       GHIDRA_IP unset   → auto-detect from host.docker.internal,
	#                           then fall back to container's first IP
	#   - Inject -ip <hostname> into server.conf as wrapper.app.parameter
	#     entries so GhidraServer advertises a reachable address in RMI stubs.
	#   - The injection is idempotent (previous auto-IP block is replaced).
	#
	# Why this is needed in Docker:
	#   Without -ip, GhidraServer advertises the container's internal hostname
	#   (e.g. "ghidra" → 172.17.0.x).  External clients receive RMI stubs
	#   pointing to that internal IP and cannot connect back.  By setting -ip
	#   to the Docker host's IP (via host.docker.internal), clients get stubs
	#   that point to the host, and Docker port-forwarding delivers the traffic.
	#
	# ---- end AgentDecompile addition docs ----

	CONF="/ghidra/server/server.conf"
	if [ -f "$CONF" ] && ! grep -qE '^\s*wrapper\.app\.parameter\.[0-9]+=-ip' "$CONF" 2>/dev/null; then
		RESOLVED_IP="${GHIDRA_IP:-}"
		if [[ -z "$RESOLVED_IP" ]]; then
			# Auto-detect: try host.docker.internal (Docker Desktop / extra_hosts gateway)
			RESOLVED_IP=$(getent hosts host.docker.internal 2>/dev/null | awk '{print $1}' | head -1)
			if [[ -z "$RESOLVED_IP" ]]; then
				# Fallback: container's first non-loopback IP
				RESOLVED_IP=$(hostname -i 2>/dev/null | awk '{print $1}')
			fi
		fi
		if [[ -n "$RESOLVED_IP" && "$RESOLVED_IP" != "*" ]]; then
			# Remove any previous auto-IP block (idempotent)
			sed -i '/^# AUTO-IP-BEGIN$/,/^# AUTO-IP-END$/d' "$CONF" 2>/dev/null || true

			# Find the repo_dir parameter (must be the LAST app.parameter — it's positional)
			REPO_NUM=$(grep -oP 'wrapper\.app\.parameter\.\K[0-9]+(?==\$\{ghidra\.repositories\.dir\})' "$CONF" | head -1)
			if [[ -n "$REPO_NUM" ]]; then
				# Remove old repo_dir line; we re-add it after the -ip entries
				sed -i "/^wrapper\.app\.parameter\.${REPO_NUM}=.*ghidra\.repositories\.dir.*/d" "$CONF"
				IP_NUM=$REPO_NUM
			else
				# No repo_dir line; use a high number
				MAX_P=$(grep -oP 'wrapper\.app\.parameter\.\K[0-9]+' "$CONF" 2>/dev/null | sort -n | tail -1)
				IP_NUM=$(( ${MAX_P:-0} + 1 ))
			fi
			HOSTNAME_NUM=$(( IP_NUM + 1 ))
			REPO_NEW_NUM=$(( IP_NUM + 2 ))

			{
				echo "# AUTO-IP-BEGIN"
				echo "wrapper.app.parameter.${IP_NUM}=-ip"
				echo "wrapper.app.parameter.${HOSTNAME_NUM}=${RESOLVED_IP}"
				echo "wrapper.app.parameter.${REPO_NEW_NUM}=\${ghidra.repositories.dir}"
				echo "# AUTO-IP-END"
			} >> "$CONF"
			echo "[entrypoint] Auto-configured RMI hostname: ${RESOLVED_IP}"
		fi
	fi

	# Note, for svrAdmin, you will need to exec into the container running the ghidra server and use the CLI there.
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
