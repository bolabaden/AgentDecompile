
# 1) Open a program from a Ghidra shared repository
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ open --server_host *** --server_port 13100 --server_username OpenKotOR --server_password MuchaShakaPaka /K1/k1_win_gog_swkotor.exe

# output
mode: shared-server
serverConnected: True
repository: Odyssey
programCount: 26
checkedOutProgram: /K1/k1_win_gog_swkotor.exe

# Set env vars to reduce amount of parameters in the cli:
$Env:AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME="OpenKotOR"
$Env:AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD="MuchaShakaPaka"
$Env:AGENT_DECOMPILE_GHIDRA_SERVER_HOST="***"
$Env:AGENT_DECOMPILE_GHIDRA_SERVER_PORT="13100"

# 2) List files in the shared repository
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ list project-files

# output
folder: /                                                                                                                   
files: [{'name': 'JadeEmpire.exe', 'path': '/JE/JadeEmpire.exe', 'isDirectory': False, 'type': 'Program'}, {'name': 'JadeEmpire_pc_2005.exe', 'path': '/JE/JadeEmpire_pc_2005.exe', 'isDirectory': False, 'type': 'Program'}, {'name': 'k1_android_ARM64', 'path': '/K1/k1_android_ARM64', 'isDirectory': False, 'type': 'Program'}, {'name': 'k1_android_ARMEABI', 'path': '/K1/k1_android_ARMEABI', 'isDirectory': False, 'type': 'Program'}, {'name': 'k1_iOS_KOTOR.ipa', 'path': '/K1/k1_iOS_KOTOR.ipa', 'isDirectory': False, 'type': 'Program'}, {'name': 'k1_mac_swkotor.app', 'path': '/K1/k1_mac_swkotor.app', 'isDirectory': False, 'type': 'Program'}, {'name': 'k1_win_amazongames_swkotor.exe', 'path': '/K1/k1_win_amazongames_swkotor.exe', 'isDirectory': False, 'type': 'Program'}, {'name': 'k1_win_gog_swkotor.exe', 'path': '/K1/k1_win_gog_swkotor.exe', 'isDirectory': False, 'type': 'Program'}, {'name': 'k1_xbox_default.xbe', 'path': '/K1/k1_xbox_default.xbe', 'isDirectory': False, 'type': 'Program'}, {'name': 'nwmain.exe', 'path': '/Other BioWare Engines/Aurora/nwmain.exe', 'isDirectory': False, 'type': 'Program'}, {'name': 'DragonAge2.exe', 'path': '/Other BioWare Engines/Eclipse/DragonAge2.exe', 'isDirectory': False, 'type': 'Program'}, {'name': 'daorigins.exe', 'path': '/Other BioWare Engines/Eclipse/daorigins.exe', 'isDirectory': False, 'type': 'Program'}, {'name': 'k2_ios_KOTOR_II.ipa', 'path': '/TSL/k2_ios_KOTOR_II.ipa', 'isDirectory': False, 'type': 'Program'}, {'name': 'k2_mac_swkotor2.app', 'path': '/TSL/k2_mac_swkotor2.app', 'isDirectory': False, 'type': 'Program'}, {'name': 'k2_win_CD_1.0_swkotor2.exe', 'path': '/TSL/k2_win_CD_1.0_swkotor2.exe', 'isDirectory': False, 'type': 'Program'}, {'name': 'k2_win_CD_1.0b_swkotor2.exe', 'path': '/TSL/k2_win_CD_1.0b_swkotor2.exe', 'isDirectory': False, 'type': 'Program'}, {'name': 'k2_win_gog_aspyr_swkotor2.exe', 'path': '/TSL/k2_win_gog_aspyr_swkotor2.exe', 'isDirectory': False, 'type': 'Program'}, {'name': 'k2_win_gog_legacypc_swkotor2.exe', 'path': '/TSL/k2_win_gog_legacypc_swkotor2.exe', 'isDirectory': False, 'type': 'Program'}, {'name': 'k2_win_steam_aspyr_swkotor2.exe', 'path': '/TSL/k2_win_steam_aspyr_swkotor2.exe', 'isDirectory': False, 'type': 'Program'}, {'name': 'k2_xbox_default.xbe', 'path': '/TSL/k2_xbox_default.xbe', 'isDirectory': False, 'type': 'Program'}]
count: 20
source: shared-server-session
note: Fell back to shared repository index: 'ghidra.framework.data.DomainFileProxy' object has no attribute 'getProjectData'

# 3) List a small function sample
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ get-functions --program_path /K1/k1_win_gog_swkotor.exe --limit 5

# output
functions: [{'name': '~CSWReentrantServerStats', 'address': '00401000', 'size': 90, 'isExternal': False, 'isThunk': False, 'parameterCount': 1}, {'name': 'GetObjectTableManager', 'address': '00401060', 'size': 30, 'isExternal': False, 'isThunk': False, 'parameterCount': 2}, {'name': 'DoSaveGameScreenShot', 'address': '00401080', 'size': 30, 'isExternal': False, 'isThunk': False, 'parameterCount': 3}, {'name': 'AllocLargeTempBuffer', 'address': '004010a0', 'size': 25, 'isExternal': False, 'isThunk': False, 'parameterCount': 1}, {'name': 'CSWReentrantServerStats', 'address': '004010c0', 'size': 101, 'isExternal': False, 'isThunk': False, 'parameterCount': 1}]
count: 5
totalMatched: 24242
offset: 0
hasMore: True

# 4) Search symbols by name
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ search-symbols-by-name --program_path /K1/k1_win_gog_swkotor.exe --query main --max_results 5

# output
query: main                                                                                                                 
results: [{'name': 'WinMain', 'address': '004041f0', 'type': 'Function', 'namespace': 'Global', 'source': 'USER_DEFINED'}, {'name': 'MainLoop', 'address': '004ae860', 'type': 'Function', 'namespace': 'CServerExoApp (GhidraClass)', 'source': 'USER_DEFINED'}, {'name': 'MainLoop', 'address': '004babb0', 'type': 'Function', 'namespace': 'CServerExoAppInternal (GhidraClass)', 'source': 'USER_DEFINED'}, {'name': 'WriteGameObjUpdate_WorkRemaining', 'address': '00567ba0', 'type': 'Function', 'namespace': 'CSWSMessage (GhidraClass)', 'source': 'USER_DEFINED'}, {'name': 'GetFeatRemainingUses', 'address': '005a6680', 'type': 'Function', 'namespace': 'CSWSCreatureStats (GhidraClass)', 'source': 'USER_DEFINED'}]
count: 5
totalMatched: 58
hasMore: True

# 5) Find references to a symbol
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ references to --binary /K1/k1_win_gog_swkotor.exe --target WinMain --limit 5

# output
mode: to                                                                                                                    
target: 004041f0
references: [{'fromAddress': '006fb509', 'toAddress': '004041f0', 'type': 'UNCONDITIONAL_CALL', 'function': 'entry'}]       
count: 1

# 6) uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli agentdecompile-cli --server-url http://***:8080 get-current-program --program_path /K1/k1_win_gog_swkotor.exe

# output
loaded: True                                                                                                                
name: swkotor.exe
path: /Untitled
language: x86:LE:32:default
compiler: windows
addressFactory: ram
functionCount: 24591
imageBase: 00400000
memoryBlocks: 7
symbolCount: 89606

# 7) Raw tool mode examples
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ tool list-imports '{"programPath":"/K1/k1_win_gog_swkotor.exe","limit":5}'

# output
mode: imports                                                                                                               
results: [{'name': 'glGetFloatv', 'address': 'EXTERNAL:00000001', 'namespace': 'OPENGL32.DLL'}, {'name': 'glClear', 'address': 'EXTERNAL:00000002', 'namespace': 'OPENGL32.DLL'}, {'name': 'glClearColor', 'address': 'EXTERNAL:00000003', 'namespace': 'OPENGL32.DLL'}, {'name': 'glColor4f', 'address': 'EXTERNAL:00000004', 'namespace': 'OPENGL32.DLL'}, {'name': 'glMatrixMode', 'address': 'EXTERNAL:00000005', 'namespace': 'OPENGL32.DLL'}]
count: 5

uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ tool list-exports '{"programPath":"/K1/k1_win_gog_swkotor.exe","limit":5}'

# output
mode: exports                                                                                                               
results: [{'name': 'entry', 'address': '006fb38d'}]
count: 1