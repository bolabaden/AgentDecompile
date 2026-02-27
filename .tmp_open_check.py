import asyncio
from agentdecompile_cli.executor import get_client

async def main():
    client = get_client(url='http://127.0.0.1:8086')
    async with client:
        res = await client.call_tool('open', {
            'programPath': '/K1/k1_win_gog_swkotor.exe',
            'serverHost': '170.9.241.140',
            'serverPort': 13100,
            'serverUsername': 'OpenKotOR',
            'serverPassword': 'MuchaShakaPaka',
            'forceIgnoreLock': True,
        })
        print('checkedOutProgram=', res.get('checkedOutProgram'))
        print('message=', res.get('message'))

asyncio.run(main())
