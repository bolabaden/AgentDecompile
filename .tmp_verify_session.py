import asyncio, json
from agentdecompile_cli.executor import get_client

async def main():
    client = get_client(url='http://127.0.0.1:8086')
    async with client:
        open_result = await client.call_tool('open', {
            'programPath': '/K1/k1_win_gog_swkotor.exe',
            'serverHost': '170.9.241.140',
            'serverPort': 13100,
            'serverUsername': 'OpenKotOR',
            'serverPassword': 'MuchaShakaPaka',
            'forceIgnoreLock': True,
        })
        print('OPEN_RESULT')
        print(json.dumps(open_result, indent=2)[:2000])

        for tool, payload in [
            ('list-functions', {'namePattern': 'ApplyDamage', 'maxResults': 5}),
            ('get-functions', {'function': 'CSWSCreature::ApplyDamage', 'view': 'info'}),
            ('get-references', {'target': 'CSWSCreature::ApplyDamage', 'mode': 'to', 'limit': 3}),
            ('get-call-graph', {'functionIdentifier': 'CSWSCreature::ApplyDamage', 'mode': 'graph', 'depth': 1}),
            ('manage-structures', {'action': 'info', 'nameFilter': 'CSWSCreature', 'maxCount': 3}),
            ('manage-symbols', {'mode': 'symbols', 'filterDefaultNames': True, 'maxResults': 5}),
        ]:
            res = await client.call_tool(tool, payload)
            print('\nTOOL', tool)
            print(json.dumps(res, indent=2)[:2000])

asyncio.run(main())
