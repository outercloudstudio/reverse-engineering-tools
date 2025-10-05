import os
import json

functions_data_path = ""
binsync_functions_path = ""

functionFile = open(functions_data_path, 'r')
function_data_string = functionFile.read()
functionFile.close()

function_data = json.loads(function_data_string)

for filename in os.listdir(binsync_functions_path):
    filepath = os.path.join(binsync_functions_path, filename)

    binsyncFile = open(filepath, 'r')
    content = binsyncFile.readlines()
    binsyncFile.close()

    address = -1
    symbol = 'NOT FOUND'

    for line in content:
        if line.startswith('addr = '):
            address = int(line[len('addr = '):], 16)
        
        if line.startswith('name = '):
            symbol = line[len('name = '):]

    if symbol == 'NOT FOUND':
        continue

    symbol = symbol[1:]

    if symbol.endswith('\n'):
        symbol = symbol[:-2]
    else:
        symbol = symbol[:-1]

    existing_index = -1

    for index in range(len(function_data)):
        function = function_data[index]

        if address == function['address']:
            existing_index = index

            break

    if existing_index != -1:
        continue

    function_data.append({
        "address": address,
        "symbol": symbol
    })

    result = json.dumps(function_data, indent=4)

    functionFile = open(functions_data_path, 'w')
    function_data_string = functionFile.write(result)
    functionFile.close()