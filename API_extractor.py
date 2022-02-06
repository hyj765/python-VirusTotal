import pefile


T_file=pefile.PE("C:\\Windows\\System32\\notepad.exe")

iat_lst = []
for entry in T_file.DIRECTORY_ENTRY_IMPORT:
  symbol=[]
  for imp in entry.imports:
    if(imp.name != None) and (imp.name != ""):
      symbol.append({
          "address": hex(imp.address),
          "name": imp.name,
      })
      iat_lst.append({
                        "dll": str(entry.dll),
                        "imports": symbol,
                    })
rt = {}
for line in iat_lst:
  for func in line['imports']:
    rt[func['name'].decode('utf-8')] = 0

for line in iat_lst:
  for func in line['imports']:
    rt[func['name'].decode('utf-8')] += 1

print(rt)