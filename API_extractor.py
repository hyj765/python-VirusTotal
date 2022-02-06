import pefile


T_file=pefile.PE("C:\\Windows\\System32\\notepad.exe")

IAT = []
for entry in T_file.DIRECTORY_ENTRY_IMPORT:
  Ens=[]
  for imp in entry.imports:
    if(imp.name != None):
      Ens.append({
          "address": hex(imp.address),
          "name": imp.name,
      })
      IAT.append({"dll": str(entry.dll), "imports": Ens,})
rt = {}
for line in IAT:
  for func in line['imports']:
    rt[func['name'].decode('utf-8')] = 0

for line in IAT:
  for func in line['imports']:
    rt[func['name'].decode('utf-8')] += 1

print(rt)
