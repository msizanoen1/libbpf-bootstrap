import yaml
import sys

infile = sys.argv[1]
outfile = sys.argv[2]

with open(infile) as f:
    data = yaml.load(f, Loader=yaml.Loader)


def mk_statement(type, name):
    if name[0] == '^':
        name = name[1:]
        prefix = True
    else:
        prefix = False
    conds = ''
    for i, c in enumerate(name):
        conds += f'name[{i}] == {repr(c)} && '
    if not prefix:
        cond2 = rf"name[{len(name)}] == '\0'"
    else:
        cond2 = 'true'
    stmt = f"if ({conds}{cond2}) {type} = true;"
    return stmt + '\n'


code = ''

for ty, names in data.items():
    for name in names:
        code += mk_statement(ty, name)

with open(outfile, "w") as f:
    f.write(code)
