import yaml

with open("evil_list.yaml") as f:
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


code = r"""/**
 * Frequently Asked Questions:
 * 
 * Q: Why does this file even exist?
 * 
 * A: __builtin_memcmp is currently broken on eBPF with LLVM 12 and this is the
 * only workaround I can come up with.
 * 
 */
"""

for ty, names in data.items():
    for name in names:
        code += mk_statement(ty, name)

with open("evil_list.c.inc", "w") as f:
    f.write(code)
