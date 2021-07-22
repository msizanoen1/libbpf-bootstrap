import yaml

with open("evil_list.yaml") as f:
    data = yaml.load(f, Loader=yaml.Loader)


def mk_statement(type, name):

    conds = ''
    for i, c in enumerate(name):
        conds += f'name[{i}] == {repr(c)} && '
    stmt = rf"if ({conds}name[{len(name)}] == '\0') {type} = true;"
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

for cancel in data["cancel"]:
    code += mk_statement('cancel', cancel)

for block in data["block"]:
    code += mk_statement('block', block)

with open("evil_list.c.inc", "w") as f:
    f.write(code)
