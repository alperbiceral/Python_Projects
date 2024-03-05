import clr
# add DLL reference for using dnlib
# You should change it according where dnlib is stored
try:
    clr.AddReference("C:\\Tools\\dnlib\\lib\\net45\\dnlib")
except FileNotFoundError as e:
    clr.AddReference("C:\\Tools\\dnlib\\lib\\net35\\dnlib")

import dnlib
from dnlib.DotNet import *
from dnlib.DotNet.Emit import OpCodes

# Signature for loading strings four times in a row
OPCODE_SIG = ["ldstr", "stsfld", "ldstr", "stsfld", "ldstr", "stsfld", "ldstr", "stsfld"]

def extract_config_pattern(method):
    results = []
    if method.HasBody:
        list_ = []
        indx_list = []
    # enumerate the opcodes and their indexes in the method
        for index, inst in enumerate(method.Body.Instructions):
            list_.append(str(inst.OpCode))
            indx_list.append(index)
        if len(list_) >= len(OPCODE_SIG):
            matched = False
            saved_val = 0
            for index in indx_list:
        # control for not including the same sequence more than once
                if matched:
                    if index <= saved_val:
                        continue
                    else:
                        matched = False
        # match the config pattern
                try:
                    search_list = list_[index:index + len(OPCODE_SIG)]
                    if search_list == OPCODE_SIG:
                        results.append((index, index + len(OPCODE_SIG)))
                        saved_val = index + len(OPCODE_SIG)
                        matched = True
                except:
                    continue
    return results

def main():
    module = dnlib.DotNet.ModuleDefMD.Load("C:\\Users\\{USERNAME}\\Downloads\\dump4.bin")

    for type_ in module.GetTypes():
        for method in type_.Methods:
            index_list = extract_config_pattern(method)
            if index_list:
                for start_index, final_index in index_list:
                    for index, instruction in enumerate(method.Body.Instructions):
                        if index >= start_index and index < final_index:
                            if instruction.OpCode == OpCodes.Ldstr:
                                print(instruction.Operand)
if __name__ == "__main__":
    main()
