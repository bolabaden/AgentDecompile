"""Native Ghidra function properties and explicit variable storage for code browsers."""
from __future__ import annotations

from agentdecompile_cli.registry import normalize_identifier as n


def storage_pieces(program, storage):
    pieces = []
    for node in storage.getVarnodes():
        address, size = node.getAddress(), int(node.getSize())
        item = {"size": size, "address": str(address)}
        if address.isStackAddress():
            item["stackOffset"] = int(address.getOffset())
        elif address.isRegisterAddress():
            register = program.getRegister(address, size)
            item["register"] = str(register.getName()) if register else str(address)
        pieces.append(item)
    return pieces


def function_properties(program, func):
    target = func.getThunkedFunction(False) if func.isThunk() else None
    return {
        "function": str(func.getName()), "address": str(func.getEntryPoint()),
        "availableRegisters": [{"name": str(r.getName()), "size": int(r.getMinimumByteSize())} for r in program.getLanguage().getRegisters()],
        "availableCallingConventions": [str(c.getName()) for c in program.getCompilerSpec().getCallingConventions()],
        "availableCallFixups": [str(c) for c in program.getCompilerSpec().getPcodeInjectLibrary().getCallFixupNames()],
        "namespace": str(func.getParentNamespace().getName(True)),
        "callingConvention": str(func.getCallingConventionName() or ""),
        "returnType": str(func.getReturnType()),
        "customStorage": bool(func.hasCustomVariableStorage()),
        "returnStorage": storage_pieces(program, func.getReturn().getVariableStorage()),
        "inline": bool(func.isInline()), "noReturn": bool(func.hasNoReturn()),
        "varArgs": bool(func.hasVarArgs()), "callFixup": str(func.getCallFixup() or ""),
        "thunkTarget": str(target.getEntryPoint()) if target else "",
        "parameters": [{"ordinal": int(p.getOrdinal()), "name": str(p.getName()),
                        "dataType": str(p.getDataType()),
                        "storage": storage_pieces(program, p.getVariableStorage())}
                       for p in func.getParameters()],
    }


def make_storage(program, pieces):
    from ghidra.program.model.listing import VariableStorage
    from ghidra.program.model.pcode import Varnode
    from java.util import ArrayList
    if not isinstance(pieces, list) or not pieces:
        raise ValueError("Storage needs at least one register or stack piece")
    nodes = ArrayList()
    for raw in pieces:
        if not isinstance(raw, dict):
            raise ValueError("Storage pieces must be objects")
        piece = {n(k): v for k, v in raw.items()}
        size = piece.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
            raise ValueError("Storage size must be a positive integer")
        if ("register" in piece) == ("stackoffset" in piece):
            raise ValueError("Each piece needs exactly one of register or stackOffset")
        if "register" in piece:
            register = program.getRegister(str(piece["register"]))
            if register is None or size > register.getMinimumByteSize():
                raise ValueError("Unknown register or oversized storage: " + str(piece["register"]))
            address = register.getAddress()
            if program.getLanguage().isBigEndian() and size < register.getMinimumByteSize():
                address = address.add(register.getMinimumByteSize() - size)
        else:
            offset = piece["stackoffset"]
            if isinstance(offset, bool) or not isinstance(offset, int):
                raise ValueError("stackOffset must be an integer")
            address = program.getAddressFactory().getStackSpace().getAddress(offset)
        nodes.add(Varnode(address, size))
    return VariableStorage(program, nodes)


def update_function(program, func, args, mode):
    from ghidra.program.model.symbol import SourceType
    values = {n(k): v for k, v in args.items()}
    if mode == "setproperties":
        if "namespace" in values:
            namespace = program.getGlobalNamespace()
            for name in str(values["namespace"]).split("::"):
                if not name or name == "Global":
                    continue
                table = program.getSymbolTable()
                existing = table.getNamespace(name, namespace)
                namespace = existing if existing else table.createNameSpace(namespace, name, SourceType.USER_DEFINED)
            func.setParentNamespace(namespace)
        for key, setter in (("inline", func.setInline), ("noreturn", func.setNoReturn), ("varargs", func.setVarArgs)):
            if key in values:
                if not isinstance(values[key], bool):
                    raise ValueError(key + " must be boolean")
                setter(values[key])
        if "callfixup" in values:
            fixup = str(values["callfixup"])
            names = {str(x) for x in program.getCompilerSpec().getPcodeInjectLibrary().getCallFixupNames()}
            if fixup and fixup not in names:
                raise ValueError("Unknown call fixup: " + fixup)
            func.setCallFixup(fixup or None)
        if "thunktarget" in values:
            target = str(values["thunktarget"])
            address = program.getAddressFactory().getAddress(target) if target else None
            function = program.getFunctionManager().getFunctionAt(address) if address else None
            if target and function is None:
                raise ValueError("Thunk target must identify a function entry address")
            func.setThunkedFunction(function)
        return
    from ghidra.util.data import DataTypeParser
    manager = program.getDataTypeManager()
    parser = DataTypeParser(manager, manager, None, DataTypeParser.AllowedDataTypes.ALL)
    enabled = values.get("customstorage", True)
    if not isinstance(enabled, bool):
        raise ValueError("customStorage must be boolean")
    if not enabled and ("returnstorage" in values or values.get("parameterstorage")):
        raise ValueError("Explicit storage requires customStorage=true")
    func.setCustomVariableStorage(enabled)
    if "returnstorage" in values:
        data_type = parser.parse(str(values["returntype"])) if values.get("returntype") else func.getReturnType()
        func.setReturn(data_type, make_storage(program, values["returnstorage"]), SourceType.USER_DEFINED)
    seen = set()
    for raw in values.get("parameterstorage", []):
        row = {n(k): v for k, v in raw.items()}
        ordinal = row.get("ordinal")
        if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 0 or ordinal in seen:
            raise ValueError("Parameter ordinal must be unique and non-negative")
        seen.add(ordinal)
        parameter = func.getParameter(ordinal)
        if parameter is None:
            raise ValueError("Parameter ordinal does not exist: " + str(ordinal))
        data_type = parser.parse(str(row["datatype"])) if row.get("datatype") else parameter.getDataType()
        parameter.setDataType(data_type, make_storage(program, row.get("storage")), False, SourceType.USER_DEFINED)
