var g_allocated = {};

rpc.exports = {
  pid: function () {
    return Process.id;
  },
  arch: function () {
    return Process.arch;
  },
  platform: function () {
    return Process.platform;
  },
  pageSize: function () {
    return Process.pageSize;
  },
  pointerSize: function () {
    return Process.pointerSize;
  },
  enumerateModules: function () {
    return Process.enumerateModules();
  },

  findBaseAddress: function (name) {
    return Module.findBaseAddress(name);
  },
  findExportByName: function (moduleName, exportName) {
    return Module.findExportByName(moduleName, exportName);
  },

  memAlloc: function (size) {
    if (size <= 0)
      size = Process.pageSize;
    var new_mem = Memory.alloc(size);
    const address = new_mem.toString(16);
    g_allocated[address] = new_mem;
    return address;
  },
  memFree: function (address) {
    delete g_allocated[address];
  },
  memFreeAll: function () {
    for (var key in g_allocated) {
      delete g_allocated[key];
    }
  },
  memProtect: function (address, size, protection) {
    if (size <= 0)
      size = Process.pageSize;
    return Memory.protect(ptr(address), size, protection);
  },
  memScan: function (pattern, protection) {
    const addresses = Process.enumerateRanges(protection)
      .map((range) => {
        try {
          return Memory.scanSync(range.base, range.size, pattern)
            .map((match) => {
              return match.address.toString(16);
            });
        }
        catch(err) {
          return '';
        }
      }).filter((m) => m.length !== 0);
    if (addresses.length <= 0) {
      return [];
    }
    return addresses.reduce((a, b) => a.concat(b));
  },

  readBool: function (address) {
    return ptr(address).readU8() != 0;
  },
  writeBool: function (address, value) {
    return ptr(address).writeU8(value);
  },
  readChar: function (address) {
    return ptr(address).readS8();
  },
  writeChar: function (address, value) {
    return ptr(address).writeS8(value);
  },
  readUchar: function (address) {
    return ptr(address).readU8();
  },
  writeUchar: function (address, value) {
    return ptr(address).writeU8(value);
  },
  readInt16: function (address) {
    return ptr(address).readS16();
  },
  writeInt16: function (address, value) {
    return ptr(address).writeS16(value);
  },
  readUint16: function (address) {
    return ptr(address).readU16();
  },
  writeUint16: function (address, value) {
    return ptr(address).writeU16(value);
  },
  readInt32: function (address) {
    return ptr(address).readS32();
  },
  writeInt32: function (address, value) {
    return ptr(address).writeS32(value);
  },
  readUint32: function (address) {
    return ptr(address).readU32();
  },
  writeUint32: function (address, value) {
    return ptr(address).writeU32(value);
  },
  readInt64: function (address) {
    return ptr(address).readS64();
  },
  writeInt64: function (address, value) {
    return ptr(address).writeS64(value);
  },
  readUint64: function (address) {
    return ptr(address).readU64();
  },
  writeUint64: function (address, value) {
    return ptr(address).writeU64(value);
  },
  readFloat: function (address) {
    return ptr(address).readFloat();
  },
  writeFloat: function (address, value) {
    return ptr(address).writeFloat(value);
  },
  readDouble: function (address) {
    return ptr(address).readDouble();
  },
  writeDouble: function (address, value) {
    return ptr(address).writeDouble(value);
  },
  readPointer: function (address) {
    return ptr(address).readPointer().toString(16);
  },
  writePointer: function (address, value) {
    return ptr(address).writePointer(ptr(value));
  },
  readCString: function (address) {
    return ptr(address).readCString();
  },
  writeUtf8String: function (address, value) {
    return ptr(address).writeUtf8String(value);
  },
  readByteArray: function (address, length) {
    return ptr(address).readByteArray(length);
  },
  writeByteArray: function (address, bytes) {
    return ptr(address).writeByteArray(bytes);
  },

  callVoidNf: function (address, returnType) {
    var func = new NativeFunction(ptr(address), returnType, []);
    return func();
  },
  callNfI: function (address, returnType, arg1) {
    var func = new NativeFunction(ptr(address), returnType, ['pointer']);
    return func(ptr(arg1));
  },
  callNfII: function (address, returnType, arg1, arg2) {
    var func = new NativeFunction(ptr(address), returnType, ['pointer', 'pointer']);
    return func(ptr(arg1), ptr(arg2));
  },
  callNfIII: function (address, returnType, arg1, arg2, arg3) {
    var func = new NativeFunction(ptr(address), returnType, ['pointer', 'pointer', 'pointer']);
    return func(ptr(arg1), ptr(arg2), ptr(arg3));
  },
  callNfIV: function (address, returnType, arg1, arg2, arg3, arg4) {
    var func = new NativeFunction(ptr(address), returnType, ['pointer', 'pointer', 'pointer', 'pointer']);
    return func(ptr(arg1), ptr(arg2), ptr(arg3), ptr(arg4));
  },
  callNfV: function (address, returnType, arg1, arg2, arg3, arg4, arg5) {
    var func = new NativeFunction(ptr(address), returnType, ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
    return func(ptr(arg1), ptr(arg2), ptr(arg3), ptr(arg4), ptr(arg5));
  },
  callNativeFunc: function (address, returnType, domain, attach, detach, ...args) {
    var result;
    var mono_thread = 0;
    var argc = args.length;

    if (domain != 0 && attach != 0) {
      var attach_func = new NativeFunction(ptr(attach), 'pointer', ['pointer']);
      mono_thread = attach_func(ptr(domain));
    }

    if (argc == 0) {
      result = this.callVoidNf(address, returnType);
    } else if (argc == 1) {
      result = this.callNfI(address, returnType, args[0]);
    } else if (argc == 2) {
      result = this.callNfII(address, returnType, args[0], args[1]);
    } else if (argc == 3) {
      result = this.callNfIII(address, returnType, args[0], args[1], args[2]);
    } else if (argc == 4) {
      result = this.callNfIV(address, returnType, args[0], args[1], args[2], args[3]);
    } else if (argc == 5) {
      result = this.callNfV(address, returnType, args[0], args[1], args[2], args[3], args[4]);
    }

    if (mono_thread != 0 && detach != 0) {
      var detach_func = new NativeFunction(ptr(detach), 'pointer', ['pointer']);
      detach_func(ptr(mono_thread));
    }
    return result;
  }
};