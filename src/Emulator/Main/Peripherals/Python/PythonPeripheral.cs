//
// Copyright (c) 2010-2024 Antmicro
// Copyright (c) 2011-2015 Realtime Embedded
//
// This file is licensed under the MIT License.
// Full license text is available in 'licenses/MIT.txt'.
//

using System.IO;
using Antmicro.Renode.Core;
using Antmicro.Renode.Exceptions;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.UserInterface;
using Antmicro.Renode.Utilities;
using System;

namespace Antmicro.Renode.Peripherals.Python
{
    public static class PythonPeripheralExtensions 
    {
        public static void PyDevFromFile(this Machine @this, ReadFilePath path, ulong address, int size, bool initable = false, string name = null, ulong offset = 0)
        {
            var pyDev = new PythonPeripheral(size, initable, filename: path);
            @this.SystemBus.Register(pyDev, new BusPointRegistration(address, offset));
            if(!string.IsNullOrEmpty(name))
            {
                @this.SetLocalName(pyDev, name);
            }
        }

        public static void PyDevFromString(this Machine @this, string script, ulong address, int size, bool initable = false, string name = null, ulong offset = 0)
        {
            var pyDev = new PythonPeripheral(size, initable, script: script);
            @this.SystemBus.Register(pyDev, new BusPointRegistration(address, offset));
            if(!string.IsNullOrEmpty(name))
            {
                @this.SetLocalName(pyDev, name);
            }
        }
    }

    [Icon("python")]
    public class PythonPeripheral : IBytePeripheral, IWordPeripheral, IDoubleWordPeripheral, IQuadWordPeripheral, IKnownSize, IAbsoluteAddressAware, IFuzzSnapshotRestorable
    {
        public PythonPeripheral(int size, bool initable = false, string script = null, string filename = null)
        {
            this.size = size;
            this.initable = initable;
            this.script = script;
            this.filename = filename;

            if((this.script == null && this.filename == null) || (this.script != null && this.filename != null))
            {
                throw new ConstructionException("Parameters `script` and `filename` cannot be both set or both unset.");
            }
            if(this.script != null)
            {
                this.pythonRunner = new PeripheralPythonEngine(this, x => x.CreateScriptSourceFromString(this.script));
            }
            else if(this.filename != null)
            {
                if(!File.Exists(this.filename))
                {
                    throw new ConstructionException(string.Format("Could not find source file for the script: {0}.", this.filename));
                }
                this.pythonRunner = new PeripheralPythonEngine(this, x => x.CreateScriptSourceFromFile(this.filename));
            }
        }

        public void SetAbsoluteAddress(ulong address)
        {
            pythonRunner.Request.absolute = address;
        }

        public byte ReadByte(long offset)
        {
            pythonRunner.Request.length = 1;
            HandleRead(offset);
            return unchecked((byte)pythonRunner.Request.value);
        }

        public void WriteByte(long offset, byte value)
        {
            pythonRunner.Request.length = 1;
            HandleWrite(offset, value);
        }

        public uint ReadDoubleWord(long offset)
        {
            pythonRunner.Request.length = 4;
            HandleRead(offset);
            return unchecked((uint)pythonRunner.Request.value);
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            pythonRunner.Request.length = 4;
            HandleWrite(offset, value);
        }

        public ulong ReadQuadWord(long offset)
        {
            pythonRunner.Request.length = 8;
            HandleRead(offset);
            return unchecked(pythonRunner.Request.value);
        }

        public void WriteQuadWord(long offset, ulong value)
        {
            pythonRunner.Request.length = 8;
            HandleWrite(offset, value);
        }

        public ushort ReadWord(long offset)
        {
            pythonRunner.Request.length = 2;
            HandleRead(offset);
            return unchecked((ushort)pythonRunner.Request.value);
        }

        public void WriteWord(long offset, ushort value)
        {
            pythonRunner.Request.length = 2;
            HandleWrite(offset, value);
        }

        public void ControlWrite(long command, ulong value)
        {
            // ignoring the return value
            ControlRead(command, value);
        }

        public ulong ControlRead(long command, ulong value)
        {
            EnsureInit();

            pythonRunner.Request.value = 0;
            pythonRunner.Request.type = PeripheralPythonEngine.PythonRequest.RequestType.USER;
            pythonRunner.Request.offset = command;
            pythonRunner.Request.value = value;
            pythonRunner.Request.length = 8;
            Execute();
            return unchecked(pythonRunner.Request.value);
        }

        public void Reset()
        {
            // Console.WriteLine("^^^^^^ PythonPeripheral.cs Reset()");
            inited = false;
            EnsureInit();
        }


    private bool fuzz_snap_inited;
private ulong fuzz_snap_requestCounter;
private PeripheralPythonEngine fuzz_snap_pythonRunner;
private bool fuzz_snap_initable;
private int fuzz_snap_size;
private string fuzz_snap_script;
private string fuzz_snap_filename;

private string fuzz_snap_codeContent;
private PeripheralPythonEngine.PythonRequest fuzz_snap_request;

public void fuzz_snap_capture()
{
    Console.WriteLine("^^^^^ PythonPeripheral.cs fuzz_snap_capture()");
    // Internal state variables
    fuzz_snap_inited = inited;
    fuzz_snap_requestCounter = requestCounter;
    fuzz_snap_pythonRunner = pythonRunner;
    fuzz_snap_initable = initable;
    fuzz_snap_size = size;
    fuzz_snap_script = script;
    fuzz_snap_filename = filename;
    
    // Python engine state
    fuzz_snap_codeContent = pythonRunner.Code;
    fuzz_snap_request = new PeripheralPythonEngine.PythonRequest
    {
        value = pythonRunner.Request.value,
        length = pythonRunner.Request.length,
        type = pythonRunner.Request.type,
        offset = pythonRunner.Request.offset,
        absolute = pythonRunner.Request.absolute,
        counter = pythonRunner.Request.counter
    };
}

public void fuzz_snap_restore()
{
    // Console.WriteLine("^^^^^ PythonPeripheral.cs fuzz_snap_restore()");
    // Restore internal state variables
    inited = fuzz_snap_inited;
    requestCounter = fuzz_snap_requestCounter;
    // pythonRunner = fuzz_snap_pythonRunner;
    // initable = fuzz_snap_initable;//readonly
    // size = fuzz_snap_size;
    // script = fuzz_snap_script;
    // filename = fuzz_snap_filename;
    
    // Restore Python engine state
    // Note: The pythonRunner will be restored through the serialization system
    // The request state will be restored when the pythonRunner is restored
    
    // Restore request state
    if (fuzz_snap_request != null)
    {
        pythonRunner.Request.value = fuzz_snap_request.value;
        pythonRunner.Request.length = fuzz_snap_request.length;
        pythonRunner.Request.type = fuzz_snap_request.type;
        pythonRunner.Request.offset = fuzz_snap_request.offset;
        pythonRunner.Request.absolute = fuzz_snap_request.absolute;
        pythonRunner.Request.counter = fuzz_snap_request.counter;
    }
}


        public long Size
        {
            get { return size; }
        }

        public void EnsureInit()
        {
            if(!inited)
            {
                Init();
                inited = true;
            }
        }

        public string Code
        {
            get
            {
                return pythonRunner.Code;
            }
        }

        private void Init()
        {
            if(initable)
            {
                pythonRunner.Request.type = PeripheralPythonEngine.PythonRequest.RequestType.INIT;
                Execute();
            }
        }

        private void HandleRead(long offset)
        {
            EnsureInit();

            pythonRunner.Request.value = 0;
            pythonRunner.Request.type = PeripheralPythonEngine.PythonRequest.RequestType.READ;
            pythonRunner.Request.offset = offset;
            pythonRunner.Request.counter = requestCounter++;
            Execute();
        }

        private void HandleWrite(long offset, ulong value)
        {
            EnsureInit();

            pythonRunner.Request.value = value;
            pythonRunner.Request.type = PeripheralPythonEngine.PythonRequest.RequestType.WRITE;
            pythonRunner.Request.offset = offset;
            pythonRunner.Request.counter = requestCounter++;
            Execute();
        }

        private void Execute()
        {
            pythonRunner.ExecuteCode();
        }

        private bool inited;
        private ulong requestCounter;

        private readonly PeripheralPythonEngine pythonRunner;
        private readonly bool initable;
        private readonly int size;
        private readonly string script;
        private readonly string filename;
    }
}
