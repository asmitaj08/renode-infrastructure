//
// Copyright (c) 2010-2023 Antmicro
// Copyright (c) 2011-2015 Realtime Embedded
//
// This file is licensed under the MIT License.
// Full license text is available in 'licenses/MIT.txt'.
//
using System;
using System.IO;
using Antmicro.Renode.Core;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Peripherals.CPU;
using Antmicro.Renode.Exceptions;
using Microsoft.Scripting.Hosting;
using Antmicro.Migrant.Hooks;
using Antmicro.Migrant;
using System.Runtime.InteropServices;

namespace Antmicro.Renode.Hooks
{
    public sealed class BlockPythonEngine : PythonEngine
    {
        // static byte[] CovMap = new byte[8 * 1024];
        [DllImport("/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/target/release/liblibafl_renode.so")] 
        // public static extern void update_cov_map(ulong pc);
        public static extern IntPtr get_cov_map_ptr();  
        public const int MAP_SIZE = 8 * 1024;
        public static IntPtr covMapPtr = get_cov_map_ptr(); 
        public BlockPythonEngine(IMachine mach, ICPUWithHooks cpu, string script)
        {
            Script = script;
            CPU = cpu;
            Machine = mach;
            ulong PREV_LOC = 0;
            int index=0;
            
            // Console.WriteLine($"Inside  BlockPythonEngine class");
            InnerInit();

            Hook = (_, pc) =>
            {  //Console.WriteLine($"^^^^^^^^^^^^^^^^^^Inside  BlockPythonEngine Hook");
                Scope.SetVariable("pc", pc);
                Execute(code, error =>
                {
                    CPU.Log(LogLevel.Error, "Python runtime error: {0}", error);
                });
            };

            HookWithSize = (pc, size) =>
            {
                // Console.WriteLine($"^^^^^^^^^^^^^^^^Inside  BlockPythonEngine HookWithSize");
                Scope.SetVariable("pc", pc);
                Scope.SetVariable("size", size);
                covMapPtr = get_cov_map_ptr();
                ulong hash = (pc ^ PREV_LOC) & (MAP_SIZE - 1);
                byte newValue = Marshal.ReadByte(covMapPtr + (int)hash * sizeof(int));
                byte prev_new_val = newValue;
                newValue++;
                Marshal.WriteByte(covMapPtr + (int)hash * sizeof(int), newValue);
                // CovMap[index] = newValue;
                PREV_LOC = pc >> 1;
                // byte newValue2 = Marshal.ReadByte(LibAflInterop.covMapPtr + (int)hash * sizeof(int));
                // using (StreamWriter logfile = new StreamWriter("/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/log_renode.txt", true))
                // {
                //     logfile.WriteLine($"Called hook, cov_ptr : {covMapPtr}, new_addr : {covMapPtr + (int)hash * sizeof(int)}, pc : {pc.ToString("X")}");
                // }
                //LibAflInterop.block_hook(pc);
                // Console.WriteLine($"Inside  BlockPythonEngine HookWithSize");
                Execute(code, error =>
                {
                    CPU.Log(LogLevel.Error, "Python runtime error: {0}", error);
                });
            };
        }

        [PostDeserialization]
        private void InnerInit()
        {
            // Console.WriteLine("^^^^ SBlockPythonEngine.cs  InnerInit --- postDeserialization");
            Scope.SetVariable(Core.Machine.MachineKeyword, Machine);
            Scope.SetVariable("cpu", CPU);
            Scope.SetVariable("self", CPU);
            var source = Engine.CreateScriptSourceFromString(Script);
            code = Compile(source);
        }

        public Action<ICpuSupportingGdb, ulong> Hook { get; private set; }

        public Action<ulong, uint> HookWithSize { get; private set; }

        [Transient]
        private CompiledCode code;

        private readonly string Script;
        private readonly ICPUWithHooks CPU;
        private readonly IMachine Machine;
    }
}
