//
// Copyright (c) 2010-2019 Antmicro
//
//  This file is licensed under the MIT License.
//  Full license text is available in 'licenses/MIT.txt'.
//
using Antmicro.Renode.Core;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Core.Structure.Registers;
using Antmicro.Renode.Time;
using System;
using static Antmicro.Renode.Utilities.BitHelper;
using Antmicro.Renode.Utilities;
using System.Collections.Generic;
using Antmicro.Renode.Logging;

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    public class STM32F4_RNG : IDoubleWordPeripheral, IKnownSize, IFuzzSnapshotRestorable
    {
        public STM32F4_RNG(IMachine machine)
        {
            IRQ = new GPIO();

            var registerMap = new Dictionary<long, DoubleWordRegister>
            {
                {(long)Registers.Control, new DoubleWordRegister(this)
                    .WithReservedBits(0, 2)
                    .WithFlag(2, out enable, changeCallback: (_, value) => Update(), name: "RNGEN")
                    .WithFlag(3, out interruptEnable, changeCallback: (_, value) => Update(), name: "IE")
                    .WithReservedBits(4, 28)
                },
                {(long)Registers.Status, new DoubleWordRegister(this)
                    .WithFlag(0, FieldMode.Read, valueProviderCallback: _ => enable.Value, name: "DRDY")
                    .WithTag("CECS", 1, 1)
                    .WithTag("SECS", 2, 1)
                    .WithReservedBits(3, 2)
                    .WithTag("CEIS", 5, 1)
                    .WithTag("SEIS", 6, 1)
                    .WithReservedBits(7, 25)
                },
                {(long)Registers.Data, new DoubleWordRegister(this)
                    .WithValueField(0, 32, FieldMode.Read, valueProviderCallback: _ =>
                {
                    if(enable.Value)
                    {
                        return unchecked((uint)rng.Next());
                    }
                    else
                    {
                        return 0;
                    }
                }, name: "RNDATA")
                },
            };
            registers = new DoubleWordRegisterCollection(this, registerMap);
        }

        public void Reset()
        {
            registers.Reset();
        }

        public void fuzz_snap_capture()
        {
            Console.WriteLine("^^^^^ STM32F4_RNG.cs fuzz_snap_capture()");
            
            // Capture register field states
            fuzz_snap_enable = enable?.Value ?? false;
            fuzz_snap_interruptEnable = interruptEnable?.Value ?? false;
            
            // Capture GPIO state
            fuzz_snap_irqActive = IRQ.IsSet;
        }

        public void fuzz_snap_restore()
        {
            // Console.WriteLine("^^^^^ STM32F4_RNG.cs fuzz_snap_restore()");
            
            // Restore register field states
            if (enable != null)
            {
                enable.Value = fuzz_snap_enable;
            }
            if (interruptEnable != null)
            {
                interruptEnable.Value = fuzz_snap_interruptEnable;
            }
            
            // Restore GPIO state
            if (fuzz_snap_irqActive)
            {
                IRQ.Set();
            }
            else
            {
                IRQ.Unset();
            }
        }

        public uint ReadDoubleWord(long offset)
        {
            return registers.Read(offset);
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            registers.Write(offset, value);
        }

        private void Update()
        {
            IRQ.Set(enable.Value && interruptEnable.Value);
        }

        public long Size => 0x400;
        public GPIO IRQ { get; private set; }

        private DoubleWordRegisterCollection registers;
        private PseudorandomNumberGenerator rng = EmulationManager.Instance.CurrentEmulation.RandomGenerator;
        private IFlagRegisterField enable;
        private IFlagRegisterField interruptEnable;

        // Fuzz snapshot variables
        private bool fuzz_snap_enable;
        private bool fuzz_snap_interruptEnable;
        private bool fuzz_snap_irqActive;

        private enum Registers
        {
            Control = 0x0,
            Status = 0x4,
            Data = 0x8,
        }
    }
}
