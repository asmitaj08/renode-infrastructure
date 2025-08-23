//
// Copyright (c) 2010-2023 Antmicro
//
// This file is licensed under the MIT License.
// Full license text is available in 'licenses/MIT.txt'.
//
using System;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Core;
using Antmicro.Renode.Core.Structure.Registers;
using Antmicro.Renode.Logging;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using Antmicro.Renode.Utilities;

namespace Antmicro.Renode.Peripherals.IRQControllers
{
    public class STM32F4_EXTI : BasicDoubleWordPeripheral, IKnownSize, IIRQController, INumberedGPIOOutput, IFuzzSnapshotRestorable
    {
        public STM32F4_EXTI(IMachine machine, int numberOfOutputLines = 14, int firstDirectLine = DefaultFirstDirectLine) : base(machine)
        {
            var innerConnections = new Dictionary<int, IGPIO>();
            for(var i = 0; i < numberOfOutputLines; ++i)
            {
                innerConnections[i] = new GPIO();
            }
            Connections = new ReadOnlyDictionary<int, IGPIO>(innerConnections);

            // All lines lower than firstDirectLine are configurable so they should be masked
            // treatOutOfRangeLinesAsDirect is set to true to preserve backwards compatibility
            core = new STM32_EXTICore(this, BitHelper.CalculateQuadWordMask(firstDirectLine, 0), treatOutOfRangeLinesAsDirect: true, allowMaskingDirectLines: false);

            numberOfLinesMask = BitHelper.CalculateQuadWordMask((int)NumberOfLines, 0);
            this.firstDirectLine = firstDirectLine;

            DefineRegisters();
            Reset();
        }

        public void OnGPIO(int number, bool value)
        {
            if(number >= NumberOfLines)
            {
                this.Log(LogLevel.Error, "GPIO number {0} is out of range [0; {1})", number, NumberOfLines);
                return;
            }
            var lineNumber = (byte)number;

            if(core.CanSetInterruptValue(lineNumber, value, out var isLineConfigurable))
            {
                // Configurable lines can only be set in this place.
                value = isLineConfigurable ? true : value;
                core.UpdatePendingValue(lineNumber, value);
                Connections[number].Set(value);
            }
        }

        public override void Reset()
        {
            // Console.WriteLine("****** STM32F4_EXTI.cs Reset");
            base.Reset();
            softwareInterrupt = 0;
            foreach(var gpio in Connections)
            {
                gpio.Value.Unset();
            }
        }

        private ulong fuzz_snap_softwareInterrupt;
        private Dictionary<int, bool> fuzz_snap_gpioStates;
        private ulong fuzz_snap_imr;
        private ulong fuzz_snap_rtsr;
        private ulong fuzz_snap_ftsr;
        private ulong fuzz_snap_pr;

        public void fuzz_snap_capture()
        {
            Console.WriteLine("^^^^STM32F4_EXTI.cs fuzz_snap_capture()");
            fuzz_snap_softwareInterrupt = softwareInterrupt;
            fuzz_snap_gpioStates = new Dictionary<int, bool>();
            foreach(var kvp in Connections)
            {
                fuzz_snap_gpioStates[kvp.Key] = kvp.Value.IsSet; // IsSet is a property of GPIO
            }
            //capture core register states
            fuzz_snap_imr = core.InterruptMask.Value;
            fuzz_snap_rtsr = core.RisingEdgeMask.Value;
            fuzz_snap_ftsr = core.FallingEdgeMask.Value;
            fuzz_snap_pr = core.PendingInterrupts.Value;

        }

        public void fuzz_snap_restore()
        {
            // Console.WriteLine("^^^^STM32F4_EXTI.cs fuzz_snap_restore()");
            // base.Reset();
            // 1) Restore masks and trigger configuration first (no callbacks)
            var validMask = numberOfLinesMask;
            var imr = fuzz_snap_imr & validMask;
            var rtsr = fuzz_snap_rtsr & validMask;
            var ftsr = fuzz_snap_ftsr & validMask;
            var pr = fuzz_snap_pr & validMask;
            var swierMasked = fuzz_snap_softwareInterrupt & validMask;

            core.InterruptMask.Value = imr;
            core.RisingEdgeMask.Value = rtsr;
            core.FallingEdgeMask.Value = ftsr;

            // 2) Restore pending register directly to avoid W1C side-effects
            core.PendingInterrupts.Value = pr;

            // 3) Deterministically drive outputs: assert only when pending AND unmasked; otherwise ensure unset
            for(var i = 0; i < (int)NumberOfLines; ++i)
            {
                var pending = ((pr >> i) & 1ul) != 0;
                var unmasked = ((imr >> i) & 1ul) != 0;
                var isConfigurable = i < firstDirectLine;
                bool shouldSet;
                if(isConfigurable)
                {
                    // Configurable lines: latched pending OR SWIER, gated by mask
                    var swier = ((swierMasked >> i) & 1ul) != 0;
                    shouldSet = (pending || swier) && unmasked;
                }
                else
                {
                    // Direct lines: reflect captured GPIO level if available; fallback to pending
                    if(fuzz_snap_gpioStates != null && fuzz_snap_gpioStates.TryGetValue(i, out var capturedLevel))
                    {
                        shouldSet = capturedLevel;
                    }
                    else
                    {
                        shouldSet = pending;
                    }
                }
                if(shouldSet)
                {
                    Connections[i].Set();
                }
                else
                {
                    Connections[i].Unset();
                }
            }

            // 4) Restore software interrupt bitmap last (it is not directly driving outputs)
            softwareInterrupt = swierMasked;

        }


        public long Size => 0x400;

        public IReadOnlyDictionary<int, IGPIO> Connections { get; }

        public long NumberOfLines => Connections.Count;

        private void DefineRegisters()
        {
            Registers.InterruptMask.Define(this)
                .WithValueField(0, 32, out core.InterruptMask, name: "IMR");

            // Blank implementation to preserve backwards compatibility with the previous version of this model
            Registers.EventMask.Define(this)
                .WithValueField(0, 32, name: "EMR");

            Registers.RisingTriggerSelection.Define(this)
                .WithValueField(0, 32, out core.RisingEdgeMask, name: "RTSR");

            Registers.FallingTriggerSelection.Define(this)
                .WithValueField(0, 32, out core.FallingEdgeMask, name: "FTSR");

            Registers.SoftwareInterruptEvent.Define(this)
                .WithValueField(0, 32, name: "SWIER", valueProviderCallback: _ => softwareInterrupt,
                    writeCallback: (_, value) =>
                    {
                        value &= numberOfLinesMask;
                        BitHelper.ForeachActiveBit(value & core.InterruptMask.Value, x => Connections[x].Set());
                    });

            Registers.PendingRegister.Define(this)
                .WithValueField(0, 32, out core.PendingInterrupts, FieldMode.Read | FieldMode.WriteOneToClear, name: "PR",
                    writeCallback: (_, value) =>
                    {
                        softwareInterrupt &= ~value;
                        value &= numberOfLinesMask;
                        BitHelper.ForeachActiveBit(value, x => Connections[x].Unset());
                    });
        }

        // We treat lines above 23 as direct by default for backwards compatibility with
        // the old behavior of the EXTI model.
        protected const int DefaultFirstDirectLine = 23;

        private ulong softwareInterrupt;

        private readonly ulong numberOfLinesMask;
        private readonly STM32_EXTICore core;
        private readonly int firstDirectLine;

        private enum Registers
        {
            InterruptMask = 0x0,
            EventMask = 0x4,
            RisingTriggerSelection = 0x8,
            FallingTriggerSelection = 0xC,
            SoftwareInterruptEvent = 0x10,
            PendingRegister = 0x14
        }
    }
}
