//
// Copyright (c) 2010-2024 Antmicro
// Copyright (c) 2022 SICK AG
//
// This file is licensed under the MIT License.
// Full license text is available in 'licenses/MIT.txt'.
//

using System.Collections.Generic;
using Antmicro.Renode.Core;
using Antmicro.Renode.Core.Structure.Registers;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Utilities;
using System;

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    [AllowedTranslations(AllowedTranslation.ByteToDoubleWord | AllowedTranslation.WordToDoubleWord)]
    public sealed class STM32_PWR : BasicDoubleWordPeripheral, IKnownSize, IFuzzSnapshotRestorable
    {
        public STM32_PWR(IMachine machine) : base(machine)
        {
            DefineRegisters();
        }
        
        private void DefineRegisters()
        {
            Registers.PowerControl.Define(this, 0xFCC00, name: "PWR_CR")
                .WithTaggedFlag("LPDS", 0)
                .WithTaggedFlag("PDDS", 1)
                .WithTaggedFlag("CWUF", 2)
                .WithTaggedFlag("CSBF", 3)
                .WithTaggedFlag("PVDE", 4)
                .WithEnumField<DoubleWordRegister, PvdLevelSelection>(5, 3, name: "PLS")
                .WithFlag(8, name: "DBP")
                .WithTaggedFlag("FPDS", 9)
                .WithTaggedFlag("LPUDS", 10)
                .WithTaggedFlag("MRUDS", 11)
                .WithReservedBits(12, 1)
                .WithTaggedFlag("ADCD1", 13)
                .WithEnumField<DoubleWordRegister, RegulatorVoltageScalingOutputSelection>(14, 2, out vosValue, name: "VOS", writeCallback: (_, value) =>
                    {
                        if(value == RegulatorVoltageScalingOutputSelection.Reserved)
                        {
                            vosValue.Value = RegulatorVoltageScalingOutputSelection.ScaleMode3;
                        }
                        vosrdyValue.Value = true;
                    })
                .WithFlag(16, name: "ODEN", writeCallback: (_, value) =>
                    {
                        if(!value)
                        {
                            odswenValue.Value = false;
                        }

                        odrdyValue.Value = value;
                    })
                .WithFlag(17, out odswenValue, name: "ODSWEN", writeCallback: (_, value) => { odswrdyValue.Value = value; })
                .WithEnumField<DoubleWordRegister, UnderDriveEnableInStopMode>(18, 2, name: "UDEN")
                .WithReservedBits(20, 12);
                
            Registers.PowerControlStatus.Define(this, name: "PWR_CSR")
                .WithTaggedFlag("WUF", 0)
                .WithTaggedFlag("SBF", 1)
                .WithTaggedFlag("PVDO", 2)
                .WithTaggedFlag("BRR", 3)
                .WithReservedBits(4, 4)
                .WithTaggedFlag("EWUP", 8)
                .WithTaggedFlag("BER", 9)
                .WithReservedBits(10, 4)
                .WithFlag(14, out vosrdyValue, FieldMode.Read, name: "VOSRDY")
                .WithReservedBits(15, 1)
                .WithFlag(16, out odrdyValue, FieldMode.Read, name: "ODRDY")
                .WithFlag(17, out odswrdyValue, FieldMode.Read, name: "ODSWRDY")
                .WithEnumField<DoubleWordRegister, UnderDriveReady>(18, 2, FieldMode.Read | FieldMode.WriteOneToClear, name: "UDRDY")
                .WithReservedBits(20, 12);
        }

        public void fuzz_snap_capture()
        {
            Console.WriteLine("^^^^^ STM32_PWR.cs fuzz_snap_capture()");
            
            // Capture register field states
            fuzz_snap_vosValue = vosValue?.Value ?? RegulatorVoltageScalingOutputSelection.ScaleMode3;
            fuzz_snap_odswenValue = odswenValue?.Value ?? false;
            fuzz_snap_vosrdyValue = vosrdyValue?.Value ?? false;
            fuzz_snap_odrdyValue = odrdyValue?.Value ?? false;
            fuzz_snap_odswrdyValue = odswrdyValue?.Value ?? false;
        }

        public void fuzz_snap_restore()
        {
            // Console.WriteLine("^^^^^ STM32_PWR.cs fuzz_snap_restore()");
            
            // Restore register field states
            if (vosValue != null)
            {
                vosValue.Value = fuzz_snap_vosValue;
            }
            if (odswenValue != null)
            {
                odswenValue.Value = fuzz_snap_odswenValue;
            }
            if (vosrdyValue != null)
            {
                vosrdyValue.Value = fuzz_snap_vosrdyValue;
            }
            if (odrdyValue != null)
            {
                odrdyValue.Value = fuzz_snap_odrdyValue;
            }
            if (odswrdyValue != null)
            {
                odswrdyValue.Value = fuzz_snap_odswrdyValue;
            }
        }

        public long Size => 0x400;

        private IEnumRegisterField<RegulatorVoltageScalingOutputSelection> vosValue;
        private IFlagRegisterField odswenValue;
        private IFlagRegisterField vosrdyValue;
        private IFlagRegisterField odrdyValue;
        private IFlagRegisterField odswrdyValue;

        // Fuzz snapshot variables
        private RegulatorVoltageScalingOutputSelection fuzz_snap_vosValue;
        private bool fuzz_snap_odswenValue;
        private bool fuzz_snap_vosrdyValue;
        private bool fuzz_snap_odrdyValue;
        private bool fuzz_snap_odswrdyValue;

        private enum Registers
        {
            PowerControl = 0x0,
            PowerControlStatus = 0x4
        }

        private enum PvdLevelSelection
        {
            V2_0,
            V2_1,
            V2_3,
            V2_5,
            V2_6,
            V2_7,
            V2_8,
            V2_9
        }

        private enum RegulatorVoltageScalingOutputSelection
        {
            Reserved,
            ScaleMode3,
            ScaleMode2,
            ScaleMode1
        }

        private enum UnderDriveEnableInStopMode
        {
            UnderDriveDisable,
            Reserved1,
            Reserved2,
            UnderDriveEnable
        }

        private enum UnderDriveReady
        {
            UnderDriveDisabled,
            Reserved1,
            Reserved2,
            UnderDriveActivated
        }
    }
}
