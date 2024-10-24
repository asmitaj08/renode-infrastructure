//
// Copyright (c) 2010-2023 Antmicro
//
// This file is licensed under the MIT License.
// Full license text is available in 'licenses/MIT.txt'.
//

using System;
using System.Linq;
using System.Collections.Generic;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Core;
using Antmicro.Renode.Core.Structure.Registers;
using Antmicro.Renode.Utilities;
using System.IO;
namespace Antmicro.Renode.Peripherals.I2C
{
    // public class BME280_modified : II2CPeripheral, IProvidesRegisterCollection<ByteRegisterCollection>
    public class BME280_modified : II2CPeripheral
    {
        public BME280_modified()
        {
            // Console.WriteLine("** Inside BME280 constructor");
            // RegistersCollection = new ByteRegisterCollection(this);
            // DefineRegisters();
            configValues = LoadConfiguration("/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/sensor_config_files/test_config"); // Load configuration file
            Reset();
        }

        public void Reset()
        {
            Console.WriteLine("** BME280 Reset");
            // RegistersCollection.Reset();
            selectedRegister = 0x0;
            // EncodeTemperature();
            // EncodeHumidity();
            // EncodePressure();
            state = State.Idle;

        }

        public void Write(byte[] data)
        {
            // this.Log(LogLevel.Noisy, "Write {0}", dConvert.ToByte(value, 16)ata.Select(x => x.ToString("X")).Aggregate((x, y) => x + " " + y));

            // Console.WriteLine($"** Inside BME280 write()");
            foreach(var b in data)
            {
                // Console.WriteLine($"** Inside BME280 write(), data : {(Registers)b}, state : {state}");

                switch(state)
                {   

                    case State.Idle:
                        selectedRegister = (Registers)b;
                        // Console.WriteLine($"** Inside BME280 write(), selected_reg : {selectedRegister},data : 0x{b:X}, state : {state}");
                        state = State.ReceivedFirstByte;
                        break;
                    case State.ReceivedFirstByte:
                    case State.WritingWaitingForValue:
                        // Console.WriteLine($"** Inside BME280 write(), selected_reg : {selectedRegister},data : 0x{b:X}, state : {state}");
                        // RegistersCollection.Write((byte)selectedRegister, b); //bme280 have 256 addressable registers the same as byte max value
                        state = State.WaitingForAddress;
                        if(selectedRegister == Registers.Reset && b == resetRequestVal){
                            Reset();
                        }
                        break;
                    case State.WaitingForAddress:
                        // Console.WriteLine($"** Inside BME280 write(), selected_reg : {selectedRegister},data : 0x{b:X}, state : {state}");
                        selectedRegister = (Registers)b;
                        state = State.WritingWaitingForValue;
                        break;
                    case State.Reading:
                        //this isn't documented, but reads are able to use address set during write transfer, opposite isn't true
                        this.Log(LogLevel.Warning, "Trying to write without specifying address, byte is omitted");
                        break;
                }
            }
        }

        public byte[] Read(int count = 0)
        {
            // Console.WriteLine($"** Inside BME280 Read(), BUFlEN : {count}");
            state = State.Reading; //reading can be started regardless of state, last selectedRegister is used
            bool present_in_config_flag = false;
            if ((configValues.ContainsKey((byte)selectedRegister))){
                present_in_config_flag = true;
                Console.WriteLine($"Selected Reg present in config file ");
            }
            // byte[] buf = new byte[count];
            if ((!(present_in_config_flag)) && general_fuzz_data!=0xAA){
                    count = general_fuzz_data;
                    Console.WriteLine($"fuzzing length : {count}");
            }
            byte[] buf = new byte[count]; // fuzzing data length, need to specifiy when to do 
            for(int i = 0; i < buf.Length; i++)
            {
                //bme280 have 256 addressable registers, byte covers them all and allows roll-over like in real hardware
                // buf[i] = RegistersCollection.Read((byte)selectedRegister);
                // if (fuzz_reg.Contains((byte)selectedRegister)){
                //       buf[i] = general_fuzz_data;
                // }
                // if (configValues.TryGetValue((byte)selectedRegister, out var value)){
                //     buf[i] = value;
                // }
                if (present_in_config_flag){
                    buf[i] = configValues[(byte)selectedRegister];
                }
                else {
                    // buf[i] = RegistersCollection.Read((byte)selectedRegister);
                    buf[i] = general_fuzz_data;
                }
                
                Console.WriteLine($"** Inside BME280 Read(), selectedReg : 0x{selectedRegister:X}, state : {state}, count : {count}, data: 0x{buf[i]:X}");

                // selectedRegister++;
            }
            this.Log(LogLevel.Noisy, "Read {0}", buf.Select(x => x.ToString("X")).Aggregate((x, y) => x + " " + y));

            return buf;
        }

        public void FinishTransmission()
        {
            // Console.WriteLine("** BME280 FinishTransmission");
            if(state != State.ReceivedFirstByte) //in case of reading we may (documentation permits this or repeated START) receive STOP before the read transfer
            {
                if(state == State.WritingWaitingForValue)
                {
                    this.Log(LogLevel.Warning, "Trying to write odd amount of bytes, last register is missing its value");
                }
                state = State.Idle;
            }
        }
        public void ReadFromFuzzer(byte[] data){
                general_fuzz_data = data[0];
                // Console.WriteLine($"%%%%Inside BME280 ReadFromFuzzer : data read {data}, {general_fuzz_data}");
        }

        // public double Temperature
        // {
        //     get
        //     {
        //         Console.WriteLine($"##### Inside Temp get :{temperature} ");
        //         return temperature;
        //     }
        //     set
        //     {
        //         temperature = value;
        //         Console.WriteLine("##### Inside Temp set");
        //         EncodeTemperature();
        //     }
        // }

        // public double Pressure
        // {
        //     get
        //     {
        //         // Console.WriteLine($"##### Inside pressure get :{pressure} ");
        //         return pressure;
        //     }
        //     set
        //     {
        //         pressure = value;
        //         // Console.WriteLine("##### Inside Pressure set");
        //         EncodePressure();
        //     }
        // }

        // public double Humidity
        // {
        //     get
        //     {
        //         // Console.WriteLine($"##### Inside humidity get :{humidity} ");
        //         return humidity;
        //     }
        //     set
        //     {
        //         humidity = value;
        //         // Console.WriteLine("##### Inside Humidity set");
        //         EncodeHumidity();
        //     }
        // }

        // public ByteRegisterCollection RegistersCollection { get; }

        // private void DefineRegisters()
        // {   
        //     Console.WriteLine("##### Inside defineReg BME280()");
        //     // Registers.HumLsb.Define(this, 0x0)
        //     //     .WithValueField(0, 8, out humLsb, FieldMode.Read);
        //     // Registers.HumMsb.Define(this, 0x80)
        //     //     .WithValueField(0, 8, out humMsb, FieldMode.Read);
        //     // Registers.TempXlsb.Define(this, 0x0)
        //     //     .WithValueField(0, 8, out tempXlsb, FieldMode.Read);
        //     // Registers.TempLsb.Define(this, 0x0)
        //     //     .WithValueField(0, 8, out tempLsb, FieldMode.Read);
        //     // Registers.TempMsb.Define(this, 0x80)
        //     //     .WithValueField(0, 8, out tempMsb, FieldMode.Read);
        //     // Registers.PressXlsb.Define(this, 0x0)
        //     //     .WithValueField(0, 8, out pressXlsb, FieldMode.Read);
        //     // Registers.PressLsb.Define(this, 0x0)
        //     //     .WithValueField(0, 8, out pressLsb, FieldMode.Read);
        //     // Registers.PressMsb.Define(this, 0x80)
        //     //     .WithValueField(0, 8, out pressMsb, FieldMode.Read);
        //     Registers.Config.Define(this, 0x0)
        //         .WithValueField(0, 8, name: "Config"); //read by the software, we need to implement it as a field, and not a tag
        //     Registers.CtrlMeas.Define(this, 0x0)
        //         .WithValueField(0, 8, name: "CtrlMeas"); //read by the software, we need to implement it as a field, and not a tag
        //     Registers.Status.Define(this, 0x0)
        //         .WithValueField(0, 8, name: "Status"); //read by the software, we need to implement it as a field, and not a tag
        //     Registers.CtrlHum.Define(this, 0x0)
        //         .WithValueField(0, 8, name: "CtrlHum"); //read by the software, we need to implement it as a field, and not a tag
        //     Registers.Reset.Define(this, 0x0)
        //         .WithValueField(0, 8)
        //         .WithWriteCallback((_, val) =>
        //         {
        //             if(val == resetRequestVal)
        //             {
        //                 // Console.WriteLine("Reset request");
        //                 Reset();
        //             }
        //         });
        //     Registers.Id.Define(this, 0x60)
        //         .WithValueField(0, 8, FieldMode.Read, valueProviderCallback: _ => 0x60);

        //     const ushort digT1T2 = 2 << 14;

        //     Registers.Calib0.Define(this, unchecked((byte)digT1T2));
        //     Registers.Calib1.Define(this, (byte)(digT1T2 >> 8));
        //     Registers.Calib2.Define(this, unchecked((byte)digT1T2));
        //     Registers.Calib3.Define(this, (byte)(digT1T2 >> 8));
        //     Registers.Calib4.Define(this, 0x0);
        //     Registers.Calib5.Define(this, 0x0);

        //     const ushort digP1P2 = 1;
        //     const ushort digP8 = 2 << 13;

        //     Registers.Calib6.Define(this, (byte)digP1P2);
        //     Registers.Calib7.Define(this, (byte)(digP1P2 >> 8));
        //     Registers.Calib8.Define(this, (byte)digP1P2);
        //     Registers.Calib9.Define(this, (byte)(digP1P2 >> 8));
        //     Registers.Calib10.Define(this, 0x0);
        //     Registers.Calib11.Define(this, 0x0);
        //     Registers.Calib12.Define(this, 0x0);
        //     Registers.Calib13.Define(this, 0x0);
        //     Registers.Calib14.Define(this, 0x0);
        //     Registers.Calib15.Define(this, 0x0);
        //     Registers.Calib16.Define(this, 0x0);
        //     Registers.Calib17.Define(this, 0x0);
        //     Registers.Calib18.Define(this, 0x0);
        //     Registers.Calib19.Define(this, 0x0);
        //     Registers.Calib20.Define(this, unchecked((byte)digP8));
        //     Registers.Calib21.Define(this, (byte)(digP8 >> 8));
        //     Registers.Calib22.Define(this, 0x0);
        //     Registers.Calib23.Define(this, 0x0);
        //     Registers.Calib24.Define(this, 0x0);

        //     const short digH2 = 361;
        //     const short digH4 = 321;
        //     const short digH5 = 50;
        //     const sbyte digH6 = 30;

        //     Registers.Calib25.Define(this, 0x0);
        //     Registers.Calib26.Define(this, unchecked((byte)digH2));
        //     Registers.Calib27.Define(this, (byte)(digH2 >> 8));
        //     Registers.Calib28.Define(this, 0x0);
        //     Registers.Calib29.Define(this, (byte)(digH4 >> 4));
        //     Registers.Calib30.Define(this, (byte)((digH4 & 0x0F) | (digH5 & 0x0F) << 4));
        //     Registers.Calib31.Define(this, (byte)(digH5 >> 4));
        //     Registers.Calib32.Define(this, (byte)digH6);
        //     Registers.Calib33.Define(this, 0x0);
        //     Registers.Calib34.Define(this, 0x0);
        //     Registers.Calib35.Define(this, 0x0);
        //     Registers.Calib36.Define(this, 0x0);
        //     Registers.Calib37.Define(this, 0x0);
        //     Registers.Calib38.Define(this, 0x0);
        //     Registers.Calib39.Define(this, 0x0);
        //     Registers.Calib40.Define(this, 0x0);
        //     Registers.Calib41.Define(this, 0x0);
        // }

        // private ushort RegistersToUShort(Registers lo, Registers hi)
        // {
        //     ushort val = RegistersCollection.Read((byte)lo);
        //     val |= (ushort)(RegistersCollection.Read((byte)hi) << 8);
        //     return val;
        // }

        // private short RegistersToShort(Registers lo, Registers hi)
        // {
        //     return (short)RegistersToUShort(lo, hi);
        // }

        // private int GetAdcTemperature()
        // {
        //     var digT1 = RegistersToUShort(Registers.Calib0, Registers.Calib1);
        //     var digT2 = RegistersToShort(Registers.Calib2, Registers.Calib3);

        //     //formula and constants derived from the compensation formula in datasheet
        //     return (int)Math.Round(((Temperature * 100 * 256 - 128)/(5 * digT2) * 2048 + digT1 * 2) * 8);
        // }

        // private void EncodeTemperature()
        // {
        //     int t = GetAdcTemperature();

        //     tempXlsb.Value = (byte)((t & 0x0F) << 4);
        //     tempLsb.Value = (byte)(t >> 4);
        //     tempMsb.Value = (byte)(t >> 12);
        //     // Console.WriteLine($"###### Inside Encode Temp , tempXlsb : 0x{tempXlsb.Value:X}, tempLsb : 0x{tempLsb.Value:X}, tempMsb : 0x{tempMsb.Value:X}");
        // }

        // private void EncodePressure()
        // {
        //     var digT1 = RegistersToUShort(Registers.Calib0, Registers.Calib1);
        //     var digT2 = RegistersToShort(Registers.Calib2, Registers.Calib3);
        //     var digP1 = RegistersToUShort(Registers.Calib6, Registers.Calib7);
        //     var digP2 = RegistersToShort(Registers.Calib8, Registers.Calib9);
        //     var digP8 = RegistersToShort(Registers.Calib20, Registers.Calib21);

        //     int adcTemp = GetAdcTemperature();
        //     //formula and constants derived from the compensation formula in datasheet
        //     long v1 = (((Int64)2 << 47) + (adcTemp / 8 - digT1 * 2) * digT2 / 2048 - 128000) * digP2 * 4096 * digP1 / ((Int64)2 << 33);
        //     int p = (int)Math.Round(-((Pressure - 52) * (2 << 27) / (digP8 + 1) * v1) / (3125 * ((Int64)2 << 31)) * 2 + 1048576);

        //     pressXlsb.Value = (byte)((p & 0x0F) << 4);
        //     pressLsb.Value = (byte)(p >> 4);
        //     pressMsb.Value = (byte)(p >> 12);
        //     // Console.WriteLine($"###### Inside Encode Pressure , pressXlsb : 0x{pressXlsb.Value:X}, pressLsb : 0x{pressLsb.Value:X}, pressMsb : 0x{pressMsb.Value:X}");
        // }

        // private void EncodeHumidity()
        // {
        //     const ushort h0 = 20650;
        //     const ushort h100 = 38550;
        //     ushort h = (ushort)(h0 + (h100 - h0) * Humidity / 100);
        //     // Console.WriteLine($"###### Inside Encode Humidity , value of Humidity is : {Humidity}");
        //     humLsb.Value = (byte)h;
        //     humMsb.Value = (byte)(h >> 8);
        //     // Console.WriteLine($"###### Inside Encode Humidity , humLsb : 0x{humLsb.Value:X}, humMsb : 0x{humMsb.Value:X}");
        // }
        
        //Dictionary with value specific to sensor offset, the value at offset could be hardcoded (liek chip id, status, etc) or marked as 'F' that is to be fuzzed
        // private Dictionary<long, string> LoadConfiguration(string filePath) 
        // {
        //     var config = new Dictionary<long, string>();
        //     foreach (var line in File.ReadAllLines(filePath))
        //     {
        //         var parts = line.Split('=');
        //         var offset = Convert.ToInt64(parts[0], 16);  // Parse offset in hex
        //         config[offset] = parts[1];  // Store the value (hex or 'F'(for fuzzing)) , currently only storing the offset addr whose value has to be hardcoded
        //     }
        //     return config;
        // }
        private Dictionary<byte, byte> LoadConfiguration(string filePath) 
        {
            var config = new Dictionary<byte, byte>();
            foreach (var line in File.ReadAllLines(filePath))
            {
                var parts = line.Split('=');
                var offset = Convert.ToByte(parts[0], 16);
                var val = Convert.ToByte(parts[1], 16);  // Parse offset in hex
                config[offset] = val;  // Store the value (hex or 'F'(for fuzzing)) , currently only storing the offset addr whose value has to be hardcoded
            }
            return config;
        }

        private byte general_fuzz_data = 0xAA ;
        // private static List<byte> fuzz_reg = new List<byte> { 0xFE, 0xFD, 0xFC,0xFB,0xFA,0xF9,0xF8,0xF7 };
        private State state;
        private Registers selectedRegister;

        // private double temperature;
        // private double pressure;
        // private double humidity;

        // private IValueRegisterField humLsb;
        // private IValueRegisterField humMsb;
        // private IValueRegisterField tempXlsb;
        // private IValueRegisterField tempLsb;
        // private IValueRegisterField tempMsb;
        // private IValueRegisterField pressLsb;
        // private IValueRegisterField pressMsb;
        // private IValueRegisterField pressXlsb;

        private const byte resetRequestVal = 0xB6;
        private Dictionary<byte, byte> configValues; // To store configuration from the file.

        private enum Registers
        {
            Calib0 = 0x88,
            Calib1 = 0x89,
            Calib2 = 0x8A,
            Calib3 = 0x8B,
            Calib4 = 0x8C,
            Calib5 = 0x8D,
            Calib6 = 0x8E,
            Calib7 = 0x8F,
            Calib8 = 0x90,
            Calib9 = 0x91,
            Calib10 = 0x92,
            Calib11 = 0x93,
            Calib12 = 0x94,
            Calib13 = 0x95,
            Calib14 = 0x96,
            Calib15 = 0x97,
            Calib16 = 0x98,
            Calib17 = 0x99,
            Calib18 = 0x9A,
            Calib19 = 0x9B,
            Calib20 = 0x9C,
            Calib21 = 0x9D,
            Calib22 = 0x9E,
            Calib23 = 0x9F,
            Calib24 = 0xA0,
            Calib25 = 0xA1,
            Id = 0xD0,
            Reset = 0xE0,
            Calib26 = 0xE1,
            Calib27 = 0xE2,
            Calib28 = 0xE3,
            Calib29 = 0xE4,
            Calib30 = 0xE5,
            Calib31 = 0xE6,
            Calib32 = 0xE7,
            Calib33 = 0xE8,
            Calib34 = 0xE9,
            Calib35 = 0xEA,
            Calib36 = 0xEB,
            Calib37 = 0xEC,
            Calib38 = 0xED,
            Calib39 = 0xEE,
            Calib40 = 0xEF,
            Calib41 = 0xF0,
            CtrlHum = 0xF2,
            Status = 0xF3,
            CtrlMeas = 0xF4,
            Config = 0xF5,
            PressMsb = 0xF7,
            PressLsb = 0xF8,
            PressXlsb = 0xF9,
            TempMsb = 0xFA,
            TempLsb = 0xFB,
            TempXlsb = 0xFC,
            HumMsb = 0xFD,
            HumLsb = 0xFE
        }

        private enum State
        {
            Idle,
            ReceivedFirstByte,
            WaitingForAddress,
            WritingWaitingForValue,
            Reading
        }
    }
}
