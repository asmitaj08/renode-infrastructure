//
// Copyright (c) 2010-2023 Antmicro
//
// This file is licensed under the MIT License.
// Full license text is available in 'licenses/MIT.txt'.
//
using System;
using System.Linq;
using System.Collections.Generic;
using Antmicro.Renode.Core;
using Antmicro.Renode.Core.Structure;
using Antmicro.Renode.Core.Structure.Registers;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Utilities;
using System.IO;
// using Newtonsoft.Json; // need to fix this for handling json config

namespace Antmicro.Renode.Peripherals.I2C
{
    public sealed class STM32F7_I2C_modified : SimpleContainer<II2CPeripheral>, II2CPeripheral, IDoubleWordPeripheral, IKnownSize
    {
        public STM32F7_I2C_modified(IMachine machine) : base(machine)
        {
            Console.WriteLine($"%%% Inside stm32f7_I2C constructor");
            EventInterrupt = new GPIO();
            ErrorInterrupt = new GPIO();
            registers = CreateRegisters();
            configValues = LoadConfiguration("/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/sensor_config_files/test_config"); // Load configuration file
            random = new Random();
            // LoadSensorConfig("/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/ensor_config_files/test_config"); // Load the config file here.
            Reset();
        }

        public uint ReadDoubleWord(long offset)
        {
            Console.WriteLine($"%%% Inside stm32f7_I2C readDouble(), offset : 0x{offset:X}, read_val : 0x{registers.Read(offset):X}");
            return registers.Read(offset);
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            Console.WriteLine($"%%% Inside stm32f7_I2C writeDouble(), offset : 0x{offset:X}, value : 0x{value:X}");
            registers.Write(offset, value);
        }

        public override void Reset()
        {
            Console.WriteLine("%% Inside stm32f7_I2C Reset()");
            registers.Reset();
            txData = new Queue<byte>();
            rxData = new Queue<byte>();
            currentSlaveAddress = 0;
            transferOutgoing = false;
            EventInterrupt.Unset();
            ErrorInterrupt.Unset();
            masterMode = false;
            state = State.Idle;
            selectedRegister = 0x0;
            // readStatusRegisterFlag = false;
        }

        public void Write(byte[] data)
        {
            // RM0444 Rev 5, p.991/1390
            // "0: Write transfer, slave enters receiver mode."
            Console.WriteLine($"@@@@@@@@2 Inside stm32f7_I2C WriteByte(), data : {data}");
            transferOutgoing = false;

            rxData.EnqueueRange(data);
        }

        public byte[] Read(int count = 1)
        {
            Console.WriteLine($"@@@@@@@@@ Inside stm32f7_I2C ReadByte(), count : {count}");
            if(!addressMatched.Value)
            {
                // Note 1:
                // RM0444 Rev 5, p.991/1390
                // "1: Read transfer, slave enters transmitter mode."
                // Note 2:
                // this is a workaround for the protocol not supporting start/stop bits
                transferOutgoing = (count > 0);
                bytesToTransfer.Value = (uint)count;
                addressMatched.Value = true;
                Update();
            }

            if(txData.Count >= (int)bytesToTransfer.Value)
            {
                // STOP condition
                stopDetection.Value = true;
                transmitInterruptStatus = false;
                addressMatched.Value = false;
                Update();
            }
            else
            {
                // TODO: return partial results
                return new byte[0];
            }

            var result = new byte[count];
            for(var i = 0; i < count; i++)
            {
                if(!txData.TryDequeue(out result[i]))
                {
                    return new byte[0];
                }
            }
            return result;
        }

        public void FinishTransmission()
        {
            Console.WriteLine("%%%%Iside stm32f7_i2c_ finish transmission");
            
        }

        public long Size { get { return 0x400; } }

        public GPIO EventInterrupt { get; private set; }

        public GPIO ErrorInterrupt { get; private set; }

        public bool RxNotEmpty => rxData.Count > 0;
        
        public bool OwnAddress1Enabled => ownAddress1Enabled.Value;

        private DoubleWordRegisterCollection CreateRegisters()
        {
            Console.WriteLine("%% Inside stm32f7_I2C CreateRegisters()");
            var map = new Dictionary<long, DoubleWordRegister> { {
                    (long)Registers.Control1, new DoubleWordRegister(this)
                        .WithFlag(0, writeCallback: PeripheralEnabledWrite, name: "PE")
                        .WithFlag(1, out transferInterruptEnabled, name: "TXIE")
                        .WithFlag(2, out receiveInterruptEnabled, name: "RXIE")
                        .WithFlag(3, out addressMatchedInterruptEnabled, name: "ADDRIE")
                        .WithFlag(4, out nackReceivedInterruptEnabled, name: "NACKIE")
                        .WithFlag(5, out stopDetectionInterruptEnabled, name: "STOPIE")
                        .WithFlag(6, out transferCompleteInterruptEnabled, name: "TCIE")
                        .WithTag("ERRIE", 7, 1)
                        .WithTag("DNF", 8, 4)
                        .WithTag("ANFOFF", 12, 1)
                        .WithReservedBits(13, 1)
                        .WithTag("TXDMAEN", 14, 1)
                        .WithTag("RXDMAEN", 15, 1)
                        .WithTag("SBC", 16, 1)
                        .WithFlag(17, out noStretch, name: "NOSTRETCH")
                        .WithTag("WUPEN", 18, 1)
                        .WithTag("GCEN", 19, 1)
                        .WithTag("SMBHEN", 20, 1)
                        .WithTag("SMBDEN", 21, 1)
                        .WithTag("ALERTEN", 22, 1)
                        .WithTag("PECEN", 23, 1)
                        .WithReservedBits(24, 8)
                        .WithChangeCallback((_,__) => Update())
                }, {
                    (long)Registers.Control2,
                    new DoubleWordRegister(this)
                        .WithValueField(0, 10, out slaveAddress, name: "SADD") //Changing this from a normal field to a callback requires a change in StartWrite
                        .WithFlag(10, out isReadTransfer, name: "RD_WRN")
                        .WithFlag(11, out use10BitAddressing, name: "ADD10")
                        .WithTag("HEAD10R", 12, 1)
                        .WithFlag(13, out start, name: "START")
                        .WithFlag(14, out stop, name: "STOP")
                        .WithTag("NACK", 15, 1)
                        .WithValueField(16, 8, out bytesToTransfer, name: "NBYTES")
                        .WithFlag(24, out reload, name: "RELOAD")
                        .WithFlag(25, out autoEnd, name: "AUTOEND")
                        .WithTag("PECBYTE", 26, 1)
                        .WithReservedBits(27, 5)
                        .WithWriteCallback((oldVal, newVal) =>
                        {
                            uint oldBytesToTransfer = (oldVal >> 16) & 0xFF;
                            // Console.WriteLine($"%% inside control2 writecallback, slave address : {newVal & 0x3FE}");
                            if(start.Value && stop.Value)
                            {
                                this.Log(LogLevel.Warning, "Setting START and STOP at the same time, ignoring the transfer");
                            }
                            else if(start.Value)
                            {
                                StartTransfer();
                            }
                            else if(stop.Value)
                            {
                                StopTransfer();
                            }

                            if(!start.Value)
                            {
                                // if(bytesToTransfer.Value > 0 && masterMode && transferCompleteReload.Value && currentSlave != null)
                                if(bytesToTransfer.Value > 0 && masterMode && transferCompleteReload.Value)
                                {
                                    ExtendTransfer();
                                }
                            }
                            else if(oldBytesToTransfer != bytesToTransfer.Value)
                            {
                                this.Log(LogLevel.Error, "Changing NBYTES when START is set is not permitted");
                            }

                            start.Value = false;
                            stop.Value = false;
                        })
                        .WithChangeCallback((_,__) => Update())
                }, {
                    (long)Registers.OwnAddress1, new DoubleWordRegister(this)
                        .WithValueField(0, 10, out ownAddress1, name: "OA1")
                        .WithFlag(10, out ownAddress1Mode, name: "OA1MODE")
                        .WithReservedBits(11, 4)
                        .WithFlag(15, out ownAddress1Enabled, name: "OA1EN")
                        .WithReservedBits(16, 16)
                        .WithWriteCallback((_, val) => 
                            this.Log(LogLevel.Info, "Slave address 1: 0x{0:X}, mode: {1}, status: {2}", ownAddress1.Value, ownAddress1Mode.Value ? "10-bit" : "7-bit", ownAddress1Enabled.Value ? "enabled" : "disabled")
                        )
                }, {
                    (long)Registers.OwnAddress2, new DoubleWordRegister(this)
                        .WithReservedBits(0, 1)
                        .WithValueField(1, 7, out ownAddress2, name: "OA2")
                        .WithValueField(8, 3, out ownAddress2Mask, name: "OA2MSK")
                        .WithReservedBits(11, 4)
                        .WithFlag(15, out ownAddress2Enabled, name: "OA2EN")
                        .WithReservedBits(16, 16)
                        .WithWriteCallback((_, val) =>
                            this.Log(LogLevel.Info, "Slave address 2: 0x{0:X}, mask: 0x{1:X}, status: {2}", ownAddress2.Value, ownAddress2Mask.Value, ownAddress2Enabled.Value ? "enabled" : "disabled")
                        )
                }, {
                    (long)Registers.Timing, new DoubleWordRegister(this)
                        .WithTag("SCLL", 0, 8)
                        .WithTag("SCLH", 8, 8)
                        .WithTag("SDADEL", 16, 4)
                        .WithTag("SCLDEL", 20, 4)
                        .WithReservedBits(24, 4)
                        .WithTag("PRESC", 28, 4)
                }, {
                    (long)Registers.InterruptAndStatus, new DoubleWordRegister(this, 1)
                        .WithFlag(0,
                            valueProviderCallback: _ => txData.Count == 0,
                            writeCallback: (_, value)=> 
                            {
                                if(value)
                                {
                                    txData.Clear();
                                }
                            }, name: "TXE")
                        .WithFlag(1, 
                            valueProviderCallback: _ => transmitInterruptStatus,
                            writeCallback: (_, val) =>
                            {
                                if(!noStretch.Value)
                                {
                                    return;
                                }
                                transmitInterruptStatus = val && transferInterruptEnabled.Value;
                            } , name: "TXIS")
                        .WithFlag(2, FieldMode.Read, valueProviderCallback: _ => RxNotEmpty, name: "RXNE")
                        .WithFlag(3, out addressMatched, FieldMode.Read, name: "ADDR")
                        .WithTag("NACKF", 4, 1)
                        .WithFlag(5, out stopDetection, FieldMode.Read, name: "STOPF")
                        .WithFlag(6, out transferComplete, FieldMode.Read, name: "TC")
                        .WithFlag(7, out transferCompleteReload, FieldMode.Read, name: "TCR")
                        .WithTag("BERR", 8, 1)
                        .WithTag("ARLO", 9, 1)
                        .WithTag("OVR", 10, 1)
                        .WithTag("PECERR", 11, 1)
                        .WithTag("TIMEOUT", 12, 1)
                        .WithTag("ALERT", 13, 1)
                        .WithReservedBits(14, 1)
                        .WithTag("BUSY", 15, 1)
                        .WithFlag(16, FieldMode.Read, valueProviderCallback: _ => transferOutgoing, name: "DIR")
                        .WithTag("ADDCODE", 17, 7)
                        .WithReservedBits(24, 8)
                        .WithChangeCallback((_,__) => Update())
                }, {
                    (long)Registers.InterruptClear, new DoubleWordRegister(this, 0)
                        .WithReservedBits(0, 3)
                        .WithFlag(3, FieldMode.WriteOneToClear, 
                            writeCallback: (_, value) =>
                            {
                                if(value)
                                {
                                    transmitInterruptStatus = transferOutgoing & (txData.Count == 0);
                                    addressMatched.Value = false;
                                }
                            }, name: "ADDRCF")
                        .WithTag("NACKCF", 4, 1)
                        .WithFlag(5, FieldMode.WriteOneToClear, 
                            writeCallback: (_, value) =>
                            {
                                if(value)
                                {
                                    stopDetection.Value = false;
                                }
                            }, name: "STOPCF")
                        .WithReservedBits(6, 2)
                        .WithTag("BERRCF", 8, 1)
                        .WithTag("ARLOCF", 9, 1)
                        .WithTag("OVRCF", 10, 1)
                        .WithTag("PECCF", 11, 1)
                        .WithTag("TIMOUTCF", 12, 1)
                        .WithTag("ALERTCF", 13, 1)
                        .WithReservedBits(14, 18)
                        .WithChangeCallback((_,__) => Update())
                }, {
                    (long)Registers.ReceiveData, new DoubleWordRegister(this, 0)
                        .WithValueField(0, 8, FieldMode.Read, valueProviderCallback: preVal => ReceiveDataRead((uint)preVal), name: "RXDATA")
                        .WithReservedBits(9, 23)
                }, {
                    (long)Registers.TransmitData, new DoubleWordRegister(this, 0)
                        .WithValueField(0, 8, writeCallback: (prevVal, val) => HandleTransmitDataWrite((uint)prevVal, (uint)val), name: "TXDATA")
                        .WithReservedBits(9, 23)
                }
            };
            // Console.WriteLine($"%%%% Inside CreatRegatReturn , map : {map}");
            // foreach (var kvp in map)
            // {
            //     Console.WriteLine($"%%%Key: {kvp.Key}, Value: {kvp.Value}");
            // }
            return new DoubleWordRegisterCollection(this, map);
        }

        private void PeripheralEnabledWrite(bool oldValue, bool newValue)
        {
            if(newValue)
            {
                return;
            }
            stopDetection.Value = false;
            transferComplete.Value = false;
            transferCompleteReload.Value = false;
            transmitInterruptStatus = false;
        }

        private void ExtendTransfer()
        {
            Console.WriteLine("%%%%%%Inside stm32f7_i2c extend transfer");
            //in case of reads we can fetch data from peripheral immediately, but in case of writes we have to wait until something is written to TXDATA
            if(isReadTransfer.Value)
            {
                // var data = currentSlave.Read((int)bytesToTransfer.Value);
                int bytesToTransfer_count = (int)bytesToTransfer.Value;
                // byte[] data = new byte[bytesToTransfer_count];
                // var data = new byte[size];
        
                // Fill the array with hardcoded values (or a pattern)
                // for(int i = 0; i < size; i++)
                // {
                //     //data[i] = (byte)(i % 256); // Example pattern, replace with your desired values
                //     data[i] = 0x80;
                // }
                for(int i = 0; i < bytesToTransfer_count; i++)
                {
                    if (configValues.TryGetValue(selectedRegister, out var value))
                    {
                        // data[i] = Convert.ToByte(value, 16);
                        rxData.Enqueue(Convert.ToByte(value, 16));// hardcoded value in hex for offset present in config file
                    }
                    else{
                        // data[i] = (byte)random.Next(0, 256);
                        // rxData.Enqueue((byte)random.Next(0, 256)); // else random value
                        var randomValue = (byte)random.Next(0, 256);
                        rxData.Enqueue(randomValue); // else random value
                    }
                    selectedRegister++;
                }
                // foreach(var item in data)
                // {
                //     rxData.Enqueue(item);
                // }
            }
            transferCompleteReload.Value = false;
            Update();
        }

        private void StartTransfer()
        {
            Console.WriteLine("%%%%%%Inside stm32f7_i2c start transfer");
            masterMode = true;
            transferComplete.Value = false;

            // currentSlave = null;

            rxData.Clear();
            //This is kinda volatile. If we change slaveAddress setting to a callback action, it might not be set at this moment.
            currentSlaveAddress = (int)(use10BitAddressing.Value ? slaveAddress.Value : ((slaveAddress.Value >> 1) & 0x7F));
            Console.WriteLine($"%%%%%%Inside stm32f7_i2c start transfer. slave address {currentSlaveAddress}");
            // if(!TryGetByAddress(currentSlaveAddress, out currentSlave))
            // {
            //     this.Log(LogLevel.Warning, "Unknown slave at address {0}.", currentSlaveAddress);
            //     return;
            // }

            // if(isReadTransfer.Value)
            // {
            //     transmitInterruptStatus = false;

            //     // if(readStatusRegisterFlag)
            //     // {
            //     //     // If the last written value to txData was 0xF3, return 0x00
            //     //     rxData.Enqueue(0x00);
            //     //     readStatusRegisterFlag = false;
            //     // }
            //     var data = currentSlave.Read((int)bytesToTransfer.Value);
            //     else {
            //             int size = (int)bytesToTransfer.Value;
            //             var data = new byte[size];
        
            //             // Fill the array with hardcoded values (or a pattern)
            //             for(int i = 0; i < size; i++)
            //             {
            //                 // data[i] = (byte)(i % 256); // Example pattern, replace with your desired values
            //                 data[i] = 0xDA;
            //             }

            //             foreach(var item in data)
            //             {
            //                 // Console.WriteLine($"^^^^Data read from slave 0x{item:X}");
            //                 rxData.Enqueue(item);
            //             }
            //         }
              
            // }
            if(isReadTransfer.Value)
            {
                Console.WriteLine($"%%%%Inside stm32f7_i2c_ start transfer : isReadTransfer.Value true, count : {(int)bytesToTransfer.Value}");
                transmitInterruptStatus = false;
                // var data = currentSlave.Read((int)bytesToTransfer.Value);
                int bytesToTransfer_count = (int)bytesToTransfer.Value;
                for(int i = 0; i < bytesToTransfer_count; i++)
                {   
                    Console.WriteLine($"selected reg : {selectedRegister}");
                    if (configValues.TryGetValue(selectedRegister, out var value))
                    {
                        Console.WriteLine($"selected reg : {selectedRegister} found in config, value : {value}");
                        // data[i] = Convert.ToUInt32(value, 16);
                        rxData.Enqueue(Convert.ToByte(value, 16));// hardcoded value in hex for offset present in config file
                        Console.WriteLine("rxData Enqueued !!");
                    }
                    else{
                        Console.WriteLine($"selected reg : {selectedRegister} not found in config , assigning random");
                        // data[i] = (uint)random.Next(0, 256);
                        var randomValue = (byte)random.Next(0, 256);
                        Console.WriteLine($"Random value : {randomValue}");
                        rxData.Enqueue(randomValue); // else random value
                        // rxData.Enqueue(0xAA);
                        Console.WriteLine("rxData Enqueued !!!");
                    }
                    selectedRegister++;
                }
                // foreach(var item in data)
                // {
                //     rxData.Enqueue(item);
                // }
            }
            else
            {
                transmitInterruptStatus = true;
            }
            Update();
        }

        private void StopTransfer()
        {
            Console.WriteLine("%%%%Iside stm32f7_i2c_ stop transfer");
            masterMode = false;
            stopDetection.Value = true;
            // currentSlave?.FinishTransmission();
            if(state != State.ReceivedFirstByte) //in case of reading we may (documentation permits this or repeated START) receive STOP before the read transfer
            {
                if(state == State.WritingWaitingForValue)
                {
                    this.Log(LogLevel.Warning, "Trying to write odd amount of bytes, last register is missing its value");
                }
                state = State.Idle;
            }
            Update();
        }

        private uint ReceiveDataRead(uint oldValue)
        {
            Console.WriteLine("%%%%Iside stm32f7_i2c_receivedDataRead");
            if(rxData.Count > 0)
            {
                var value = rxData.Dequeue();
                if(rxData.Count == 0)
                {
                    SetTransferCompleteFlags(); //TC/TCR is set when NBYTES data have been transfered
                }
                return value;
            }
            this.Log(LogLevel.Warning, "Receive buffer underflow!");
            return 0;
        }

        private void HandleTransmitDataWrite(uint oldValue, uint newValue)
        {
            if(masterMode)
            {
                MasterTransmitDataWrite(oldValue, newValue);
            }
            else
            {
                SlaveTransmitDataWrite(oldValue, newValue);
            }
        }

        private void MasterTransmitDataWrite(uint oldValue, uint newValue)
        {
            Console.WriteLine($"%%%%Iside stm32f7_i2c_masterTransmitDataWrite : bytes to transfer : {(int)bytesToTransfer.Value}");
            // if(currentSlave == null)
            // {
            //     this.Log(LogLevel.Warning, "Trying to send byte {0} to an unknown slave with address {1}.", newValue, currentSlaveAddress);
            //     return;
            // }
            // byte reg_val = (byte)(newValue);
            txData.Enqueue((byte)newValue);
            if(txData.Count == (int)bytesToTransfer.Value)
            {
                // currentSlave.Write(txData.ToArray());
                byte data_val = 0xFF;
                // state = State.Idle; // added in FinishTransmission
                foreach(var b in txData.ToArray())
                {
                    Console.WriteLine($"** stm32f7_i2c_masterTransmitDataWrite : write to sensor, data : 0x{b:X}, state : {state}");

                    switch(state) // Do I need to check these states, or shall i don't care about what the MCU is writing to the sensor ?
                    {   
                    case State.Idle:
                        selectedRegister = b;
                        Console.WriteLine($"** stm32f7_i2c_masterTransmitDataWrite : write to sensor, data : 0x{b:X}, state : {state}");
                        state = State.ReceivedFirstByte;
                        break;
                    case State.ReceivedFirstByte:
                    case State.WritingWaitingForValue:
                        Console.WriteLine($"** stm32f7_i2c_masterTransmitDataWrite : write to sensor, data : 0x{b:X}, state : {state}");
                        // RegistersCollection.Write((byte)selectedRegister, b); //bme280 have 256 addressable registers the same as byte max value
                        data_val = b;
                        state = State.WaitingForAddress;
                        break;
                    case State.WaitingForAddress:
                        Console.WriteLine($"** stm32f7_i2c_masterTransmitDataWrite : write to sensor, data : 0x{b:X}, state : {state}");
                        selectedRegister = b;
                        state = State.WritingWaitingForValue;
                        break;
                    case State.Reading:
                        //this isn't documented, but reads are able to use address set during write transfer, opposite isn't true
                        this.Log(LogLevel.Warning, "Trying to write without specifying address, byte is omitted");
                        break;
                    }
                    if(selectedRegister == resetAddrSensor && data_val == resetRequestVal)
                    {
                        Console.WriteLine("Reset request for sensor");
                        state = State.Idle;
                    }
                }
                
                txData.Clear();
                SetTransferCompleteFlags();
            }
            // if(reg_val==0xF3){
            //     readStatusRegisterFlag = true;
            // }
            // else{
            //     readStatusRegisterFlag = false;
            // }
            // txData.Enqueue((byte)newValue);
            // if(txData.Count == (int)bytesToTransfer.Value)
            // {
            //     // currentSlave.Write(txData.ToArray());
            //     txData.Clear();
            //     SetTransferCompleteFlags();
            // }
        }

        private void SlaveTransmitDataWrite(uint oldValue, uint newValue)
        {
            Console.WriteLine("%%%%Inside stm32f7_i2c_ slaveTransmitDataWrite");
            txData.Enqueue((byte)newValue);
        }

        private void SetTransferCompleteFlags()
        {
            Console.WriteLine("%%%%Inside stm32f7_i2c_ SetTransferCompleteFlags");
            if(!autoEnd.Value && !reload.Value)
            {
                Console.WriteLine($"no autoEnd.Value, state = {state}");
                transferComplete.Value = true;
            }
            if(autoEnd.Value)
            {
                // currentSlave.FinishTransmission();
                // state = State.Idle;
                // Console.WriteLine($"yes autoEnd.Value, state = {state}");
                // if(state != State.ReceivedFirstByte) //in case of reading we may (documentation permits this or repeated START) receive STOP before the read transfer
                // {
                //     if(state == State.WritingWaitingForValue)
                //     {
                //         this.Log(LogLevel.Warning, "Trying to write odd amount of bytes, last register is missing its value");
                //     }
                //     state = State.Idle;
                //     Console.WriteLine($"reset state = {state}");
                // }
                stopDetection.Value = true;
                masterMode = false;
            }
            if(reload.Value)
            {
                Console.WriteLine($"@@@@@@@no autoEnd.Value, state = {state}");
                transferCompleteReload.Value = true;
            }
            else
            {
                Console.WriteLine($"****no autoEnd.Value, state = {state}");
                transmitInterruptStatus = false; //this is a guess based on a driver
            }
            state = State.Idle;
            Update();
        }

        private void Update()
        {
            Console.WriteLine("%%%%Inside stm32f7_i2c_update");
            var value = (transferCompleteInterruptEnabled.Value && (transferCompleteReload.Value || transferComplete.Value))
                || (transferInterruptEnabled.Value && transmitInterruptStatus)
                || (receiveInterruptEnabled.Value && isReadTransfer.Value && rxData.Count > 0) //RXNE is calculated dynamically
                || (stopDetectionInterruptEnabled.Value && stopDetection.Value)
                || (nackReceivedInterruptEnabled.Value && false) //TODO: implement NACKF
                || (addressMatchedInterruptEnabled.Value && addressMatched.Value);
            EventInterrupt.Set(value);
        }
        //Dictionary with value specific to sensor offset, the value at offset could be hardcoded (liek chip id, status, etc) or marked as 'F' that is to be fuzzed
        private Dictionary<long, string> LoadConfiguration(string filePath) 
        {
            var config = new Dictionary<long, string>();
            foreach (var line in File.ReadAllLines(filePath))
            {
                var parts = line.Split('=');
                var offset = Convert.ToInt64(parts[0], 16);  // Parse offset in hex
                config[offset] = parts[1];  // Store the value (hex or 'F'(for fuzzing)) , currently only storing the offset addr whose value has to be hardcoded
            }
            return config;
        }

        private IValueRegisterField bytesToTransfer;
        private IValueRegisterField slaveAddress;
        private IValueRegisterField ownAddress1;
        private IValueRegisterField ownAddress2;
        private IValueRegisterField ownAddress2Mask;
        private IFlagRegisterField transferInterruptEnabled;
        private IFlagRegisterField receiveInterruptEnabled;
        private IFlagRegisterField addressMatchedInterruptEnabled;
        private IFlagRegisterField nackReceivedInterruptEnabled;
        private IFlagRegisterField stopDetectionInterruptEnabled;
        private IFlagRegisterField transferCompleteInterruptEnabled;
        private IFlagRegisterField isReadTransfer;
        private IFlagRegisterField use10BitAddressing;
        private IFlagRegisterField reload;
        private IFlagRegisterField autoEnd;
        private IFlagRegisterField noStretch;
        private IFlagRegisterField ownAddress1Mode;
        private IFlagRegisterField ownAddress1Enabled;
        private IFlagRegisterField ownAddress2Enabled;
        private IFlagRegisterField transferComplete;
        private IFlagRegisterField transferCompleteReload;
        private IFlagRegisterField stopDetection;
        private IFlagRegisterField addressMatched;
        private IFlagRegisterField start;
        private IFlagRegisterField stop;

        private DoubleWordRegisterCollection registers;

        // private II2CPeripheral currentSlave;
        private Queue<byte> rxData;
        private Queue<byte> txData;
        private int currentSlaveAddress;
        private bool transferOutgoing;
        private bool transmitInterruptStatus;
        private bool masterMode;
        private enum Registers
        {
            Control1 = 0x00,
            Control2 = 0x04,
            OwnAddress1 = 0x08,
            OwnAddress2 = 0x0C,
            Timing = 0x10,
            Timeout = 0x14,
            InterruptAndStatus = 0x18,
            InterruptClear = 0x1C,
            PacketErrorChecking = 0x20,
            ReceiveData = 0x24,
            TransmitData = 0x28
        }

        private Dictionary<long, string> configValues; // To store configuration from the file.
        private Random random;
        private byte selectedRegister;

        private enum State
        {
            Idle,
            ReceivedFirstByte,
            WaitingForAddress,
            WritingWaitingForValue,
            Reading
        }

        private State state;
        private const byte resetRequestVal = 0xB6; // change as per sensor datasheet
        private const byte resetAddrSensor = 0xE0; // change as per sensor datasheet

        // private bool readStatusRegisterFlag;

    }
}
