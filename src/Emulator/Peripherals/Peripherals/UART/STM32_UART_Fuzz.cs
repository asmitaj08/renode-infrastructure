//
// Copyright (c) 2010-2024 Antmicro
//
// This file is licensed under the MIT License.
// Full license text is available in 'licenses/MIT.txt'.
//
using System;
using System.Threading;
using Antmicro.Renode.Core;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Peripherals.Bus;
using System.Collections.Generic;
using Antmicro.Migrant;
using Antmicro.Migrant.Hooks;
using Antmicro.Renode.Core.Structure.Registers;
using Antmicro.Renode.Time;
using System.Runtime.InteropServices;

namespace Antmicro.Renode.Peripherals.UART
{
    [AllowedTranslations(AllowedTranslation.WordToDoubleWord | AllowedTranslation.ByteToDoubleWord)]
    public class STM32_UART_Fuzz : BasicDoubleWordPeripheral, IUART, IFuzzSnapshotRestorable
    {
        // [DllImport("liblibafl_renode.so")]
        // // public static extern IntPtr uart_get_input_ptr(); //multiInput - libafl
        // public static extern IntPtr get_input_ptr(); //byteInput - libafl
        // // public static extern IntPtr get_i2c_input_size_ptr(); //multipart - libafl
        // [DllImport("liblibafl_renode.so")]
        // // public static extern IntPtr uart_get_input_size_ptr(); //multiInput - libafl
        // public static extern IntPtr get_input_size_ptr(); //byteInput
        // // private static IntPtr inputPtr = uart_get_input_ptr(); //multi
        // // private static IntPtr inputSizePtr = uart_get_input_size_ptr(); 
        // private static IntPtr inputPtr = get_input_ptr(); //byteInput
        // private static IntPtr inputSizePtr = get_input_size_ptr(); 

        public STM32_UART_Fuzz(IMachine machine, uint frequency = 8000000) : base(machine)
        {
            this.frequency = frequency;
            DefineRegisters();

        }

         public void ReadFromFuzzer_PY(byte[] data){
                Console.WriteLine($"^^^^Start ReadFromFuzzer_PY_uart() in STM32F4_UART_Fuzz.cs Len : {receiveFifo.Count}");

                receiveFifo = new Queue<byte>(data);
                 WriteChar(0xaa); //dummy val, just setting  UART flags internaly
                // general_fuzz_data.Clear();
                // general_fuzz_data.AddRange(data);
                Console.WriteLine($"^^^^ Done ReadFromFuzzer_PY_uart() in STM32F4_UART_Fuzz.cs Len : {receiveFifo.Count}");

        }

        public void ReadFromFuzzer_Internal(byte[] data){  
                //if (data != null && data.Length > 0){ //already being checked inside machine.cs
                    receiveFifo = new Queue<byte>(data);
                    WriteChar(0xaa); //dummy val, just setting  UART flags  // issue with static method here
                //}
                // general_fuzz_data.Clear();
                // general_fuzz_data.AddRange(data);
                //Console.WriteLine($"^^^^ReadFromFuzzer_Internal() in STM32F4_UART_Fuzz.cs Len : {receiveFifo.Count}");
        }

        public void SetRXNE_Fuzz(){
            readFifoNotEmpty.Value=true;
            Console.WriteLine($"^^^^STM32_UART_FUZZ.cs SetRXNE() val : {readFifoNotEmpty.Value}");
        }

        public void GetRXNE_Fuzz(){
            Console.WriteLine($"^^^^STM32_UART_FUZZ.cs GetRXNE_Fuzz() val : {readFifoNotEmpty.Value}");
        }

       
        public void WriteChar(byte value)
        {
            //  Console.WriteLine("****** UART WriteChar");
            if(!usartEnabled.Value && !receiverEnabled.Value)
            {
                // Console.WriteLine("****** Received a character, but the receiver is not enabled, dropping.");
                this.Log(LogLevel.Warning, "Received a character, but the receiver is not enabled, dropping.");
                return;
            }
            // receiveFifo.Enqueue(value);
        //     //---Fuzzing
        //     int datasize = 0;
        //     unsafe{
        //             ulong* datasize_ptr = (ulong*)inputSizePtr;
        //             datasize = (int)*datasize_ptr;
        //         }
        //    if(datasize!=datasize_track && datasize>0){
        //         byte[] tempArray = new byte[datasize];
        //         // lock (syncLock){
        //             Marshal.Copy(inputPtr, tempArray, 0, datasize);
        //         // }
        //         receiveFifo = new Queue<byte>(tempArray);
        //         datasize_track = datasize;
        //         // general_fuzz_data.Clear();
        //         // general_fuzz_data.AddRange(tempArray);
        //     }
            // else if(general_fuzz_data.Count > 0){
            //     receiveFifo = new Queue<byte>(general_fuzz_data.ToArray());
            // }
            // else if(datasize<=0){
            //     receiveFifo.Enqueue(value); // if no fuzz data available
            // }
        //     //--------

            // Console.WriteLine($"****** UART WriteChar, receiveFifo Len : {receiveFifo.Count}");
            readFifoNotEmpty.Value = true;
           

            if(BaudRate == 0)
            {
                this.Log(LogLevel.Warning, "Unknown baud rate, couldn't trigger the idle line interrupt");
            }
            else
            {
                // Setup a timeout of 1 UART frame (8 bits) for Idle line detection
                idleLineDetectedCancellationTokenSrc?.Cancel();

                var idleLineIn = (8 * 1000000) / BaudRate;
                idleLineDetectedCancellationTokenSrc = new CancellationTokenSource();
                machine.ScheduleAction(TimeInterval.FromMicroseconds(idleLineIn), _ => ReportIdleLineDetected(idleLineDetectedCancellationTokenSrc.Token), name: $"{nameof(STM32_UART_Fuzz)} Idle line detected");
            }

            Update();
        }

        public override void Reset()
        {
            //  Console.WriteLine("****** STM32_UART_Fuzz.cs Reset");
            base.Reset();
            idleLineDetectedCancellationTokenSrc?.Cancel();
            receiveFifo.Clear();
            IRQ.Set(false);
            // readFifoNotEmpty.Value=true;

        }

        private CancellationTokenSource fuzz_snap_idleLineDetectedCancellationTokenSrc;
        private bool fuzz_snap_irqLineActive;
    
    private bool fuzz_snap_idleLineDetected;
private bool fuzz_snap_readFifoNotEmpty;
private bool fuzz_snap_transmissionComplete;
private bool fuzz_snap_usartEnabled;
private bool fuzz_snap_receiverEnabled;
private bool fuzz_snap_transmitterEnabled;
private bool fuzz_snap_idleLineDetectedInterruptEnabled;
private bool fuzz_snap_receiverNotEmptyInterruptEnabled;
private bool fuzz_snap_transmissionCompleteInterruptEnabled;
private bool fuzz_snap_transmitDataRegisterEmptyInterruptEnabled;
private bool fuzz_snap_parityControlEnabled;
private OversamplingMode fuzz_snap_oversamplingMode;
private StopBitsValues fuzz_snap_stopBits;
private ParitySelection fuzz_snap_paritySelection;
private ulong fuzz_snap_dividerMantissa;
private ulong fuzz_snap_dividerFraction;


public void fuzz_snap_capture()
{
    Console.WriteLine("^^^^^ STM32_UART_Fuzz.cs fuzz_snap_capture()");
    
    // GPIO state
    fuzz_snap_irqLineActive = IRQ.IsSet;
    
    // Register field states (out variables)
    fuzz_snap_idleLineDetected = idleLineDetected.Value;
    fuzz_snap_readFifoNotEmpty = readFifoNotEmpty.Value;
    fuzz_snap_transmissionComplete = transmissionComplete.Value;
    fuzz_snap_usartEnabled = usartEnabled.Value;
    fuzz_snap_receiverEnabled = receiverEnabled.Value;
    fuzz_snap_transmitterEnabled = transmitterEnabled.Value;
    fuzz_snap_idleLineDetectedInterruptEnabled = idleLineDetectedInterruptEnabled.Value;
    fuzz_snap_receiverNotEmptyInterruptEnabled = receiverNotEmptyInterruptEnabled.Value;
    fuzz_snap_transmissionCompleteInterruptEnabled = transmissionCompleteInterruptEnabled.Value;
    fuzz_snap_transmitDataRegisterEmptyInterruptEnabled = transmitDataRegisterEmptyInterruptEnabled.Value;
    fuzz_snap_parityControlEnabled = parityControlEnabled.Value;
    fuzz_snap_oversamplingMode = oversamplingMode.Value;
    fuzz_snap_stopBits = stopBits.Value;
    fuzz_snap_paritySelection = paritySelection.Value;
    fuzz_snap_dividerMantissa = dividerMantissa.Value;
    fuzz_snap_dividerFraction = dividerFraction.Value;
    
    // CancellationTokenSource (if not null)
    if (idleLineDetectedCancellationTokenSrc != null)
    {
        fuzz_snap_idleLineDetectedCancellationTokenSrc = new CancellationTokenSource();
    }
}

public void fuzz_snap_restore()
{
    // Console.WriteLine("^^^^^ STM32_UART_Fuzz.cs fuzz_snap_restore()");
    // base.Reset();
    // Restore GPIO state
    if (fuzz_snap_irqLineActive)
    {
        IRQ.Set();
    }
    else
    {
        IRQ.Unset();
    }
    
    // Restore register field states (out variables)
    idleLineDetected.Value = fuzz_snap_idleLineDetected;
    readFifoNotEmpty.Value = fuzz_snap_readFifoNotEmpty;
    transmissionComplete.Value = fuzz_snap_transmissionComplete;
    usartEnabled.Value = fuzz_snap_usartEnabled;
    receiverEnabled.Value = fuzz_snap_receiverEnabled;
    transmitterEnabled.Value = fuzz_snap_transmitterEnabled;
    idleLineDetectedInterruptEnabled.Value = fuzz_snap_idleLineDetectedInterruptEnabled;
    receiverNotEmptyInterruptEnabled.Value = fuzz_snap_receiverNotEmptyInterruptEnabled;
    transmissionCompleteInterruptEnabled.Value = fuzz_snap_transmissionCompleteInterruptEnabled;
    transmitDataRegisterEmptyInterruptEnabled.Value = fuzz_snap_transmitDataRegisterEmptyInterruptEnabled;
    parityControlEnabled.Value = fuzz_snap_parityControlEnabled;
    oversamplingMode.Value = fuzz_snap_oversamplingMode;
    stopBits.Value = fuzz_snap_stopBits;
    paritySelection.Value = fuzz_snap_paritySelection;
    dividerMantissa.Value = fuzz_snap_dividerMantissa;
    dividerFraction.Value = fuzz_snap_dividerFraction;
    
    // Restore CancellationTokenSource (if it was captured)
    if (fuzz_snap_idleLineDetectedCancellationTokenSrc != null)
    {
        idleLineDetectedCancellationTokenSrc = fuzz_snap_idleLineDetectedCancellationTokenSrc;
    }
    
    // Update the peripheral state
    Update();
}



        public uint BaudRate
        {
            get
            {
                //OversamplingMode.By8 means we ignore the oldest bit of dividerFraction.Value
                var fraction = oversamplingMode.Value == OversamplingMode.By16 ? dividerFraction.Value : dividerFraction.Value & 0b111;

                var divisor = 8 * (2 - (int)oversamplingMode.Value) * (dividerMantissa.Value + fraction / 16.0);
                return divisor == 0 ? 0 : (uint)(frequency / divisor);
            }
        }

        public Bits StopBits
        {
            get
            {
                switch(stopBits.Value)
                {
                case StopBitsValues.Half:
                    return Bits.Half;
                case StopBitsValues.One:
                    return Bits.One;
                case StopBitsValues.OneAndAHalf:
                    return Bits.OneAndAHalf;
                case StopBitsValues.Two:
                    return Bits.Two;
                default:
                    throw new ArgumentException("Invalid stop bits value");
                }
            }
        }

        public Parity ParityBit => parityControlEnabled.Value ?
                                    (paritySelection.Value == ParitySelection.Even ?
                                        Parity.Even :
                                        Parity.Odd) :
                                    Parity.None;

        public GPIO IRQ { get; } = new GPIO();

        [field: Transient]
        public event Action<byte> CharReceived;

        private void DefineRegisters()
        {
            Register.Status.Define(this, 0xC0, name: "USART_SR")
                .WithTaggedFlag("PE", 0)
                .WithTaggedFlag("FE", 1)
                .WithTaggedFlag("NF", 2)
                .WithFlag(3, FieldMode.Read, valueProviderCallback: _ => false, name: "ORE") // we assume no receive overruns
                .WithFlag(4, out idleLineDetected, FieldMode.Read, name: "IDLE")
                .WithFlag(5, out readFifoNotEmpty, FieldMode.Read | FieldMode.WriteZeroToClear, name: "RXNE") // as these two flags are WZTC, we cannot just calculate their results
                // .WithFlag(5, out readFifoNotEmpty,valueProviderCallback: _ => true , name: "RXNE") //fuzz
                .WithFlag(6, out transmissionComplete, FieldMode.Read | FieldMode.WriteZeroToClear, name: "TC")
                .WithFlag(7, FieldMode.Read, valueProviderCallback: _ => true, name: "TXE") // we always assume "transmit data register empty"
                .WithTaggedFlag("LBD", 8)
                .WithTaggedFlag("CTS", 9)
                .WithReservedBits(10, 22)
                .WithWriteCallback((_, __) => Update())
            ;
            Register.Data.Define(this, name: "USART_DR")
                .WithValueField(0, 9, valueProviderCallback: _ =>
                    {
                        uint value = 0;

                        // "Cleared by a USART_SR register followed by a read to the USART_DR register."
                        // We can assume that USART_SR has already been read on the ISR.
                        idleLineDetected.Value = false;
                        // receiveFifo = new Queue<byte>(new byte[] { 0xD0, 0xAA, 0xCC, 0xDE, 0xFF,0x1A, 0xAA, 0xCC, 0xDE, 0xFF}); // if no fuzz data available
                        // Console.WriteLine($"****** UART DR....... read , receiveFifo Len : {receiveFifo.Count}");
                        if(receiveFifo.Count > 0)
                        {
                            value = receiveFifo.Dequeue();
                        }
                        readFifoNotEmpty.Value = receiveFifo.Count > 0;
                        Update();
                        return value;
                    }, writeCallback: (_, value) =>
                    {
                        //  Console.WriteLine($"****** UART DR writecallback, value : 0x{value:X}");
                        if(!usartEnabled.Value && !transmitterEnabled.Value)
                        {
                            this.Log(LogLevel.Warning, "Trying to transmit a character, but the transmitter is not enabled. dropping.");
                            return;
                        }
                        CharReceived?.Invoke((byte)value);
                        transmissionComplete.Value = true;
                        Update();
                    }, name: "DR"
                )
            ;
            Register.BaudRate.Define(this, name: "USART_BRR")
                .WithValueField(0, 4, out dividerFraction, name: "DIV_Fraction")
                .WithValueField(4, 12, out dividerMantissa, name: "DIV_Mantissa")
            ;
            Register.Control1.Define(this, name: "USART_CR1")
                .WithTaggedFlag("SBK", 0)
                .WithTaggedFlag("RWU", 1)
                .WithFlag(2, out receiverEnabled, name: "RE")
                .WithFlag(3, out transmitterEnabled, name: "TE")
                .WithFlag(4, out idleLineDetectedInterruptEnabled, name: "IDLEIE")
                .WithFlag(5, out receiverNotEmptyInterruptEnabled, name: "RXNEIE")
                .WithFlag(6, out transmissionCompleteInterruptEnabled, name: "TCIE")
                .WithFlag(7, out transmitDataRegisterEmptyInterruptEnabled, name: "TXEIE")
                .WithFlag(8, name:"PEIE")
                .WithEnumField(9, 1, out paritySelection, name: "PS")
                .WithFlag(10, out parityControlEnabled, name: "PCE")
                .WithTaggedFlag("WAKE", 11)
                .WithTaggedFlag("M", 12)
                .WithFlag(13, out usartEnabled, name: "UE")
                .WithReservedBits(14, 1)
                .WithEnumField(15, 1, out oversamplingMode, name: "OVER8")
                .WithReservedBits(16, 16)
                .WithWriteCallback((_, __) =>
                {
                    if(!receiverEnabled.Value || !usartEnabled.Value)
                    {
                        idleLineDetectedCancellationTokenSrc?.Cancel();
                    }
                    // if(receiverEnabled.Value){ //added for fuzzing - cnc - it won't work for all target
                    //     WriteChar(0xbb);
                    // }

                    Update();
                })
            ;
            Register.Control2.Define(this, name: "USART_CR2")
                .WithTag("ADD", 0, 4)
                .WithReservedBits(5, 1)
                .WithTaggedFlag("LBDIE", 6)
                .WithReservedBits(7, 1)
                .WithTaggedFlag("LBCL", 8)
                .WithTaggedFlag("CPHA", 9)
                .WithTaggedFlag("CPOL", 10)
                .WithTaggedFlag("CLKEN", 11)
                .WithEnumField(12, 2, out stopBits, name: "STOP")
                .WithTaggedFlag("LINEN", 14)
                .WithReservedBits(15, 17)
            ;
            Register.Control3.Define(this, name: "USART_CR3")
                .WithFlag(0, name:"EIE")
                .WithTaggedFlag("IREN", 1)
                .WithTaggedFlag("IRLP", 2)
                .WithTaggedFlag("HDSEL", 3)
                .WithTaggedFlag("NACK", 4)
                .WithTaggedFlag("DMAR", 6)
                .WithTaggedFlag("DMAT", 7)
                .WithTaggedFlag("RTSE", 8)
                .WithTaggedFlag("CTSE", 9)
                .WithTaggedFlag("CTSIE", 10)
                .WithTaggedFlag("ONEBIT", 11)
                .WithReservedBits(12, 20)
            ;


        }
        

        private void ReportIdleLineDetected(CancellationToken ct)
        {
            if(!ct.IsCancellationRequested)
            {
                idleLineDetected.Value = true;
                Update();
            }
        }

        private void Update()
        {
            IRQ.Set(
                (idleLineDetectedInterruptEnabled.Value && idleLineDetected.Value) ||
                (receiverNotEmptyInterruptEnabled.Value && readFifoNotEmpty.Value) ||
                (transmitDataRegisterEmptyInterruptEnabled.Value) || // TXE is assumed to be true
                (transmissionCompleteInterruptEnabled.Value && transmissionComplete.Value)
            );
        }

        private readonly uint frequency;

        private CancellationTokenSource idleLineDetectedCancellationTokenSrc;

        private IEnumRegisterField<OversamplingMode> oversamplingMode;
        private IEnumRegisterField<StopBitsValues> stopBits;
        private IFlagRegisterField usartEnabled;
        private IFlagRegisterField parityControlEnabled;
        private IEnumRegisterField<ParitySelection> paritySelection;
        private IFlagRegisterField transmissionCompleteInterruptEnabled;
        private IFlagRegisterField transmitDataRegisterEmptyInterruptEnabled;
        private IFlagRegisterField idleLineDetectedInterruptEnabled;
        private IFlagRegisterField receiverNotEmptyInterruptEnabled;
        private IFlagRegisterField receiverEnabled;
        private IFlagRegisterField transmitterEnabled;
        private IFlagRegisterField idleLineDetected;
        private IFlagRegisterField readFifoNotEmpty;
        private IFlagRegisterField transmissionComplete;
        private IValueRegisterField dividerMantissa;
        private IValueRegisterField dividerFraction;

        // private readonly Queue<byte> receiveFifo = new Queue<byte>();
        private Queue<byte> receiveFifo = new Queue<byte>(1024); // fuzz - 1024 is MAX INPUT size that I have set on LibAFL to cap teh size of input generated by mutator
        // private static Queue<byte> receiveFifo = new Queue<byte>(1024);
        // private byte[] general_fuzz_data ;
        private List<byte> general_fuzz_data = new List<byte>(1024); //size changes based on input from fuzzer
        private int datasize_track = 0;

        private enum OversamplingMode
        {
            By16 = 0,
            By8 = 1
        }

        private enum StopBitsValues
        {
            One = 0,
            Half = 1,
            Two = 2,
            OneAndAHalf = 3
        }

        private enum ParitySelection
        {
            Even = 0,
            Odd = 1
        }

        private enum Register : long
        {
            Status = 0x00,
            Data = 0x04,
            BaudRate = 0x08,
            Control1 = 0x0C,
            Control2 = 0x10,
            Control3 = 0x14,
            GuardTimeAndPrescaler = 0x18
        }
    }
}
