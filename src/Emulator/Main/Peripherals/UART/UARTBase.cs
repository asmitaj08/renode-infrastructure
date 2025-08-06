//
// Copyright (c) 2010-2023 Antmicro
// Copyright (c) 2011-2015 Realtime Embedded
//
// This file is licensed under the MIT License.
// Full license text is available in 'licenses/MIT.txt'.
//
using System;
using System.Collections.Generic;
using Antmicro.Renode.Core;
using Antmicro.Renode.Core.Structure;
using Antmicro.Renode.Logging;
using Antmicro.Migrant;
using Antmicro.Migrant.Hooks;
using System.Runtime.InteropServices;

namespace Antmicro.Renode.Peripherals.UART
{
    public abstract class UARTBase : NullRegistrationPointPeripheralContainer<IUART>, IUART
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
        
        protected UARTBase(IMachine machine) : base(machine)
        {
            queue = new Queue<byte>();
            innerLock = new object();
        }

        // public virtual void ReadFromFuzzer_PY(byte[] data){ //added fuzz for renodeAFL++ sample example
        //         queue = new Queue<byte>(data);
        //         //  WriteChar(0xaa); //dummy val, just setting  UART flags internaly
        //         // general_fuzz_data.Clear();
        //         // general_fuzz_data.AddRange(data);
        //         Console.WriteLine($"^^^^ReadFromFuzzer_PY_uart() in STM32F4_UART_Fuzz.cs Len : {queue.Count}");

        // }

        public void ReadFromFuzzer_Internal(byte[] data_in=null){ 
                if (data_in != null && data_in.Length > 0){ //already being checked inside machine.cs
                // dataToReceive.Clear();
                queue = new Queue<byte>(data_in);
                WriteChar(0xaa);
                // }
                // general_fuzz_data.Clear();
                // general_fuzz_data.AddRange(data_in);
                // Console.WriteLine($"^^^^ReadFromFuzzer_Internal() in UARTBAse.cs Len : {queue.Count}");
                }
        }

        public virtual void WriteChar(byte value) //orig
        {
            lock(innerLock)
            {
                if(!IsReceiveEnabled)
                {
                    this.Log(LogLevel.Debug, "UART or receive disabled; dropping the character written: '{0}'", (char)value);
                    return;
                }

                queue.Enqueue(value);
                CharWritten();
            }
        }
        //for fuzzing
        // private int datasize_track=0;
        // public virtual void WriteChar(byte value) //modified
        // {
        //     lock(innerLock)
        //     {
        //         if(!IsReceiveEnabled)
        //         {
        //             this.Log(LogLevel.Debug, "UART or receive disabled; dropping the character written: '{0}'", (char)value);
        //             return;
        //         }


        //          int datasize = 0;
        //     unsafe{
        //             ulong* datasize_ptr = (ulong*)inputSizePtr;
        //             datasize = (int)*datasize_ptr;
        //         }
        //    if(datasize!=datasize_track && datasize>0){
        //         byte[] tempArray = new byte[datasize];
        //         // lock (syncLock){
        //             Marshal.Copy(inputPtr, tempArray, 0, datasize);
        //         // }
        //         queue = new Queue<byte>(tempArray);
        //         datasize_track = datasize;
        //         // general_fuzz_data.Clear();
        //         // general_fuzz_data.AddRange(tempArray);
        //     }
        //     // else if(general_fuzz_data.Count > 0){
        //     //     receiveFifo = new Queue<byte>(general_fuzz_data.ToArray());
        //     // }
        //     else if(datasize<=0){
        //         queue.Enqueue(value); // if no fuzz data available
        //     }
        // //     //--------

        //         // queue.Enqueue(value);
        //         CharWritten();
        //     }
        // }

        public override void Reset()
        {
            // Console.WriteLine("^^^^^ UARTBase.cs Reset()");
            ClearBuffer();
        }

        public override void Register(IUART uart, NullRegistrationPoint registrationPoint)
        {
            base.Register(uart, registrationPoint);
            ConnectEvents();
        }

        public override void Unregister(IUART uart)
        {
            base.Unregister(uart);

            this.CharReceived -= uart.WriteChar;
            uart.CharReceived -= this.WriteChar;
        }

        [field: Transient]
        public event Action<byte> CharReceived;

        protected abstract void CharWritten();
        protected abstract void QueueEmptied();

        protected bool TryGetCharacter(out byte character)
        {
            lock(innerLock)
            {
                if(queue.Count == 0)
                {
                    character = default(byte);
                    return false;
                }
                character = queue.Dequeue();
                if(queue.Count == 0)
                {
                    QueueEmptied();
                }
                return true;
            }
        }

        protected void TransmitCharacter(byte character)
        {
            CharReceived?.Invoke(character);
        }

        protected void ClearBuffer()
        {
            lock(innerLock)
            {
                queue.Clear();
                QueueEmptied();
            }
        }

        protected int Count
        {
            get
            {
                lock(innerLock)
                {
                    return queue.Count;
                }
            }
        }

        protected readonly object innerLock;
        // private readonly Queue<byte> queue; //orig
        private Queue<byte> queue;

        public abstract Bits StopBits { get; }

        public abstract Parity ParityBit { get; }

        public abstract uint BaudRate { get; }

        protected virtual bool IsReceiveEnabled => true;

        [PostDeserialization]
        private void ConnectEvents()
        {
            if(RegisteredPeripheral != null)
            {
                this.CharReceived += RegisteredPeripheral.WriteChar;
                RegisteredPeripheral.CharReceived += this.WriteChar;
            }
        }
    }
}

