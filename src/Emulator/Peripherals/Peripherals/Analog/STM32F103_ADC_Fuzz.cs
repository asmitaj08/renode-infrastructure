//
// Copyright (c) 2010-2023 Antmicro
//
//  This file is licensed under the MIT License.
//  Full license text is available in 'licenses/MIT.txt'.
//

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Antmicro.Renode.Core;
using Antmicro.Renode.Core.Structure.Registers;
using Antmicro.Renode.Exceptions;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Utilities;
using Antmicro.Renode.Time;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Peripherals.Timers;

namespace Antmicro.Renode.Peripherals.Analog
{
   // STM32 ADC has many features and only a partial subset are implemented here
   //
   // Supported:
   // * Software triggered conversion
   // * Single conversion
   // * Scan mode with regular group
   // * Continuous conversion
   // * Modes of use
   //   - Polling (read EOC status flag)
   //   - Interrupt (enable ADC interrupt for EOC)
   //   - DMA (enable DMA and configure stream for peripheral to memory transfer)
   //
   // Not Implemented:
   // * Analog watchdog
   // * Overrun detection
   // * External triggers
   // * Injected channels
   // * Sampling time (time is fixed)
   // * Discontinuous mode
   // * Multi-ADC (i.e. Dual/Triple) mode
   public class STM32F103_ADC_Fuzz : BasicDoubleWordPeripheral, IKnownSize, IFuzzSnapshotRestorable
   {
      public STM32F103_ADC_Fuzz(IMachine machine) : base(machine)
      {
         channels = Enumerable.Range(0, NumberOfChannels).Select(x => new ADCChannel(this, x)).ToArray();

         DefineRegisters();

         // Sampling time fixed
         samplingTimer = new LimitTimer(
               machine.ClockSource, 1000000, this, "samplingClock",
               limit: 100,
               eventEnabled: true,
               direction: Direction.Ascending,
               enabled: false,
               autoUpdate: false,
               workMode: WorkMode.OneShot);
         samplingTimer.LimitReached += OnConversionFinished;
         
         // // Feed default samples to all channels
         // for(uint i = 0; i < NumberOfChannels; i++)
         // {
         //    FeedSample(0x1000 + i * 0x100, i, 1000);  // Default values - fuzz change
         // }
      }

      public void FeedSample(uint value, uint channelIdx, int repeat = 1)
      {
         if(IsValidChannel(channelIdx))
         {
            channels[channelIdx].FeedSample(value, repeat);
         }
      }

      public void FeedSample(string path, uint channelIdx, int repeat = 1)
      {
         if(IsValidChannel(channelIdx))
         {
            var parsedSamples = ADCChannel.ParseSamplesFile(path);
            channels[channelIdx].FeedSample(parsedSamples, repeat);
         }
      }

      private bool IsValidChannel(uint channelIdx)
      {
         if(channelIdx >= NumberOfChannels)
         {
            throw new RecoverableException("Only channels 0/1 are supported");
         }
         return true;
      }

      public override void Reset()
      {
         // Console.WriteLine("^^^^ADC_Fuzz.cs Reset()");
         base.Reset();
         foreach(var c in channels)
         {
            c.Reset();
         }
      }

      private uint fuzz_snap_adcData;
      private uint fuzz_snap_regularSequenceLen;
      private uint fuzz_snap_currentChannelIdx;
      private ADCChannel fuzz_snap_currentChannel;
      private ADCChannel[] fuzz_snap_channels;
      private LimitTimer fuzz_snap_samplingTimer;
      private Queue<uint> fuzz_snap_adcSample_fuzz;

      private bool fuzz_snap_scanMode;
      private bool fuzz_snap_endOfConversion;
      private bool fuzz_snap_adcOn;
      private bool fuzz_snap_endOfConversionSelect;
      private bool fuzz_snap_eocInterruptEnable;
      private bool fuzz_snap_continuousConversion;
      private bool fuzz_snap_dmaEnabled;
      private bool fuzz_snap_dmaIssueRequest;
      private IValueRegisterField[] fuzz_snap_regularSequence;

      private bool fuzz_snap_irqLineActive;
      private bool fuzz_snap_dmaRequestLineActive;

      private bool fuzz_snap_samplingTimerEnabled;
      private ulong fuzz_snap_samplingTimerValue;
      private ulong fuzz_snap_samplingTimerLimit;

      public void fuzz_snap_capture()
      {
         Console.WriteLine("^^^^^ STM32F103_ADC_Fuzz.cs fuzz_snap_capture()");
         // Internal state variables
         fuzz_snap_adcData = adcData;
         fuzz_snap_regularSequenceLen = regularSequenceLen;
         fuzz_snap_currentChannelIdx = currentChannelIdx;
         fuzz_snap_currentChannel = currentChannel;
         fuzz_snap_channels = (ADCChannel[])channels.Clone();
         fuzz_snap_samplingTimer = samplingTimer;
         fuzz_snap_adcSample_fuzz = new Queue<uint>(adcSample_fuzz);
    
         // Register field states (out variables)
         fuzz_snap_scanMode = scanMode.Value;
         fuzz_snap_endOfConversion = endOfConversion.Value;
         fuzz_snap_adcOn = adcOn.Value;
         fuzz_snap_endOfConversionSelect = endOfConversionSelect.Value;
         fuzz_snap_eocInterruptEnable = eocInterruptEnable.Value;
         fuzz_snap_continuousConversion = continuousConversion.Value;
         fuzz_snap_dmaEnabled = dmaEnabled.Value;
         fuzz_snap_dmaIssueRequest = dmaIssueRequest.Value;
    
         // Regular sequence array
         fuzz_snap_regularSequence = new IValueRegisterField[regularSequence.Length];
         Array.Copy(regularSequence, fuzz_snap_regularSequence, regularSequence.Length);
    
         // GPIO states
         fuzz_snap_irqLineActive = IRQ.IsSet;
         fuzz_snap_dmaRequestLineActive = DMARequest.IsSet;
    
         // Timer states
         fuzz_snap_samplingTimerEnabled = samplingTimer.Enabled;
         fuzz_snap_samplingTimerValue = samplingTimer.Value;
         fuzz_snap_samplingTimerLimit = samplingTimer.Limit;
      }

      public void fuzz_snap_restore()
      {
         //  Console.WriteLine("^^^^^ STM32F103_ADC_Fuzz.cs fuzz_snap_restore()");
         // Restore internal state variables
         adcData = fuzz_snap_adcData;
         regularSequenceLen = fuzz_snap_regularSequenceLen;
         currentChannelIdx = fuzz_snap_currentChannelIdx;
         currentChannel = fuzz_snap_currentChannel;
         //  channels = (ADCChannel[])fuzz_snap_channels.Clone(); //read-only
         //  samplingTimer = fuzz_snap_samplingTimer;
         adcSample_fuzz = new Queue<uint>(fuzz_snap_adcSample_fuzz);
    
         // Restore register field states (out variables)
         scanMode.Value = fuzz_snap_scanMode;
         endOfConversion.Value = fuzz_snap_endOfConversion;
         adcOn.Value = fuzz_snap_adcOn;
         endOfConversionSelect.Value = fuzz_snap_endOfConversionSelect;
         eocInterruptEnable.Value = fuzz_snap_eocInterruptEnable;
         continuousConversion.Value = fuzz_snap_continuousConversion;
         dmaEnabled.Value = fuzz_snap_dmaEnabled;
         dmaIssueRequest.Value = fuzz_snap_dmaIssueRequest;
    
         // Restore regular sequence array
         Array.Copy(fuzz_snap_regularSequence, regularSequence, regularSequence.Length);
    
         // Restore GPIO states
         if (fuzz_snap_irqLineActive)
         {
            IRQ.Set();
         }
         else
         {
            IRQ.Unset();
         }
    
         if (fuzz_snap_dmaRequestLineActive)
         {
            DMARequest.Set();
         }
         else
         {
            DMARequest.Unset();
         }
    
         // Restore timer states
         samplingTimer.Enabled = fuzz_snap_samplingTimerEnabled;
         samplingTimer.Value = fuzz_snap_samplingTimerValue;
         samplingTimer.Limit = fuzz_snap_samplingTimerLimit;
      }

      public void ReadFromFuzzer_Internal(byte[] data_in)
      {
         // Console.WriteLine($"^^^^^^ STM32F103_ADC_Fuzz: Injecting {data_in.Length} bytes");
    
         var localQueue = new Queue<uint>();
         // Handle complete pairs
         for (int i = 0; i < data_in.Length - 1; i += 2)
         {
            uint adcValue = (uint)((data_in[i + 1] << 8) | data_in[i]);
            localQueue.Enqueue(adcValue);
         }
         // Handle last byte if odd length
         if (data_in.Length % 2 != 0)
         {
            uint adcValue = (uint)((0x00 << 8) | data_in[data_in.Length - 1]);
            localQueue.Enqueue(adcValue);
         }

         // Console.WriteLine($"^^^^^^ ADC: Parsed {localQueue.Count} samples from {data_in.Length} bytes");
         // Feed to all channels
         for (uint channelId = 0; channelId < 4; channelId++)
         {
            channels[channelId].FeedSample(localQueue, 1);
         }

      }  




      public long Size => 0x50;

      public GPIO IRQ { get; } = new GPIO();
      public GPIO DMARequest { get; } = new GPIO();

      private void DefineRegisters()
      {
         Registers.Status.Define(this)
            .WithTaggedFlag("Analog watchdog flag", 0)
            .WithFlag(1, out endOfConversion, name: "Regular channel end of conversion",valueProviderCallback: _ => true)
            .WithTaggedFlag("Injected channel end of conversion", 2)
            .WithTaggedFlag("Injected channel start flag", 3)
            .WithTaggedFlag("Regular channel start flag", 4)
            // .WithTaggedFlag("Overrun", 5)
            .WithReservedBits(5, 27);

         Registers.Control1.Define(this)
            .WithTag("Analog watchdog channel select bits", 0, 5)
            .WithFlag(5, out eocInterruptEnable, name: "Interrupt enable for EOC")
            .WithTaggedFlag("Analog watchdog interrupt enable", 6)
            .WithTaggedFlag("Interrupt enable for injected channels", 7)
            .WithFlag(8, out scanMode, name: "Scan mode")
            .WithTaggedFlag("Enable the watchdog on a single channel in scan mode", 9)
            .WithTaggedFlag("Automatic injected group conversion", 10)
            .WithTaggedFlag("Discontinuous mode on regular channels", 11)
            .WithTaggedFlag("Discontinuous mode on injected channels", 12)
            .WithTag("Discontinuous mode channel count", 13, 3)
            .WithReservedBits(16, 6)
            .WithTaggedFlag("Analog watchdog enable on injected channels", 22)
            .WithTaggedFlag("Analog watchdog enable on regular channels", 23)
            .WithTag("Resolution", 24, 2)
            .WithTaggedFlag("Overrun interrupt enable", 26)
            .WithReservedBits(27, 5);

         Registers.Control2.Define(this, name: "Control2")
            .WithFlag(0, out adcOn,
                  name: "A/D Converter ON/OFF",
                  changeCallback: (_, val) => { if(val) { EnableADC(); }})
            .WithFlag(1, out continuousConversion, name: "Continous conversion")
            .WithFlag(2,name:"AD Calibration", valueProviderCallback: _ => false)
            .WithFlag(3, name:"Reset Calibration", valueProviderCallback: _ => false)
            .WithReservedBits(4, 4)
            .WithFlag(8, out dmaEnabled, name: "Direct memory access mode")
            .WithFlag(9, out dmaIssueRequest, name: "DMA disable selection")
            .WithFlag(10, out endOfConversionSelect, name: "End of conversion select")
            .WithTaggedFlag("Data Alignment", 11)
            .WithReservedBits(12, 4)
            .WithReservedBits(16, 1)
            .WithValueField(17, 3, name:"External event select for regular group")
            // .WithValueField(17, 3,valueProviderCallback: _ =>7, name:"External event select for regular group")
            // .WithTag("External event select for injected group", 17, 3)
            .WithFlag(20, name:"External trigger conversion mode for regular channels")
            .WithFlag(21, name:"Start conversion of injected channels")
            // .WithTaggedFlag("Start conversion of injected channels", 22)
            .WithFlag(22,
                  name: "Start Conversion Of Regular Channels",
                  writeCallback: (_, value) => { if(value) StartConversion(); },
                  valueProviderCallback: _ => false)
            .WithTaggedFlag("Temperature sensor and VREFINT enable", 23)
            .WithReservedBits(24, 8);

         Registers.SampleTime1.Define(this)
            .WithValueField(0,3, name:"Channel 10 sampling time")
            .WithTag("Channel 11 sampling time", 3, 3)
            .WithTag("Channel 12 sampling time", 6, 3)
            .WithTag("Channel 13 sampling time", 9, 3)
            .WithTag("Channel 14 sampling time", 12, 3)
            .WithTag("Channel 15 sampling time", 15, 3)
            .WithTag("Channel 16 sampling time", 18, 3)
            .WithTag("Channel 17 sampling time", 21, 3)
            .WithTag("Channel 18 sampling time", 24, 3)
            .WithReservedBits(27, 5);

         Registers.SampleTime2.Define(this)
         .WithValueField(0, 3, name:"Channel 0 sampling time")
            // .WithTag("Channel 0 sampling time", 0, 3)
            .WithTag("Channel 1 sampling time", 3, 3)
            .WithTag("Channel 2 sampling time", 6, 3)
            .WithTag("Channel 3 sampling time", 9, 3)
            .WithTag("Channel 4 sampling time", 12, 3)
            .WithTag("Channel 5 sampling time", 15, 3)
            .WithTag("Channel 6 sampling time", 18, 3)
            .WithTag("Channel 7 sampling time", 21, 3)
            .WithTag("Channel 8 sampling time", 24, 3)
            .WithTag("Channel 9 sampling time", 27, 3)
            .WithReservedBits(30, 2);

         Registers.InjectedChannelDataOffset1.Define(this)
            .WithTag("Data offset for injected channel 1", 0, 12)
            .WithReservedBits(12, 20);
         Registers.InjectedChannelDataOffset2.Define(this)
            .WithTag("Data offset for injected channel 2", 0, 12)
            .WithReservedBits(12, 20);
         Registers.InjectedChannelDataOffset3.Define(this)
            .WithTag("Data offset for injected channel 3", 0, 12)
            .WithReservedBits(12, 20);
         Registers.InjectedChannelDataOffset4.Define(this)
            .WithTag("Data offset for injected channel 4", 0, 12)
            .WithReservedBits(12, 20);

         Registers.RegularSequence1.Define(this)
            .WithValueField(0, 5, out regularSequence[12], name: "13th conversion in regular sequence")
            .WithValueField(5, 5, out regularSequence[13], name: "14th conversion in regular sequence")
            .WithValueField(10, 5, out regularSequence[14], name: "15th conversion in regular sequence")
            .WithValueField(15, 5, out regularSequence[15], name: "16th conversion in regular sequence")
            .WithValueField(20, 4, writeCallback: (_, val) => { regularSequenceLen = (uint)val + 1; }, name: "Regular channel sequence length");

         Registers.RegularSequence2.Define(this)
            .WithValueField(0, 5, out regularSequence[6], name: "7th conversion in regular sequence")
            .WithValueField(5, 5, out regularSequence[7], name: "8th conversion in regular sequence")
            .WithValueField(10, 5, out regularSequence[8], name: "9th conversion in regular sequence")
            .WithValueField(15, 5, out regularSequence[9], name: "10th conversion in regular sequence")
            .WithValueField(20, 5, out regularSequence[10], name: "11th conversion in regular sequence")
            .WithValueField(25, 5, out regularSequence[11], name: "12th conversion in regular sequence");

         Registers.RegularSequence3.Define(this)
            .WithValueField(0, 5, out regularSequence[0], name: "1st conversion in regular sequence")
            .WithValueField(5, 5, out regularSequence[1], name: "2nd conversion in regular sequence")
            .WithValueField(10, 5, out regularSequence[2], name: "3rd conversion in regular sequence")
            .WithValueField(15, 5, out regularSequence[3], name: "4th conversion in regular sequence")
            .WithValueField(20, 5, out regularSequence[4], name: "5th conversion in regular sequence")
            .WithValueField(25, 5, out regularSequence[5], name: "6th conversion in regular sequence");

         // Data register
         Registers.RegularData.Define(this)
            .WithValueField(0, 32,
                  valueProviderCallback: _ =>
                  {
                      this.Log(LogLevel.Debug, "Reading ADC data {0}", adcData);
                      Console.WriteLine($"Reading ADC data {adcData}");
                      // Reading ADC_DR should clear EOC
                      endOfConversion.Value = false;
                      IRQ.Set(false);
                      return adcData;
                  });
      }

      private void EnableADC()
      {
          currentChannel = channels[regularSequence[currentChannelIdx].Value];
         //  Console.WriteLine($"^^^^^^ADC EnableADC(). currentChannel : {currentChannelIdx}");
      }

      private void StartConversion()
      {
         // Console.WriteLine("^^^^^^ADC StartConversion()");
         if(adcOn.Value)
         {
             this.Log(LogLevel.Debug, "Starting conversion time={0}",
                   machine.ElapsedVirtualTime.TimeElapsed);

             // Enable timer, which will simulate conversion being performed.
             samplingTimer.Enabled = true;
         }
         else
         {
             this.Log(LogLevel.Warning, "Trying to start conversion while ADC off");
         }
      }
      private uint i =0;
      private uint val =0;
      private void OnConversionFinished()
      {
         this.Log(LogLevel.Debug, "OnConversionFinished: time={0} channel={1}",
               machine.ElapsedVirtualTime.TimeElapsed,
               currentChannelIdx);

         // Set data register and trigger DMA request
         currentChannel.PrepareSample();
         var adcData = currentChannel.GetSample();
         // var adcData1 = currentChannel.GetSample();
         
         // if(i<5){
         //    val=0;
         // }
         // else {
         //    val =i*10;
         // }
         // adcSample_fuzz.Enqueue((uint)val);
         // i+=1;
         // adcData = adcSample_fuzz.Dequeue();
         // Console.WriteLine($"^^^^adcDAta OnConversionFinished : from GetSample adcData1: {adcData:X}, adcData : {adcData:X}, currentChannel : {currentChannelIdx}");
         
         // FIX: Assign the calculated adcData to the class field
         this.adcData = adcData;
         // Console.WriteLine($"^^^^ADC OnConversionFinished : dmaEnabled.Value : {dmaEnabled.Value}, dmaIssueRequest.Value : {dmaIssueRequest.Value}");
         
         // if(dmaEnabled.Value && dmaIssueRequest.Value) //orig
          if(dmaEnabled.Value)
         {
            // Issue DMA peripheral request, which when mapped to DMA
            // controller will trigger a peripheral to memory transfer
            // Console.WriteLine($"^^^^ADC OnConversionFinished : DMA triggered");
            DMARequest.Set();
            DMARequest.Unset();
         }

         var scanModeActive = scanMode.Value && currentChannelIdx < regularSequenceLen - 1;
         var scanModeFinished = scanMode.Value && currentChannelIdx == regularSequenceLen - 1;

         // Signal EOC if EOCS set with scan mode enabled and finished or we finished scanning regular group
         endOfConversion.Value = scanModeActive ? (endOfConversionSelect.Value || scanModeFinished) : true;

         // Iterate to next channel
         currentChannelIdx = (currentChannelIdx + 1) % regularSequenceLen;
         currentChannel = channels[regularSequence[currentChannelIdx].Value];

         // Auto trigger next conversion if we're scanning or CONT bit set
         samplingTimer.Enabled = scanModeActive || continuousConversion.Value;

         // Console.WriteLine($"^^^^adc OnConversionFinished: samplingTimer.Enabled - {samplingTimer.Enabled}, endOfConversion.Value : {endOfConversion.Value}");

         // Trigger EOC interrupt
         if(endOfConversion.Value && eocInterruptEnable.Value)
         {
            this.Log(LogLevel.Debug, "OnConversionFinished: Set IRQ");
            // Console.WriteLine($"^^^^adc OnConversionFinished: Set IRQ");
            IRQ.Set(true);
         }
      }

      // Control 1/2 fields
      private IFlagRegisterField scanMode;
      private IFlagRegisterField endOfConversion;
      private IFlagRegisterField adcOn;
      private IFlagRegisterField endOfConversionSelect;
      private IFlagRegisterField eocInterruptEnable;
      private IFlagRegisterField continuousConversion;
      private IFlagRegisterField adCalibration;
      private IFlagRegisterField resetCalibration;

      private IFlagRegisterField dmaEnabled;
      private IFlagRegisterField dmaIssueRequest;

      // Sampling timer. Provides time-based event for driving conversion of
      // regular channel sequence.
      private readonly LimitTimer samplingTimer;

      // Data sample to be returned from data register when read.
      private uint adcData;

      // Regular sequence settings, i.e. the channels and order of channels
      // for performing conversion
      private uint regularSequenceLen;
      private readonly IValueRegisterField[] regularSequence = new IValueRegisterField[19];

      // Channel objects, for managing input test data
      private uint currentChannelIdx;
      private ADCChannel currentChannel;
      private readonly ADCChannel[] channels;

      public const int NumberOfChannels = 19;

      private Queue<uint> adcSample_fuzz = new Queue<uint>(1024);

      private enum Registers
      {
         Status = 0x0,
         Control1 = 0x4,
         Control2 = 0x8,
         SampleTime1 = 0x0C,
         SampleTime2 = 0x10,
         InjectedChannelDataOffset1 = 0x14,
         InjectedChannelDataOffset2 = 0x18,
         InjectedChannelDataOffset3 = 0x1C,
         InjectedChannelDataOffset4 = 0x20,
         WatchdogHigherThreshold = 0x24,
         WatchdogLowerThreshold = 0x28,
         RegularSequence1 = 0x2C,
         RegularSequence2 = 0x30,
         RegularSequence3 = 0x34,
         InjectedSequence = 0x38,
         InjectedData1 = 0x3C,
         InjectedData2 = 0x40,
         InjectedData3 = 0x44,
         InjectedData4 = 0x48,
         RegularData = 0x4C
      }
   }
}
