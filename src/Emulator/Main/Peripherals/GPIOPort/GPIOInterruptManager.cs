﻿//
// Copyright (c) 2010-2018 Antmicro
//
// This file is licensed under the MIT License.
// Full license text is available in 'licenses/MIT.txt'.
//
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using Antmicro.Renode.Core;
using Antmicro.Renode.Utilities.Collections;

namespace Antmicro.Renode.Peripherals.GPIOPort
{
    public class GPIOInterruptManager
    {
        public GPIOInterruptManager(GPIO irq, bool[] state)
        {
            this.numberOfGpios = (uint)state.Length;
            this.underlyingIrq = irq;
            this.underlyingState = state;

            interruptEnable = new EventRisingCollection<bool>(numberOfGpios, () => RefreshInterrupts());
            interruptType = new EventRisingCollection<InterruptTrigger>(numberOfGpios, () => RefreshInterrupts());
            interruptMask = new EventRisingCollection<bool>(numberOfGpios, () => RefreshInterrupts());
            pinDirection = new EventRisingCollection<Direction>(numberOfGpios, () => RefreshInterrupts());

            previousState = new bool[numberOfGpios];
            activeInterrupts = new bool[numberOfGpios];
        }

        public void Reset()
        {
            interruptEnable.Clear();
            interruptType.Clear();
            interruptMask.Clear();
            pinDirection.Clear();

            Array.Clear(previousState, 0, previousState.Length);
            Array.Clear(activeInterrupts, 0, activeInterrupts.Length);
        }

        /// <summary>
        /// Clears the interrupt caused by the GPIO pin number <see argref="index"/>.
        /// </summary>
        /// <remarks>
        /// It is possible that the interrupt will be reissued right after clearing
        /// if the interrupt condition for the pin is true.
        /// </remarks>
        public void ClearInterrupt(int index)
        {
            activeInterrupts[index] = false;
            RefreshInterrupts();
        }

        public void RefreshInterrupts()
        {
            var irqState = false;
            for(var i = 0; i < numberOfGpios; i++)
            {
                if(!InterruptEnable[i] || (pinDirection[i] & Direction.Input) == 0)
                {
                    continue;
                }
                var isEdge = underlyingState[i] != previousState[i];
                switch(InterruptType[i])
                {
                    case InterruptTrigger.ActiveHigh:
                        if(DeassertActiveInterruptTrigger)
                        {
                            activeInterrupts[i] = underlyingState[i];
                        }
                        else
                        {
                            activeInterrupts[i] |= underlyingState[i];
                        }
                        irqState |= activeInterrupts[i] && !InterruptMask[i];
                        break;
                    case InterruptTrigger.ActiveLow:
                        if(DeassertActiveInterruptTrigger)
                        {
                            activeInterrupts[i] = !underlyingState[i];
                        }
                        else
                        {
                            activeInterrupts[i] |= !underlyingState[i];
                        }
                        irqState |= activeInterrupts[i] && !InterruptMask[i];
                        break;
                    case InterruptTrigger.RisingEdge:
                        if(isEdge && underlyingState[i])
                        {
                            irqState |= !InterruptMask[i];
                            activeInterrupts[i] = true;
                        }
                        break;
                    case InterruptTrigger.FallingEdge:
                        if(isEdge && !underlyingState[i])
                        {
                            irqState |= !InterruptMask[i];
                            activeInterrupts[i] = true;
                        }
                        break;
                    case InterruptTrigger.BothEdges:
                        if(isEdge)
                        {
                            irqState |= !InterruptMask[i];
                            activeInterrupts[i] = true;
                        }
                        break;
                }
            }
            Array.Copy(underlyingState, previousState, underlyingState.Length);
            if(irqState)
            {
                underlyingIrq.Set();
            }
            else if(!activeInterrupts.Any(x => x))
            {
                underlyingIrq.Unset();
            }
        }

        public bool DeassertActiveInterruptTrigger { get; set; }

        public IArray<bool> InterruptEnable { get { return interruptEnable; } }

        public IArray<InterruptTrigger> InterruptType { get { return interruptType; } }

        public IArray<bool> InterruptMask { get { return interruptMask; } }

        public IArray<Direction> PinDirection { get { return pinDirection; } }

        public IReadOnlyCollection<bool> State { get { return underlyingState; } }

        public IReadOnlyCollection<bool> ActiveInterrupts { get { return activeInterrupts; } }

        private readonly uint numberOfGpios;
        private readonly bool[] underlyingState;
        private readonly bool[] previousState;
        private readonly bool[] activeInterrupts;
        private readonly GPIO underlyingIrq;

        private readonly EventRisingCollection<bool> interruptEnable;
        private readonly EventRisingCollection<InterruptTrigger> interruptType;
        private readonly EventRisingCollection<bool> interruptMask;
        private readonly EventRisingCollection<Direction> pinDirection;

        public enum InterruptTrigger
        {
            ActiveLow,
            ActiveHigh,
            FallingEdge,
            RisingEdge,
            BothEdges
        }

        [Flags]
        public enum Direction
        {
            Input = 0x1,
            Output = 0x2
        }

        public class EventRisingCollection<T> : IArray<T>
        {
            public EventRisingCollection(uint size, Action onChanged)
            {
                elements = new T[size];
                this.onChanged = onChanged;
            }

            public IEnumerator<T> GetEnumerator()
            {
                return ((IEnumerable<T>)elements).GetEnumerator();
            }

            IEnumerator IEnumerable.GetEnumerator()
            {
                return elements.GetEnumerator();
            }

            public void Clear()
            {
                for(var i = 0; i < elements.Length; i++)
                {
                    elements[i] = default(T);
                }
            }

            public T this[int index]
            {
                get
                {
                    return elements[index];
                }

                set
                {
                    var currentValue = elements[index];
                    if(currentValue.Equals(value))
                    {
                        return;
                    }

                    elements[index] = value;
                    onChanged();
                }
            }

            public int Length => elements.Length;

            private readonly T[] elements;
            private readonly Action onChanged;
        }
    }
}
