
using System;

namespace Antmicro.Renode.Core
{
    /// <summary>
    /// Interface for peripherals that support fuzzing snapshot capture and restore
    /// </summary>
    public interface IFuzzSnapshotRestorable
    {
        /// <summary>
        /// Captures the current state of the peripheral for fuzzing snapshots
        /// </summary>
        void fuzz_snap_capture();
        
        /// <summary>
        /// Restores the peripheral state from a previously captured snapshot
        /// </summary>
        void fuzz_snap_restore();
    }
}