using System;
using System.Runtime.InteropServices;

namespace SharpPcapDemo.Utilities
{
    public class MacPowerModeHandler
    {
        private const string IOKitLib = "/System/Library/Frameworks/IOKit.framework/IOKit";
        private static IntPtr powerNotifier;
        private Action _onSuspend;
        private Action _onResume;

        [DllImport(IOKitLib)]
        private static extern IntPtr IORegisterForSystemPower(IntPtr refcon, IntPtr portRef, PowerCallback callback, ref IntPtr notifier);

        [DllImport(IOKitLib)]
        private static extern uint IODeregisterForSystemPower(IntPtr notifier);

        private delegate void PowerCallback(IntPtr refCon, uint messageType, IntPtr messageArgument);

        public MacPowerModeHandler(Action onSuspend, Action onResume)
        {
            _onSuspend = onSuspend;
            _onResume = onResume;
        }

        public void StartListening()
        {
            PowerCallback callback = (refCon, messageType, messageArgument) =>
            {
                switch (messageType)
                {
                    case 0x10000: // Sleep
                        Console.WriteLine("System is going to sleep.");
                        _onSuspend?.Invoke();
                        break;
                    case 0x10001: // Wake
                        Console.WriteLine("System is waking up.");
                        _onResume?.Invoke();
                        break;
                }
            };

            IntPtr notifier = IntPtr.Zero;
            IORegisterForSystemPower(IntPtr.Zero, IntPtr.Zero, callback, ref notifier);
            powerNotifier = notifier;
        }

        public void StopListening()
        {
            if (powerNotifier != IntPtr.Zero)
            {
                IODeregisterForSystemPower(powerNotifier);
                powerNotifier = IntPtr.Zero;
            }
        }
    }

}
